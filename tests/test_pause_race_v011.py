"""Deterministic red-team tests for Pause-vs-dispatch concurrency.

Assurance statement: this linearizes the *signed dispatch intent*, not the
completion of an external side effect after an intent has been recorded.
"""
import tempfile
import sys
import json
import sqlite3
import threading
import time
import unittest
from pathlib import Path

from catl.broker import BrokerServer
from catl.crypto import digest
from catl.gateway import Gateway
from catl.policy import Policy
from catl.store import State


def tool():
    return {'name':'safe','inputSchema':{'type':'object'},'description':'reviewed'}

class Backend:
    def __init__(self):
        self.calls=[]
        self.entered=threading.Event()
        self.resume=threading.Event()
        self.wait_during_call=False
    def request(self,method,params=None):
        self.calls.append(method)
        if method=='initialize':
            return {'result':{'protocolVersion':'2025-11-25','capabilities':{},'serverInfo':{'name':'fake','version':'1'}}}
        if method=='tools/list':
            return {'result':{'tools':[tool()]}}
        if method=='tools/call':
            self.entered.set()
            if self.wait_during_call:
                if not self.resume.wait(8):
                    raise TimeoutError('backend_stalled')
            return {'result':{'content':[{'type':'text','text':'done'}]}}
        raise AssertionError(method)
    def notify(self,*a,**kw): pass
    def close(self): pass

@unittest.skipUnless(sys.platform == "linux", "protected broker ordering is Linux-only")
class PauseDispatchTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
        root=Path(self.tmp.name)
        self.state=State(root/'state.sqlite3',b'L'*32)
        self.state.set_feature('gateway_enabled',True,'bootstrap')
        data={'agent_id':'linearization-test','tool_pins':{'safe':digest(tool())},
              'rules':[{'tool':'safe','effect':'allow','conditions':[]}]}
        self.policy=Policy.from_dict(data)
        self.backend=Backend()
        self.gw=Gateway(self.policy,self.state,self.backend)
        self.broker=BrokerServer(self.gw,self.state,self.policy,agent_socket=root/'agent.sock',
            operator_socket=root/'operator.sock',agent_uid=10021,operator_uid=10022,
            allow_test_same_uid=True)
        self.request={'jsonrpc':'2.0','id':9,'method':'tools/call','params':{'name':'safe','arguments':{}}}

    def _records(self):
        with sqlite3.connect(self.state.path) as db:
            return [json.loads(r[0]) for r in db.execute("SELECT body FROM receipts ORDER BY seq")]

    def test_pause_before_gate_denies_call_without_dispatch_intent(self):
        entered=threading.Event();proceed=threading.Event()
        original=self.policy.evaluate
        def slow_evaluate(name,args):
            entered.set()
            if not proceed.wait(8): raise AssertionError('did not release evaluation')
            return original(name,args)
        object.__setattr__(self.policy, "evaluate", slow_evaluate)
        result=[]
        worker=threading.Thread(target=lambda:result.append(self.gw.handle(self.request)))
        worker.start()
        self.assertTrue(entered.wait(4))
        paused=self.broker._op({'op':'set_feature','feature':'gateway_enabled','enabled':False},10022)
        self.assertFalse(paused['controls']['gateway_enabled'])
        proceed.set();worker.join(8)
        self.assertFalse(worker.is_alive())
        self.assertEqual(result[0]['error']['message'],'operator_control_changed_before_dispatch')
        self.assertNotIn('tools/call',self.backend.calls)
        self.assertFalse(any(r.get('outcome')=='dispatch_intent' for r in self._records()))

    def test_pause_cannot_return_before_existing_dispatch_intent(self):
        permit_entered=threading.Event();release_permit=threading.Event()
        real=self.state.acquire_rate
        def slow_acquire(*a,**kw):
            permit_entered.set()
            if not release_permit.wait(8):raise AssertionError('rate gate held too long')
            return real(*a,**kw)
        self.state.acquire_rate=slow_acquire
        action=[];paused=[]
        worker=threading.Thread(target=lambda:action.append(self.gw.handle(self.request)))
        worker.start();self.assertTrue(permit_entered.wait(4))
        operator=threading.Thread(target=lambda:paused.append(self.broker._op(
            {'op':'set_feature','feature':'gateway_enabled','enabled':False},10022)))
        operator.start()
        # The operator may initiate a pause while an action is being committed,
        # but the pause cannot truthfully report success *before* the intent.
        time.sleep(0.12)
        self.assertFalse(paused)
        release_permit.set();worker.join(8);operator.join(8)
        self.assertFalse(worker.is_alive());self.assertFalse(operator.is_alive())
        self.assertEqual(len(action),1);self.assertIn('result',action[0])
        self.assertFalse(paused[0]['controls']['gateway_enabled'])
        records=self._records()
        dispatch_index=next(i for i,r in enumerate(records) if r.get('outcome')=='dispatch_intent')
        pause_index=max(i for i,r in enumerate(records) if r.get('decision')=='operator_control_change')
        self.assertLess(dispatch_index,pause_index)
        self.assertTrue(self.state.verify()['valid'])

    def test_pause_remains_responsive_during_in_flight_backend_request(self):
        self.backend.wait_during_call=True
        result=[]
        worker=threading.Thread(target=lambda:result.append(self.gw.handle(self.request)))
        worker.start();self.assertTrue(self.backend.entered.wait(4))
        started=time.monotonic()
        paused=self.broker._op({'op':'set_feature','feature':'gateway_enabled','enabled':False},10022)
        self.assertLess(time.monotonic()-started,2)
        self.assertFalse(paused['controls']['gateway_enabled'])
        self.backend.resume.set();worker.join(8)
        self.assertFalse(worker.is_alive())
        self.assertIn('result',result[0])  # already in-flight operation is not undone
        self.assertEqual(self.gw.handle(self.request)['error']['message'],
            'operator_disabled_gateway_or_audit')

if __name__=='__main__': unittest.main()
