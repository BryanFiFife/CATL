"""Disposable safety drill: uncertain dispatch must not run twice by accident."""
from __future__ import annotations
import json
import tempfile
from pathlib import Path
from catl.crypto import digest
from catl.gateway import Gateway
from catl.policy import Policy
from catl.store import State

TOOL = {"name": "simulate_send", "inputSchema": {"type": "object"}}
class SimulatedBackend:
    calls=0
    def request(self, method, params=None):
        if method == 'initialize': return {"result": {}}
        if method == 'tools/list': return {"result": {"tools": [TOOL]}}
        if method == 'tools/call':
            self.calls += 1
            if self.calls == 1: raise TimeoutError('response_lost_after_possible_effect')
            return {"result": {"content": []}}
        raise ValueError(method)
    def notify(self,method,params=None): pass
    def close(self): pass

def main():
    with tempfile.TemporaryDirectory(prefix='catl-incident-drill-') as td:
        state=State(Path(td)/'state.db', b'D'*32)
        state.set_feature('gateway_enabled', True, 'trusted_test_bootstrap')
        policy=Policy.from_dict({'agent_id':'drill-agent', 'tool_pins': {'simulate_send':digest(TOOL)},
            'rules':[{'tool':'simulate_send','effect':'allow','conditions':[]}]})
        backend=SimulatedBackend()
        gateway=Gateway(policy,state,backend)
        call={'jsonrpc':'2.0','id':1,'method':'tools/call',
            'params':{'name':'simulate_send','arguments':{}}}
        first=gateway.handle(call)
        assert first['error']['message']=='tool_transport_failure'
        restarted=Gateway(policy,State(state.path,b'D'*32),backend)
        second=restarted.handle(call)
        assert second['error']['message']=='tool_quarantined_pending_reconciliation'
        assert backend.calls==1
        incident=state.open_incidents()[0]
        assert state.reconcile_incident(incident['action_id'],'trusted_operator',
            'ticket:synthetic-drill-reconciled','I_HAVE_RECONCILED_THE_EXTERNAL_EFFECT')
        third=restarted.handle(call)
        assert 'result' in third and backend.calls==2
        assert state.verify()['valid']
        return {'passed':True,'first_call_uncertain':True,'second_call_blocked':True,
                'manual_reconciliation_recorded':True,'new_call_after_reconciliation':True,
                'live_external_system_used':False}
if __name__=='__main__':
    print(json.dumps(main(),sort_keys=True))
