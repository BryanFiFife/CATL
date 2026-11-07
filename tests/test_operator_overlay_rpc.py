"""Overlay uses an operator RPC client rather than taking possession of HMAC keys."""
import os
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

class FakeOperatorClient:
    def __init__(self):
        self.doc={"gateway_enabled": False, "approvals_enabled": True,
                  "verification_enabled":True, "audit_enabled":True, "disabled_tools": []}
        self.calls=[]
        self.requests=[]
        self.incidents=[]
    def status(self):
        return {"controls":dict(self.doc),"tools":["echo_safe","send_message"]}
    def controls(self):
        return dict(self.doc)
    def list_pending(self):
        return list(self.requests)
    def open_incidents(self):
        return list(self.incidents)
    def reconcile_incident(self,action_id,actor,reference,acknowledgement):
        self.calls.append(('reconcile',action_id,reference))
        self.incidents=[x for x in self.incidents if x['action_id'] != action_id]
        return True
    def set_feature(self,name,on,actor):
        self.calls.append(("feature",name,on))
        self.doc[name]=on
        return self.controls()
    def set_tool(self,name,on,actor,tools):
        self.calls.append(("tool",name,on))
        banned=set(self.doc['disabled_tools'])
        (banned.discard if on else banned.add)(name)
        self.doc['disabled_tools']=sorted(banned)
        return self.controls()
    def set_all_tools(self,on,actor,tools):
        self.calls.append(("all",on))
        self.doc['disabled_tools']=[] if on else sorted(tools)
        return self.controls()
    def decide(self,id,actor,approve):
        self.calls.append(("decide",id,approve))
        return True

@unittest.skipUnless((os.environ.get('DISPLAY') or os.name == 'nt' or sys.platform == 'darwin') and os.environ.get('CATL_CI_HEADLESS') != '1', 'headless test environment')
class TestBrokerOverlayWindow(unittest.TestCase):
    def setUp(self):
        import tkinter as tk
        from catl.overlay import OperatorOverlay
        self.root=tk.Tk()
        self.addCleanup(self.root.destroy)
        self.client=FakeOperatorClient()
        policy=SimpleNamespace(tool_pins={'echo_safe':'x','send_message':'y'})
        self.widget=OperatorOverlay(self.root,self.client,policy,topmost=False)
        self.root.update()

    def test_minimize_collapse_expand(self):
        self.assertFalse(self.widget.compact)
        self.widget.toggle_compact()
        self.assertTrue(self.widget.compact)
        self.widget.toggle_compact()
        self.assertFalse(self.widget.compact)

    def test_toolbar_updates_broker_client(self):
        self.widget.toggle_feature('gateway_enabled',True)
        self.assertIn(('feature','gateway_enabled',True),self.client.calls)
        self.assertTrue(self.widget.feature_vars['gateway_enabled'].get())
        self.widget.toggle_tool('send_message',False)
        self.assertIn(('tool','send_message',False),self.client.calls)
        self.assertFalse(self.widget.tool_vars['send_message'].get())

    def test_quarantine_cannot_be_cleared_by_toggle(self):
        self.client.incidents=[{'action_id':'a'*32,'tool':'send_message',
                              'status':'dispatch_outcome_unknown','binding':'B','at':1}]
        self.widget.refresh()
        self.assertFalse(self.widget.tool_vars['send_message'].get())
        self.widget.toggle_tool('send_message',True)
        self.assertFalse(self.widget.tool_vars['send_message'].get())
        self.assertEqual(self.widget.incident_list.size(), 1)

    def test_all_sections_scroll_without_squashing_approval_queue(self):
        self.root.update_idletasks()
        self.assertGreaterEqual(self.widget.pending.winfo_height(), 30)
        self.assertGreater(self.widget.content.winfo_height(), self.widget.body_canvas.winfo_height())
        self.widget.body_canvas.yview_moveto(1)
        self.root.update_idletasks()
        self.assertGreater(float(self.widget.body_canvas.yview()[0]), 0)

    def test_no_direct_state_or_hmac_key_owned_by_gui(self):
        self.assertIs(self.widget.state,self.client)
        self.assertFalse(hasattr(self.widget.state,'key'))
        self.assertFalse(hasattr(self.widget.state,'path'))
