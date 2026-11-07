"""An adversarial result firewall for pinned MCP tool outputs."""
import unittest
from catl.gateway import checked_tool_reply


class ResultFirewall(unittest.TestCase):
    def test_legacy_complete_remains_compatible(self):
        kind, result = checked_tool_reply({'result':{'content':[]}})
        self.assertEqual(kind, 'result')
        self.assertEqual(result['content'], [])

    def test_explicit_complete_accepted(self):
        kind, result = checked_tool_reply({'result':{'resultType':'complete','content':[]}})
        self.assertEqual(result['resultType'], 'complete')

    def test_input_required_fails_closed(self):
        for variant in ('input_required', 'pending', 'task', 'complete\u0000', None):
            with self.subTest(variant=variant), self.assertRaises(ValueError):
                checked_tool_reply({'result':{'resultType':variant,'content':[],'inputRequests':{'x':{}}}})

    def test_pinned_output_schema_success(self):
        tool={'outputSchema':{'type':'object','properties':{'count':{'type':'integer'}},'required':['count'],'additionalProperties':False}}
        kind, result = checked_tool_reply({'result':{'content':[],'structuredContent':{'count':7}}},tool=tool)
        self.assertEqual(result['structuredContent']['count'],7)

    def test_wrong_schema_result_is_rejected(self):
        tool={'outputSchema':{'type':'object','properties':{'count':{'type':'integer'}},'required':['count']}}
        for bad in ({'count':'seven'}, {}, ['count',7], None):
            with self.subTest(bad=bad),self.assertRaises(ValueError):
                checked_tool_reply({'result':{'content':[],'structuredContent':bad}},tool=tool)

    def test_remote_ref_never_loads(self):
        tool={'outputSchema':{'$ref':'https://attacker.invalid/resolve.json'}}
        with self.assertRaises(ValueError):
            checked_tool_reply({'result':{'content':[],'structuredContent':{}}},tool=tool)

    def test_error_result_skips_success_schema(self):
        tool={'outputSchema':{'type':'object','required':['count']}}
        _, result=checked_tool_reply({'result':{'content':[],'isError':True}},tool=tool)
        self.assertTrue(result['isError'])

    def test_untrusted_meta_stripped(self):
        _, result=checked_tool_reply({'result':{'content':[],'_meta':{'CATL-Approved':True}}})
        self.assertNotIn('_meta',result)

    def test_result_reply_with_extra_rpc_error_refused(self):
        with self.assertRaises(ValueError):
            checked_tool_reply({'result':{'content':[]},'error':{'code':1,'message':'x'}})

class GatewayReceiptIntegrity(unittest.TestCase):
    """Prove the gateway records uncertainty instead of blessing backend data."""
    def setUp(self):
        import tempfile
        from pathlib import Path
        from catl.crypto import digest
        from catl.gateway import Gateway
        from catl.policy import Policy
        from catl.store import State
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.tool = {'name':'read_structured','inputSchema':{'type':'object','additionalProperties':False},
                     'outputSchema':{'type':'object','required':['ok'],
                                     'properties':{'ok':{'type':'boolean'}},'additionalProperties':False}}
        self.state = State(Path(self.tmp.name)/'audit.sqlite3', b'S'*32)
        self.state.set_feature('gateway_enabled',True,'operator')
        self.policy = Policy.from_dict({'agent_id':'test','tool_pins':{'read_structured':digest(self.tool)},
                       'rules':[{'tool':'read_structured','effect':'allow','conditions':[]}]})
        class Backend:
            reply={'result':{'content':[],'structuredContent':{'ok':True}}}
            dispatched=0
            def request(inner,method,params=None):
                if method=='initialize':return {'result':{'protocolVersion':'2025-11-25'}}
                if method=='tools/list':return {'result':{'tools':[self.tool]}}
                if method=='tools/call':
                    inner.dispatched+=1
                    return inner.reply
                raise AssertionError(method)
            def notify(inner,method,params=None): pass
            def close(inner): pass
        self.backend=Backend()
        self.gateway=Gateway(self.policy,self.state,self.backend)
    def call(self):
        return self.gateway.handle({'jsonrpc':'2.0','id':1,'method':'tools/call',
                    'params':{'name':'read_structured','arguments':{}}})
    def test_structured_output_valid_allowed(self):
        self.assertIn('result',self.call())
        self.assertTrue(self.state.verify()['valid'])
    def test_structured_output_mismatch_uncertain_and_audited(self):
        import json,sqlite3
        self.backend.reply={'result':{'content':[],'structuredContent':{'ok':'not-a-bool'}}}
        response=self.call()
        self.assertEqual(response['error']['message'],'backend_result_unverified_side_effect_possible')
        self.assertEqual(self.backend.dispatched,1)
        self.assertTrue(self.state.verify()['valid'])
        with sqlite3.connect(self.state.path) as db:
            bodies=[json.loads(row[0]) for row in db.execute('SELECT body FROM receipts')]
        self.assertTrue(any(x.get('outcome')=='invalid_backend_result_side_effect_possible' for x in bodies))
    def test_input_required_uncertain_and_not_retried_automatically(self):
        self.backend.reply={'result':{'resultType':'input_required','content':[],
                       'inputRequests':{'confirm':{'type':'text'}}}}
        response=self.call()
        self.assertEqual(response['error']['message'],'backend_result_unverified_side_effect_possible')
        self.assertEqual(self.backend.dispatched,1)
