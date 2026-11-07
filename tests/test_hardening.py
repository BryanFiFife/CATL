"""High-signal security cases for v0.2; not a penetration-test certification."""
from __future__ import annotations
import copy
import hashlib
import json
import os
import sys
import tempfile
import time
import unittest
from pathlib import Path
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'src'))
sys.path.insert(0, str(ROOT / 'examples'))
from catl.crypto import digest
from catl.gateway import Gateway, SubprocessBackend
from catl.isolation import isolation_for, child_environment
from catl.policy import Policy
from catl.protocol import MODERN, VERSION_KEY, CAPABILITY_KEY
from catl.store import State
from catl.verifier import FileDigestVerifier
from mock_server import TOOLS


def packet(method, params=None, id_=1):
    return {"jsonrpc": "2.0", "id": id_, "method": method, "params": params or {}}


def modern(method, params=None, id_=1, *, version=MODERN, capabilities=None):
    arg = {**(params or {})}
    arg['_meta'] = {VERSION_KEY: version, CAPABILITY_KEY: {} if capabilities is None else capabilities}
    return packet(method, arg, id_)


class Backend:
    def __init__(self):
        self.tools = copy.deepcopy(TOOLS)
        self.call_count = 0
        self.init_count = 0
        self.notification_count = 0
        self.file_path = None
        self.pages = None
        self.tamper_result = False
    def request(self, method, params=None):
        if method == 'initialize':
            self.init_count += 1
            return {'result': {'capabilities': {'tools': {}}, 'protocolVersion': '2025-11-25'}}
        if method == 'tools/list':
            if self.pages is not None:
                return {'result': self.pages.get(params.get('cursor') if params else None, {'tools': []})}
            return {'result': {'tools': self.tools}}
        if method == 'tools/call':
            self.call_count += 1
            if self.file_path:
                self.file_path.write_bytes(params['arguments']['content'].encode('utf-8'))
            if self.tamper_result:
                return {'result': 'not_an_object'}
            return {'result': {'content': [{'type': 'text', 'text': 'done'}]}}
        raise RuntimeError('unknown method')
    def notify(self, method, params=None):
        self.notification_count += 1
    def close(self):
        pass


class ModernTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.backend = Backend()
        self.policy = Policy.from_dict({'agent_id': 'worker', 'tool_pins': {t['name']: digest(t) for t in TOOLS}, 'rules': [
            {'tool': 'echo_safe', 'effect': 'allow', 'conditions': []},
            {'tool': 'write_demo', 'effect': 'approve', 'conditions': []}]})
        self.state = State(Path(self.tmp.name) / 'state.sqlite3', b'x'*32)
        self.state.set_feature('gateway_enabled', True, 'test-bootstrap')
        self.gw = Gateway(self.policy, self.state, self.backend)

    def test_modern_discovery_result_complete_and_server_identity(self):
        out = self.gw.handle(modern('server/discover'))
        self.assertEqual(out['result']['resultType'], 'complete')
        self.assertEqual(out['result']['capabilities'], {'tools': {'listChanged': False}})
        self.assertEqual(out['result']['_meta']['io.modelcontextprotocol/serverInfo']['name'], 'caledapt-agent-trust')
        self.assertEqual(self.backend.init_count, 0)

    def test_modern_list_autoinitializes_legacy_backend(self):
        out = self.gw.handle(modern('tools/list'))
        self.assertEqual(out['result']['resultType'], 'complete')
        self.assertEqual(self.backend.init_count, 1)
        self.assertEqual(self.backend.notification_count, 1)
        self.assertEqual(len(out['result']['tools']), 2)

    def test_modern_direct_call(self):
        out = self.gw.handle(modern('tools/call', {'name':'echo_safe','arguments':{'message':'hello'}}))
        self.assertEqual(out['result']['resultType'], 'complete')
        self.assertEqual(self.backend.call_count, 1)

    def test_modern_denied(self):
        out = self.gw.handle(modern('tools/call', {'name':'unknown','arguments':{}}))
        self.assertIn('error', out)
        self.assertEqual(self.backend.call_count, 0)

    def test_unsupported_revision_fails(self):
        out = self.gw.handle(modern('tools/list', version='2027-01-01'))
        self.assertEqual(out['error']['code'], -32022)
        self.assertEqual(self.backend.init_count, 0)

    def test_missing_capabilities_fails(self):
        msg = modern('tools/list')
        del msg['params']['_meta'][CAPABILITY_KEY]
        self.assertEqual(self.gw.handle(msg)['error']['message'], 'modern_client_capabilities_required')

    def test_wrong_capabilities_type_fails(self):
        self.assertIn('error', self.gw.handle(modern('tools/list', capabilities='all')))

    def test_bad_identity_fails(self):
        msg = modern('tools/list')
        msg['params']['_meta']['io.modelcontextprotocol/clientInfo'] = {'name': 123}
        self.assertIn('error', self.gw.handle(msg))

    def test_modern_cannot_initialize_or_ping(self):
        for method in ('initialize','ping'):
            self.assertEqual(self.gw.handle(modern(method))['error']['code'], -32601)

    def test_modern_mrtr_retry_fails_closed(self):
        out = self.gw.handle(modern('tools/call', {'name':'echo_safe','arguments':{},'inputResponses':{'foo':{'action':'accept'}}}))
        self.assertEqual(out['error']['message'], 'multi_round_trip_not_supported')
        self.assertEqual(self.backend.call_count, 0)

    def test_legacy_still_works(self):
        init = self.gw.handle(packet('initialize', {'protocolVersion':'2025-11-25','capabilities':{}}))
        self.assertIn('result', init)
        result = self.gw.handle(packet('tools/list'))
        self.assertNotIn('resultType', result['result'])

    def test_pagination_two_pages_and_stable_sorting(self):
        self.backend.pages = {None:{'tools':[self.backend.tools[1]],'nextCursor':'next'},'next':{'tools':[self.backend.tools[0]]}}
        tools = self.gw.handle(modern('tools/list'))['result']['tools']
        self.assertEqual([t['name'] for t in tools], ['echo_safe', 'write_demo'])

    def test_pagination_repeated_cursor_blocked(self):
        self.backend.pages = {None:{'tools':[],'nextCursor':'A'}, 'A':{'tools':[], 'nextCursor':'A'}}
        self.assertIn('error', self.gw.handle(packet('tools/list')))

    def test_pagination_duplicate_across_pages_blocked(self):
        self.backend.pages = {None:{'tools':[self.backend.tools[0]],'nextCursor':'A'}, 'A':{'tools':[self.backend.tools[0]]}}
        self.assertIn('error', self.gw.handle(packet('tools/list')))

    def test_unexpected_result_kind_blocked(self):
        from catl.protocol import modernize
        out = modernize({'jsonrpc':'2.0','id':4,'result':{'resultType':'input_required','inputRequests':{}}})
        self.assertEqual(out['error']['message'],'unsupported_backend_result_type')

    def test_malformed_result_meta_blocked(self):
        from catl.protocol import modernize
        out = modernize({'jsonrpc':'2.0','id':4,'result':{'_meta':['forged']}})
        self.assertEqual(out['error']['message'],'invalid_backend_result_metadata')

    def test_malformed_backend_result_denied(self):
        self.backend.tamper_result = True
        self.assertEqual(self.gw.handle(packet('tools/call', {'name':'echo_safe','arguments':{'message':'hello'}}))['error']['message'], 'backend_result_invalid')


class IsolationTests(unittest.TestCase):
    def test_default_requires_isolation(self):
        with self.assertRaises(PermissionError):
            isolation_for(None, False)

    def test_demo_override_explicit(self):
        self.assertTrue(isolation_for(None, True).unsandboxed)

    @unittest.skipUnless(os.name=='posix', 'POSIX identity test')
    def test_self_identity_cannot_be_backend(self):
        import pwd
        own = pwd.getpwuid(os.geteuid()).pw_name
        with self.assertRaises(PermissionError):
            isolation_for(own, False)

    @unittest.skipUnless(os.name=='posix', 'POSIX identity test')
    def test_root_is_not_a_backend_identity(self):
        with self.assertRaises(PermissionError):
            isolation_for('root', False)

    def test_clean_environment_drops_unexpected_secret(self):
        old=os.environ.get('AWS_SECRET_ACCESS_KEY')
        os.environ['AWS_SECRET_ACCESS_KEY']='NEVER_PASS_BY_DEFAULT'
        try:
            self.assertNotIn('AWS_SECRET_ACCESS_KEY', child_environment())
            self.assertEqual(child_environment(pass_env=('AWS_SECRET_ACCESS_KEY',))['AWS_SECRET_ACCESS_KEY'], 'NEVER_PASS_BY_DEFAULT')
        finally:
            if old is None: del os.environ['AWS_SECRET_ACCESS_KEY']
            else: os.environ['AWS_SECRET_ACCESS_KEY']=old

    def test_invalid_env_name_rejected(self):
        with self.assertRaises(ValueError):
            child_environment(pass_env=('AWS_KEY; evil',))

    def test_subprocess_rejected_without_explicit_override(self):
        with self.assertRaises(PermissionError):
            SubprocessBackend([sys.executable, '-c','print("no")'])


class PostconditionTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.backend = Backend()
        self.backend.file_path = self.root/'write.txt'
        # This test simulates a reviewed write backend with a real input schema.
        self.backend.tools[1]['inputSchema'] = {'type':'object',
            'properties':{'content':{'type':'string'},'filename':{'type':'string'},'sha256':{'type':'string'}},
            'required':['content','filename','sha256']}
        self.tool = self.backend.tools[1]
        self.info = {'kind':'file_sha256','root':str(self.root),'path_pointer':'/filename', 'digest_pointer':'/sha256'}
        self.policy = Policy.from_dict({'agent_id':'writer','tool_pins': {self.tool['name']:digest(self.tool)},
                                        'rules':[{'tool':self.tool['name'],'effect':'allow','conditions':[]}],
                                        'postconditions':{'write_demo':self.info}})
        self.state = State(self.root/'state.sqlite3', b'y'*32)
        self.state.set_feature('gateway_enabled', True, 'test-bootstrap')
        self.gw = Gateway(self.policy, self.state, self.backend)

    def args(self, content='hello', sha=None, filename='write.txt'):
        return {'name':'write_demo','arguments':{'content':content,'filename':filename,
            'sha256':sha or hashlib.sha256(content.encode()).hexdigest()}}

    def test_verified_real_file_sha(self):
        result = self.gw.handle(packet('tools/call', self.args()))
        self.assertIn('result', result)
        self.assertEqual(self.backend.file_path.read_bytes(), b'hello')
        self.assertEqual(self.state.verify()['count'], 5)  # includes signed rate permit

    def test_changed_backend_output_refused(self):
        args = self.args(sha='0'*64)
        result = self.gw.handle(packet('tools/call', args))
        self.assertEqual(result['error']['message'], 'postcondition_failed_side_effect_possible')
        self.assertEqual(self.backend.file_path.read_bytes(), b'hello')  # side effect was real

    def test_path_traversal_rejected(self):
        v=FileDigestVerifier.from_dict(self.info)
        with self.assertRaises(ValueError): v.verify(self.args(filename='../escape')['arguments'])

    def test_preflight_traversal_blocks_dispatch(self):
        response = self.gw.handle(packet('tools/call', self.args(filename='../escape')))
        self.assertEqual(response['error']['message'], 'postcondition_preflight_invalid')
        self.assertEqual(self.backend.call_count, 0)

    def test_preflight_bad_digest_blocks_dispatch(self):
        response = self.gw.handle(packet('tools/call', self.args(sha='abc')))
        self.assertEqual(response['error']['message'], 'postcondition_preflight_invalid')
        self.assertEqual(self.backend.call_count, 0)

    def test_absolute_path_rejected(self):
        v=FileDigestVerifier.from_dict(self.info)
        with self.assertRaises(ValueError): v.verify(self.args(filename=str(self.root/'write.txt'))['arguments'])

    @unittest.skipIf(os.name == "nt", "Windows symlink privileges vary")
    def test_symlink_file_rejected(self):
        data=self.root/'real.txt'; data.write_text('hello')
        fake=self.root/'write.txt'; fake.symlink_to(data)
        v=FileDigestVerifier.from_dict(self.info)
        with self.assertRaises(ValueError): v.verify(self.args()['arguments'])

    @unittest.skipIf(os.name == "nt", "Windows symlink privileges vary")
    def test_symlink_parent_rejected(self):
        nested=self.root/'real';nested.mkdir();(nested/'write.txt').write_text('hello')
        (self.root/'sym').symlink_to(nested, target_is_directory=True)
        v=FileDigestVerifier.from_dict(self.info)
        with self.assertRaises(ValueError): v.verify(self.args(filename='sym/write.txt')['arguments'])

    def test_oversize_file_rejected(self):
        target=self.root/'write.txt'
        with target.open('wb') as f: f.truncate(32*1024*1024+1)
        v=FileDigestVerifier.from_dict(self.info)
        with self.assertRaises(ValueError): v.verify(self.args()['arguments'])

    def test_nonexistent_path_fails_postcondition(self):
        self.backend.file_path = self.root/'other.txt'
        self.assertEqual(self.gw.handle(packet('tools/call', self.args()))['error']['message'], 'postcondition_failed_side_effect_possible')

    def test_unknown_postcondition_tool_fails_load(self):
        with self.assertRaises(ValueError):
            Policy.from_dict({'agent_id':'writer','tool_pins':{},'rules':[], 'postconditions':{'bad':self.info}})

    def test_postcondition_policy_pinned_hash_changes(self):
        original=self.policy.source_hash
        v=dict(self.info);v['path_pointer']='/other'
        changed=Policy.from_dict({'agent_id':'writer','tool_pins': {self.tool['name']:digest(self.tool)},
                                        'rules':[{'tool':self.tool['name'],'effect':'allow','conditions':[]}],
                                        'postconditions':{'write_demo':v}})
        self.assertNotEqual(original,changed.source_hash)
