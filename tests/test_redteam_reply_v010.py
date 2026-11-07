"""Hostile MCP tool-output tests: type confusion and active URL injection."""
import unittest
from catl.gateway import checked_tool_reply


class HostileBackendResultTests(unittest.TestCase):
    def checked(self, item):
        return checked_tool_reply({'result':{'content':[item]}})

    def test_unknown_result_type_rejected(self):
        for kind in ('shell', 'javascript', 'tool_call', 'approval', '', None):
            with self.subTest(kind=kind), self.assertRaises(ValueError):
                self.checked({'type': kind, 'command':'run'})

    def test_active_or_local_resource_links_rejected(self):
        urls = ('javascript:alert(1)', 'data:text/html,test', 'file:///etc/passwd',
                'http://127.0.0.1:2380/admin', 'https://user:pass@example.com/x',
                'https://localhost/admin', 'https://a.localhost/foo', 'https://127.0.0.1/admin', 'https://192.168.1.1/config', 'https://[::1]/',
                'https://example.com/\nAuthorization:secret')
        for uri in urls:
            with self.subTest(uri=uri), self.assertRaises(ValueError):
                self.checked({'type':'resource_link','uri':uri,'name':'poison'})

    def test_https_resource_link_and_text_pass(self):
        self.assertEqual(self.checked({'type':'resource_link','uri':'https://example.com/a','name':'ref'})[0], 'result')
        self.assertEqual(self.checked({'type':'text','text':'untrusted instructions'})[0], 'result')

    def test_media_requires_correct_mime_and_data(self):
        for item in ({'type':'image','data':'AAAA','mimeType':'text/html'},
                     {'type':'audio','data':'AAAA'}, {'type':'image','mimeType':'image/png'}):
            with self.subTest(item=item), self.assertRaises(ValueError):
                self.checked(item)
        self.assertEqual(self.checked({'type':'image','data':'AAAA','mimeType':'image/png'})[0],'result')

    def test_backend_metadata_and_unknown_result_fields_are_not_forwarded(self):
        kind, payload = checked_tool_reply({'result': {
            'content': [{'type':'text','text':'safe','admin':True,
                         '_meta':{'trusted':True}}],
            'CATL_BYPASS': True, '_meta': {'role':'operator'},
            'annotations': {'trusted':True}, 'isError': False}})
        self.assertEqual(kind, 'result')
        self.assertEqual(payload, {'content':[{'type':'text','text':'safe'}],
                                   'isError':False})
        for continuation in ('inputRequests', 'requestState'):
            with self.subTest(continuation=continuation),self.assertRaises(ValueError):
                checked_tool_reply({'result': {'content': [], 'resultType': 'complete',
                                                continuation: {'evil':'retry'}}})

    def test_pinned_array_output_schema_is_valid_mcp(self):
        tool = {'name': 'rows', 'inputSchema': {'type': 'object'},
                'outputSchema': {'type': 'array', 'items': {'type': 'integer'}}}
        self.assertEqual(checked_tool_reply({'result': {'content': [],
            'structuredContent': [1, 2, 3]}}, tool=tool)[0], 'result')
        with self.assertRaises(ValueError):
            checked_tool_reply({'result': {'content': [],
                'structuredContent': ['one']}}, tool=tool)

    def test_resource_requires_text_or_blob_not_both(self):
        for content in ({'uri':'file:///tmp/a'}, {'uri':'r','text':'x','blob':'AAAA'}):
            with self.subTest(content=content),self.assertRaises(ValueError):
                self.checked({'type':'resource','resource':content})
        self.assertEqual(self.checked({'type':'resource','resource':{'uri':'https://example.com/foo','text':'text'}})[0],'result')
        with self.assertRaises(ValueError):
            self.checked({'type':'resource','resource':{'uri':'file:///private/secret','text':'secret'}})

if __name__=='__main__': unittest.main()
