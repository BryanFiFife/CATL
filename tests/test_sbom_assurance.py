import sys,unittest,hashlib,json,tempfile
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'tools'))
from sbom_assurance import verify_source_manifest,validate_cyclonedx,AssuranceRejected
class TestSBOM(unittest.TestCase):
 def setUp(self):
  self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup);self.root=Path(self.tmp.name)
  (self.root/'code.py').write_text('print(1)\n');digest=hashlib.sha256((self.root/'code.py').read_bytes()).hexdigest()
  self.files={'code.py':digest};self.write()
  self.bom={'bomFormat':'CycloneDX','specVersion':'1.6','components':[{'bom-ref':'a','name':'lib','version':'1.0.0'}]}
 def write(self):
  (self.root/'RELEASE_MANIFEST.json').write_text(json.dumps({'algorithm':'sha256','files':self.files}))
  (self.root/'SHA256SUMS.txt').write_text(''.join(f'{h}  {p}\n' for p,h in self.files.items()))
 def test_valid(self):self.assertEqual(verify_source_manifest(self.root)['files'],1)
 def test_bad_hash(self):
  (self.root/'code.py').write_text('print(2)')
  with self.assertRaisesRegex(AssuranceRejected,'digest'):verify_source_manifest(self.root)
 def test_index_mismatch(self):
  (self.root/'SHA256SUMS.txt').write_text('')
  with self.assertRaises(AssuranceRejected):verify_source_manifest(self.root)
 def test_traversal(self):
  self.files={'../evil': '0'*64};self.write()
  with self.assertRaises(AssuranceRejected):verify_source_manifest(self.root)
 def test_symlink(self):
  target=self.root/'target';target.write_text('');(self.root/'code.py').unlink();(self.root/'code.py').symlink_to(target)
  with self.assertRaises(AssuranceRejected):verify_source_manifest(self.root)
 def test_sbom_valid(self):self.assertEqual(validate_cyclonedx(self.bom)['component_count'],1)
 def test_sbom_duplicate(self):
  self.bom['components'].append(self.bom['components'][0])
  with self.assertRaises(AssuranceRejected):validate_cyclonedx(self.bom)
 def test_sbom_unpinned(self):
  self.bom['components'][0]['version']='latest'
  with self.assertRaises(AssuranceRejected):validate_cyclonedx(self.bom)
if __name__=='__main__':unittest.main()
