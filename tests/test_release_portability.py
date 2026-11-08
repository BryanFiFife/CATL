"""Cross-platform release archive filename collision and path safety regressions."""
from __future__ import annotations
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

PACK = Path(__file__).resolve().parents[1] / 'tools' / 'release_pack.py'
ENV = {**os.environ, 'GIT_AUTHOR_NAME':'CATL offline test',
       'GIT_AUTHOR_EMAIL':'offline@example.invalid',
       'GIT_COMMITTER_NAME':'CATL offline test',
       'GIT_COMMITTER_EMAIL':'offline@example.invalid'}

class PortableArchiveTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory(prefix='catl-portability-')
        self.addCleanup(self.tmp.cleanup)
        self.repo=Path(self.tmp.name)/'repo'
        (self.repo/'tools').mkdir(parents=True)
        (self.repo/'tools'/'release_pack.py').write_bytes(PACK.read_bytes())
        (self.repo/'pyproject.toml').write_text('[project]\nname="caledapt-agent-trust"\nversion="0.11.0rc1"\n')
        (self.repo/'README.md').write_text('base\n')
        self.git('init','-q'); self.git('add','.'); self.git('commit','-qm','base')
    def git(self,*args):
        return subprocess.run(['git',*args],cwd=self.repo,env=ENV,text=True,capture_output=True,check=True).stdout
    def add_committed(self,name):
        path=self.repo/name
        path.parent.mkdir(parents=True,exist_ok=True)
        path.write_text('synthetic payload')
        self.git('add','--',name);self.git('commit','-qm','fixture')
    def build(self):
        return subprocess.run([sys.executable,str(self.repo/'tools'/'release_pack.py'),
                               '--output',str(Path(self.tmp.name)/'out.zip')],
                              cwd=self.repo,text=True,capture_output=True,env=ENV)

    def test_windows_reserved_device_names_refused(self):
        for name in ['CON', 'aux.txt', 'LPT1.log', 'NUL', 'com9.txt', 'COM¹.txt', 'LPT³.log', 'CONIN$', 'CONOUT$']:
            with self.subTest(name=name):
                with self.repo.joinpath(name).open('w') as f:f.write('data')
                self.git('add','--',name);self.git('commit','-qm','fixture')
                result=self.build()
                self.assertNotEqual(result.returncode,0,(name,result.stdout,result.stderr))
                self.git('rm','-q','--',name);self.git('commit','-qm','removed')

    def test_windows_alternate_data_stream_and_illegal_characters_refused(self):
        for name in ['payload:stream', 'question?.txt', 'pipe|name.txt']:
            with self.subTest(name=name):
                self.add_committed(name)
                result=self.build()
                self.assertNotEqual(result.returncode,0,(name,result.stdout,result.stderr))
                self.git('rm','-q','--',name);self.git('commit','-qm','removed')

    def test_windows_trailing_dot_and_space_refused(self):
        for name in ['foo.', 'trailing ']:
            with self.subTest(name=name):
                self.add_committed(name)
                result=self.build()
                self.assertNotEqual(result.returncode,0,(name,result.stdout,result.stderr))
                self.git('rm','-q','--',name);self.git('commit','-qm','removed')

    def test_case_insensitive_extract_collision_refused(self):
        self.add_committed('readme.md')
        self.assertNotEqual(self.build().returncode,0,'README.md/readme.md collision accepted')

    def test_case_insensitive_file_directory_collision_refused(self):
        self.add_committed('DOCS')
        self.add_committed('docs/readme.txt')
        self.assertNotEqual(self.build().returncode, 0,
                            'DOCS file collides with docs/ directory on target filesystem')

    def test_unicode_normalization_extract_collision_refused(self):
        self.add_committed('café.txt')
        self.add_committed('cafe\u0301.txt')
        self.assertNotEqual(self.build().returncode,0,'NFC/NFD duplicate accepted')

class ArchiveMetadataCoherenceTests(unittest.TestCase):
    def setUp(self):
        self.lab=PortableArchiveTests(methodName='test_case_insensitive_extract_collision_refused')
        self.lab.setUp()
        self.addCleanup(self.lab.tmp.cleanup)
        result=self.lab.build()
        if result.returncode:
            raise AssertionError(result.stderr)
        self.archive=Path(self.lab.tmp.name)/'out.zip'

    def mutate_archive(self, mutate):
        import hashlib, json, zipfile, stat
        with zipfile.ZipFile(self.archive) as z:
            files={n:z.read(n) for n in z.namelist()
                   if n not in ('RELEASE_MANIFEST.json','SHA256SUMS.txt')}
            m=json.loads(z.read('RELEASE_MANIFEST.json'))
        mutate(files,m)
        m['files']={n:hashlib.sha256(b).hexdigest() for n,b in files.items()}
        files['RELEASE_MANIFEST.json']=(json.dumps(m,indent=2,sort_keys=True)+'\n').encode()
        files['SHA256SUMS.txt']=''.join(f'{hash_}  {n}\n' for n,hash_ in sorted(m['files'].items())).encode()
        with zipfile.ZipFile(self.archive,'w',compression=zipfile.ZIP_DEFLATED) as z:
            for name,data in files.items():
                i=zipfile.ZipInfo(name,(2026,11,7,0,0,0))
                i.compress_type=zipfile.ZIP_DEFLATED
                i.external_attr=(stat.S_IFREG|0o644)<<16
                z.writestr(i,data)

    def test_recomputed_checksum_archive_with_windows_device_refused(self):
        self.mutate_archive(lambda files,m:files.update({'AUX.txt':b'synthetic'}))
        result=subprocess.run(
            [sys.executable,str(self.lab.repo/'tools'/'release_pack.py'),'--verify',str(self.archive)],
            text=True,capture_output=True,env=ENV,cwd=self.lab.repo)
        self.assertNotEqual(result.returncode,0,result.stdout)

    def test_recomputed_checksum_archive_with_file_directory_collision_refused(self):
        self.mutate_archive(lambda files,m:files.update({'DOCS':b'file', 'docs/child.txt':b'child'}))
        result=subprocess.run([sys.executable,str(self.lab.repo/'tools'/'release_pack.py'),'--verify',str(self.archive)],
                              text=True,capture_output=True,env=ENV,cwd=self.lab.repo)
        self.assertNotEqual(result.returncode,0,result.stdout)

    def test_recomputed_checksum_archive_with_case_collision_refused(self):
        self.mutate_archive(lambda files,m:files.update({'readme.md':b'collision'}))
        result=subprocess.run([sys.executable,str(self.lab.repo/'tools'/'release_pack.py'),'--verify',str(self.archive)],
                              text=True,capture_output=True,env=ENV,cwd=self.lab.repo)
        self.assertNotEqual(result.returncode,0,result.stdout)

    def test_recomputed_checksum_archive_with_version_mismatch_refused(self):
        self.mutate_archive(lambda files,m:files.update({'pyproject.toml':b'[project]\nname="caledapt-agent-trust"\nversion="9.9.9"\n'}))
        result=subprocess.run([sys.executable,str(self.lab.repo/'tools'/'release_pack.py'),'--verify',str(self.archive)],
                              text=True,capture_output=True,env=ENV,cwd=self.lab.repo)
        self.assertNotEqual(result.returncode,0,result.stdout)

    def test_missing_source_commit_refused_even_when_hashes_coherent(self):
        self.mutate_archive(lambda files,m:m.pop('source_commit'))
        result=subprocess.run([sys.executable,str(self.lab.repo/'tools'/'release_pack.py'),'--verify',str(self.archive)],
                              text=True,capture_output=True,env=ENV,cwd=self.lab.repo)
        self.assertNotEqual(result.returncode,0,result.stdout)
    def test_recomputed_checksum_archive_with_package_name_mismatch_refused(self):
        self.mutate_archive(lambda files,m:files.update({'pyproject.toml':b'[project]\nname="attacker-package"\nversion="0.11.0rc1"\n'}))
        result=subprocess.run([sys.executable,str(self.lab.repo/'tools'/'release_pack.py'),'--verify',str(self.archive)],
                              text=True,capture_output=True,env=ENV,cwd=self.lab.repo)
        self.assertNotEqual(result.returncode,0,result.stdout)

    def test_recomputed_checksum_archive_without_package_name_refused(self):
        self.mutate_archive(lambda files,m:files.update({'pyproject.toml':b'[project]\nversion="0.11.0rc1"\n'}))
        result=subprocess.run([sys.executable,str(self.lab.repo/'tools'/'release_pack.py'),'--verify',str(self.archive)],
                              text=True,capture_output=True,env=ENV,cwd=self.lab.repo)
        self.assertNotEqual(result.returncode,0,result.stdout)

if __name__ == "__main__":
    unittest.main()
