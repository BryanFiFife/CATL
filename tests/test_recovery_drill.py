import sys
import unittest
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'tools'))
from recovery_drill import drill

@unittest.skipUnless(sys.platform=='linux','anchored recovery drill targeted at Linux')
class RecoveryDrill(unittest.TestCase):
    def test_database_rollback_is_detected(self):
        result=drill()
        self.assertTrue(result['passed'])
        self.assertTrue(result['restored_database_rejected'])
        self.assertGreater(result['advanced_count'],result['initial_count'])
