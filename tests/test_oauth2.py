import sys
sys.path.append('../tyoi')

import unittest
import mox

class TestClient(unittest.TestCase):

    def setUp(self):
        self._mox = mox.Mox()
