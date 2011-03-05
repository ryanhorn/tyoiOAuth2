import unittest
import mox

from tyoi.oauth2 import Client, UnsupportedGrantTypeError


class TestClient(unittest.TestCase):

    def setUp(self):
        self._mox = mox.Mox()

    def testNewClientBadGrantType(self):
        self.assertRaises(UnsupportedGrantTypeError, Client,
                          grant_type='bad_grant_type')
