import unittest
import mox

from tyoi.oauth2 import OAuth2Client, UnsupportedGrantTypeError


class TestOAuth2Client(unittest.TestCase):

    def setUp(self):
        self._mox = mox.Mox()

    def testNewOAuth2ClientBadGrantType(self):
        self.assertRaises(UnsupportedGrantTypeError, OAuth2Client, client_id='test',
                          client_secret='test', access_token_endpoint='test',
                          auth_endpoint='test', grant_type='bad_grant_type')

    def testNewOAuth2ClientValidParams(self):
        client = OAuth2Client(client_id='test_client_id',
                        client_secret='test_client_secret',
                        access_token_endpoint='test_access_token_endpoint',
                        auth_endpoint='test_auth_endpoint',
                        grant_type='authorization_code',
                        redirect_uri='test_redirect_uri',
                        scope=['test_scope_1', 'test_scope_2'])

        self.assertEquals('test_client_id', client._client_id)
        self.assertEquals('test_client_secret', client._client_secret)
        self.assertEquals('test_access_token_endpoint', client._access_token_endpoint)
        self.assertEquals('test_auth_endpoint', client._auth_endpoint)
        self.assertEquals('authorization_code', client._grant_type)
        self.assertEquals('test_redirect_uri', client._redirect_uri)
        self.assertEquals(['test_scope_1', 'test_scope_2'], client._scope)
