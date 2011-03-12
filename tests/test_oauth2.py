import unittest

import mox

from tyoi import oauth2
from tyoi.oauth2 import authenticators, grants


class TestTokenRequest(unittest.TestCase):

    def setUp(self):
        self._mox = mox.Mox()

    def _create_urlopen_mock(self):
        from urllib2 import urlopen
        return self._mox.CreateMock(urlopen)

    def _create_file_mock(self):
        return self._mox.CreateMock(file)

    def test_new_access_token_request(self):
        def test_callable():
            pass
        req = oauth2.AccessTokenRequest(authenticator=test_callable,
                                        grant=test_callable,
                                        endpoint='test_endpoint')

        self.assertEquals(test_callable, req._authenticator)
        self.assertEquals(test_callable, req._grant)
        self.assertEquals('test_endpoint', req._endpoint)

    def test_new_access_token_request_bad_params(self):
        def test_callable():
            pass
        self.assertRaises(oauth2.OAuth2Error, oauth2.AccessTokenRequest, 'not a callable', test_callable, 'test_endpoint')
        self.assertRaises(oauth2.OAuth2Error, oauth2.AccessTokenRequest, test_callable, 'not a callable', 'test_endpoint')

    def test_build_url_request(self):
        def authenticator(parameters, headers):
            parameters['test_authenticator_param'] = 'test_authenticator_param_value'
            headers['test_header'] = 'test_header_value'

        def grant(parameters):
            parameters['test_grant_param'] = 'test_grant_param_value'

        req = oauth2.AccessTokenRequest(authenticator=authenticator,
                                        grant=grant,
                                        endpoint='http://www.example.com')

        self._mox.StubOutClassWithMocks(oauth2, 'Request')

        url_req = oauth2.Request('http://www.example.com',
                                 'test_grant_param=test_grant_param_value&test_authenticator_param=test_authenticator_param_value',
                                 {'test_header': 'test_header_value'})

        self._mox.ReplayAll()
        result = req.build_url_request()
        self._mox.VerifyAll()
        self._mox.UnsetStubs()

    def test_send_default_response_decoder(self):
        def test_callable():
            pass
        req = oauth2.AccessTokenRequest(authenticator=test_callable,
                                        grant=test_callable,
                                        endpoint='test_endpoint')

        self._mox.StubOutWithMock(req, 'build_url_request')
        self._mox.StubOutWithMock(oauth2, 'urlopen')

        resp_mock = self._create_file_mock()

        req.build_url_request().AndReturn('test return value')
        oauth2.urlopen('test return value').AndReturn(resp_mock)
        resp_mock.read().AndReturn('{"access_token": "test_access_token",\
                                     "token_type": "test_token_type",\
                                     "expires_in": "3600",\
                                     "refresh_token": "test_refresh_token"}')

        self._mox.ReplayAll()
        token = req.send()
        self._mox.VerifyAll()

        self.assertEquals('test_access_token', token.access_token)
        self.assertEquals('test_token_type', token.token_type)
        self.assertEquals('test_refresh_token', token.refresh_token)

        # "expires" will be a datetime object representing the current
        # date/time plus the number of seconds the access token is good for.
        # We need to account for time consumed by the script, so we give 60
        # seconds leeway
        from datetime import datetime, timedelta
        expected = datetime.now() + timedelta(seconds=3600)
        delta = expected - token.expires
        self.assertTrue(0 == delta.days)
        self.assertTrue(60 > delta.seconds)

        self._mox.UnsetStubs()

    def test_send_custom_decoder(self):
        def test_callable():
            pass

        def decode_form_encoded(query):
            return dict([pair.split('=') for pair in query.split('&')])

        req = oauth2.AccessTokenRequest(authenticator=test_callable,
                                        grant=test_callable,
                                        endpoint='test_endpoint')

        self._mox.StubOutWithMock(req, 'build_url_request')
        self._mox.StubOutWithMock(oauth2, 'urlopen')

        resp_mock = self._create_file_mock()

        req.build_url_request().AndReturn('test return value')
        oauth2.urlopen('test return value').AndReturn(resp_mock)
        resp_mock.read().AndReturn('access_token=test_access_token&token_type=test_token_type&refresh_token=test_refresh_token')

        self._mox.ReplayAll()
        token = req.send(response_decoder=decode_form_encoded)
        self._mox.VerifyAll()

        self.assertEquals('test_access_token', token.access_token)
        self.assertEquals('test_token_type', token.token_type)
        self.assertEquals('test_refresh_token', token.refresh_token)

        self._mox.UnsetStubs()

    def test_send_error_response(self):
        from urllib2 import HTTPError

        def test_callable():
            pass

        req = oauth2.AccessTokenRequest(authenticator=test_callable,
                                        grant=test_callable,
                                        endpoint='test_endpoint')

        self._mox.StubOutWithMock(req, 'build_url_request')
        self._mox.StubOutWithMock(oauth2, 'urlopen')

        # HTTPError.read cannot be directly mocked, so we need to stub it in
        def read(self):
            return '{"error": "invalid_request", "error_description": "error description", "error_uri": "http://www.example.com/error"}'

        HTTPError.read = read
        http_error = HTTPError('test return value', 400, 'Bad Request', {}, None)

        req.build_url_request().AndReturn('test return value')
        oauth2.urlopen('test return value').AndRaise(http_error)

        self._mox.ReplayAll()
        try:
            req.send()
        except oauth2.AccessTokenRequestError as e:
            self.assertEquals('invalid_request', e.error_code)
            self.assertEquals('error description', e.error_description)
            self.assertEquals('http://www.example.com/error', e.error_uri)
        except Exception as ex:
            self.fail('Expected exception oauth2.AccessTokenRequestError not raised. Got error %s' % ex)
        finally:
            self._mox.VerifyAll()
            self._mox.UnsetStubs()
            del HTTPError.read


class TestAccessToken(unittest.TestCase):

    def test_access_token(self):
        from datetime import datetime
        expires = datetime.now()
        token = oauth2.AccessToken(access_token='test_access_token',
                            token_type='bearer', expires=expires,
                            refresh_token='test_refresh_token',
                            scope=['perm1', 'perm2', 'perm3'])
        self.assertEquals('test_access_token', token.access_token)
        self.assertEquals('bearer', token.token_type)
        self.assertEquals(expires, token.expires)
        self.assertEquals('test_refresh_token', token.refresh_token)
        self.assertEquals(['perm1', 'perm2', 'perm3'], token.scope)
        self.assertEquals('test_access_token', str(token))

    def test_access_token_error_all_error_codes(self):
        error = oauth2.AccessTokenRequestError(error_code='invalid_request')
        self.assertEquals('invalid_request', error.error_code)
        self.assertEquals('The request is missing a unsupported parameter or parameter, includes multiple credentials, utilizes more than one mechanism for authenticating the client, or is otherwise malformed.', error.error_code_description)

        error = oauth2.AccessTokenRequestError(error_code='invalid_client')
        self.assertEquals('invalid_client', error.error_code)
        self.assertEquals('Client authentication failed (e.g. unknown client, no client credentials included, multiple client credentials included, or unsupported credentials type).', error.error_code_description)

        error = oauth2.AccessTokenRequestError(error_code='invalid_grant')
        self.assertEquals('invalid_grant', error.error_code)
        self.assertEquals('The provided authorization grant is invalid, expired, revoked, or does not match the redirection URI used in the authorization request.', error.error_code_description)

        error = oauth2.AccessTokenRequestError(error_code='unauthorized_client')
        self.assertEquals('unauthorized_client', error.error_code)
        self.assertEquals('The authenticated client is not authorized to use this authorization grant type.', error.error_code_description)

        error = oauth2.AccessTokenRequestError(error_code='unsupported_grant_type')
        self.assertEquals('unsupported_grant_type', error.error_code)
        self.assertEquals('The authorization grant type is not supported by the authorization server.', error.error_code_description)

        error = oauth2.AccessTokenRequestError(error_code='invalid_scope')
        self.assertEquals('invalid_scope', error.error_code)
        self.assertEquals('The requested scope is invalid, unknown, malformed, or exceeds the previously granted scope.', error.error_code_description)

        error = oauth2.AccessTokenRequestError(error_code='unknown_code')
        self.assertEquals('unknown_code', error.error_code)
        self.assertEquals('Unknown error code', error.error_code_description)

    def test_access_token_error_to_string(self):
        error = oauth2.AccessTokenRequestError(error_code='invalid_scope')
        expected = 'invalid_scope: The requested scope is invalid, unknown, '\
                   'malformed, or exceeds the previously granted scope.'
        self.assertEquals(expected, str(error))

    def test_access_token_request_optional_params(self):
        error = oauth2.AccessTokenRequestError(error_code='unknown', error_description='Bad request', error_uri='http://www.example.com/errors/bad_request')
        self.assertEquals('Bad request', error.error_description)
        self.assertEquals('http://www.example.com/errors/bad_request', error.error_uri)

class TestOAuth2GrantTypes(unittest.TestCase):
    def test_new_authorization_code(self):
        grant = grants.AuthorizationCode(code='test_code', redirect_uri='test_redirect_uri')
        self.assertEquals('test_code', grant._code)
        self.assertEquals('test_redirect_uri', grant._redirect_uri)

    def test_call_authorization_code(self):
        grant = grants.AuthorizationCode(code='test_code', redirect_uri='test_redirect_uri')
        params = {}
        grant(params)
        self.assertEquals('test_code', params['code'])
        self.assertEquals('test_redirect_uri', params['redirect_uri'])
        self.assertEquals('authorization_code', params['grant_type'])

    def test_authorization_code_build_auth_uri_required_params(self):
        uri = grants.AuthorizationCode.build_auth_uri('http://www.example.com', 'test_client_id')
        self.assertEquals('http://www.example.com?response_type=code&client_id=test_client_id', uri)

    def test_authorization_code_buid_auth_uri_optional_params(self):
        uri = grants.AuthorizationCode.build_auth_uri(
            'http://www.example.com', 'test_client_id',
            'http://www.example.com/redirect', ['perm1', 'perm2', 'perm3'],
            'test_state')

        self.assertEquals('http://www.example.com?scope=perm1+perm2+perm3&state=test_state&redirect_uri=http%3A%2F%2Fwww.example.com%2Fredirect&response_type=code&client_id=test_client_id', uri)

    def test_new_client_credentials(self):
        grant = grants.ClientCredentials()
        self.assertEquals(grant._scope, None)

    def test_new_client_credentials_with_scope(self):
        grant = grants.ClientCredentials(scope=('perm1', 'perm2'))
        self.assertEquals(grant._scope, ('perm1', 'perm2'))

    def test_call_client_credentials(self):
        grant = grants.ClientCredentials()
        params = {}
        grant(params)
        self.assertEquals('client_credentials', params['grant_type'])

    def test_call_client_credentials_with_scope(self):
        grant = grants.ClientCredentials(scope=('perm1', 'perm2'))
        params = {}
        grant(params)
        self.assertEquals('client_credentials', params['grant_type'])
        self.assertEquals('perm1 perm2', params['scope'])

    def test_new_refresh_token(self):
        grant = grants.RefreshToken('test_refresh_token')
        self.assertEquals('test_refresh_token', grant._refresh_token)
        self.assertEquals(None, grant._scope)

    def test_call_refresh_token(self):
        grant = grants.RefreshToken('test_refresh_token')
        params = {}
        grant(params)
        self.assertEquals('test_refresh_token', params['refresh_token'])
        self.assertEquals('refresh_token', params['grant_type'])

    def test_call_refresh_token_with_scope(self):
        grant = grants.RefreshToken('test_refresh_token', scope=('perm1', 'perm2'))
        params = {}
        grant(params)
        self.assertEquals('test_refresh_token', params['refresh_token'])
        self.assertEquals('refresh_token', params['grant_type'])
        self.assertEquals('perm1 perm2', params['scope'])

class TestOAuth2Authenticators(unittest.TestCase):

    def test_authenticator_client_credentials(self):
        auth = authenticators.ClientPassword(id='test_id', secret='test_secret')
        self.assertEquals('test_id', auth._id)
        self.assertEquals('test_secret', auth._secret)
        params = {}
        headers = {}
        auth(params, headers)
        self.assertEquals('test_id', params['client_id'])
        self.assertEquals('test_secret', params['client_secret'])
