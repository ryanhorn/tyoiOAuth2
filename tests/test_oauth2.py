import unittest

import mox

from tyoi import oauth2
from tyoi.oauth2 import authenticators


class TestOAuth2Client(unittest.TestCase):

    def setUp(self):
        self._mox = mox.Mox()

    def _create_urlopen_mock(self):
        from urllib2 import urlopen
        return self._mox.CreateMock(urlopen)

    def _create_file_mock(self):
        return self._mox.CreateMock(file)

    def test_authenticator_client_credentials(self):
        auth = authenticators.ClientCredentials(id='test_id', secret='test_secret')
        self.assertEquals('test_id', auth._id)
        self.assertEquals('test_secret', auth._secret)
        params = {}
        headers = {}
        auth(params, headers)
        self.assertEquals('test_id', params['client_id'])
        self.assertEquals('test_secret', params['client_secret'])

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

        url_req = oauth2.Request('http://www.example.com?'
                                 'test_grant_param=test_grant_param_value&'
                                 'test_authenticator_param='
                                 'test_authenticator_param_value',
                                 {}, {'test_header': 'test_header_value'})

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

    def test_new_o_auth2_client_bad_grant_type(self):
        self.assertRaises(oauth2.OAuth2Error, oauth2.OAuth2Client,
                          client_id='test', client_secret='test',
                          access_token_endpoint='test',
                          grant_type='bad_grant_type')

    def test_new_o_auth2_client_valid_params(self):
        client = oauth2.OAuth2Client(client_id='test_client_id',
                        client_secret='test_client_secret',
                        access_token_endpoint='test_access_token_endpoint',
                        auth_endpoint='test_auth_endpoint',
                        grant_type='authorization_code',
                        redirect_uri='test_redirect_uri')

        self.assertEquals('test_client_id', client._client_id)
        self.assertEquals('test_client_secret', client._client_secret)
        self.assertEquals('test_access_token_endpoint',
                          client._access_token_endpoint)
        self.assertEquals('test_auth_endpoint', client._auth_endpoint)
        self.assertEquals('authorization_code', client._grant_type)
        self.assertEquals('test_redirect_uri', client._redirect_uri)

    def test_auth_code_without_auth_endpoint(self):
        self.assertRaises(oauth2.OAuth2Error, oauth2.OAuth2Client, client_id='test',
                          client_secret='test', access_token_endpoint='test',
                          grant_type='authorization_code')

    def test_get_auth_uri_client_credentials_grant(self):
        client = oauth2.OAuth2Client(client_id='test', client_secret='test',
                              access_token_endpoint='test',
                              grant_type='client_credentials')

        self.assertRaises(oauth2.OAuth2Error, client.get_auth_uri)

    def test_get_auth_uri(self):
        client = oauth2.OAuth2Client(client_id='test_client_id',
                              client_secret='test_client_secret',
                              access_token_endpoint='test',
                              grant_type='authorization_code',
                              auth_endpoint='http://www.example.com/oauth')

        self.assertEquals(
            'http://www.example.com/oauth?response_type=code&client_id=test_client_id',
            client.get_auth_uri()
        )

    def test_get_auth_uri_with_scope(self):
        client = oauth2.OAuth2Client(client_id='test_client_id',
                              client_secret='test_client_secret',
                              access_token_endpoint='test',
                              grant_type='authorization_code',
                              auth_endpoint='http://www.example.com/oauth')

        self.assertEquals(
            'http://www.example.com/oauth?scope=perm1+perm2+perm3&response_type=code&client_id=test_client_id',
            client.get_auth_uri(scope=['perm1', 'perm2', 'perm3'])
        )

    def test_get_auth_uri_with_redirect_uri(self):
        client = oauth2.OAuth2Client(client_id='test_client_id',
                              client_secret='test_client_secret',
                              access_token_endpoint='test',
                              grant_type='authorization_code',
                              auth_endpoint='http://www.example.com/oauth',
                              redirect_uri='http://www.example.com/')

        self.assertEquals(
            'http://www.example.com/oauth?redirect_uri=http%3A%2F%2Fwww.example.com%2F&response_type=code&client_id=test_client_id',
            client.get_auth_uri()
        )

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

    def test_get_auth_uri_with_state(self):
        client = oauth2.OAuth2Client(client_id='test_client_id',
                              client_secret='test_client_secret',
                              access_token_endpoint='test',
                              grant_type='authorization_code',
                              auth_endpoint='http://www.example.com/oauth')

        self.assertEquals(
            'http://www.example.com/oauth?state=test_state&response_type=code&client_id=test_client_id',
            client.get_auth_uri(state='test_state')
        )

    def test_request_access_token_client_credentials_no_code_no_custom_parser(self):
        client = oauth2.OAuth2Client(client_id='test_client_id',
                              client_secret='test_client_secret',
                              access_token_endpoint='http://www.example.com/access_token',
                              grant_type='client_credentials')

        urlopen_mock = self._create_urlopen_mock()
        resp_mock = self._create_file_mock()

        urlopen_mock('http://www.example.com/access_token?client_secret=test_client_secret&grant_type=client_credentials&client_id=test_client_id',
                     {}).AndReturn(resp_mock)
        resp_mock.read().AndReturn('{"access_token": "test_access_token",\
                                     "token_type": "test_token_type",\
                                     "expires_in": "3600",\
                                     "refresh_token": "test_refresh_token"}')

        # Monkey patch
        tmp = oauth2.urlopen
        oauth2.urlopen = urlopen_mock

        self._mox.ReplayAll()
        token = client.request_access_token()
        self._mox.VerifyAll()

        oauth2.urlopen = tmp

        self.assertEquals('test_access_token', token.access_token)
        self.assertEquals('test_token_type', token.token_type)

        # "expires" will be a datetime object representing the current
        # date/time plus the number of seconds the access token is good for.
        # We need to account for time consumed by the script, so we give 60
        # seconds leeway
        from datetime import datetime, timedelta
        expected = datetime.now() + timedelta(seconds=3600)
        delta = expected - token.expires
        self.assertTrue(0 == delta.days)
        self.assertTrue(60 > delta.seconds)

        self.assertEquals('test_refresh_token', token.refresh_token)

    def test_request_access_token_authorization_code_no_custom_parser(self):
        client = oauth2.OAuth2Client(client_id='test_client_id',
                              client_secret='test_client_secret',
                              access_token_endpoint='http://www.example.com/access_token',
                              grant_type='authorization_code',
                              auth_endpoint='http://www.example.com/auth',
                              redirect_uri='http://www.example.com')

        urlopen_mock = self._create_urlopen_mock()
        resp_mock = self._create_file_mock()

        urlopen_mock('http://www.example.com/access_token?code=test_code&client_secret=test_client_secret&grant_type=authorization_code&client_id=test_client_id&redirect_uri=http%3A%2F%2Fwww.example.com',
                     {}).AndReturn(resp_mock)
        resp_mock.read().AndReturn('{"access_token": "test_access_token",\
                                     "token_type": "test_token_type"}')

        # Monkey patch
        tmp = oauth2.urlopen
        oauth2.urlopen = urlopen_mock

        self._mox.ReplayAll()
        token = client.request_access_token(code='test_code')
        self._mox.VerifyAll()

        oauth2.urlopen = tmp

        self.assertEquals('test_access_token', token.access_token)
        self.assertEquals('test_token_type', token.token_type)

    def test_request_access_token_with_scope(self):
        client = oauth2.OAuth2Client(client_id='test_client_id',
                              client_secret='test_client_secret',
                              access_token_endpoint='http://www.example.com/access_token',
                              grant_type='client_credentials',
                              auth_endpoint='http://www.example.com/auth')

        urlopen_mock = self._create_urlopen_mock()
        resp_mock = self._create_file_mock()

        urlopen_mock('http://www.example.com/access_token?client_secret=test_client_secret&grant_type=client_credentials&client_id=test_client_id&scope=perm1+perm2',
                     {}).AndReturn(resp_mock)
        resp_mock.read().AndReturn('{"access_token": "test_access_token",\
                                     "token_type": "test_token_type"}')

        # Monkey patch
        tmp = oauth2.urlopen
        oauth2.urlopen = urlopen_mock

        self._mox.ReplayAll()
        token = client.request_access_token(scope=['perm1', 'perm2'])
        self._mox.VerifyAll()

        oauth2.urlopen = tmp

    def test_request_access_token_authorization_code_no_code(self):
        client = oauth2.OAuth2Client(client_id='test_client_id',
                              client_secret='test_client_secret',
                              access_token_endpoint='http://www.example.com/access_token',
                              auth_endpoint='http://www.example.com/auth',
                              grant_type='authorization_code')

        self.assertRaises(oauth2.OAuth2Error, client.request_access_token)

    def test_request_access_token_authorization_code_no_redirect_uri(self):
        client = oauth2.OAuth2Client(client_id='test_client_id',
                              client_secret='test_client_secret',
                              access_token_endpoint='http://www.example.com/access_token',
                              auth_endpoint='http://www.example.com/auth',
                              grant_type='authorization_code')

        self.assertRaises(oauth2.OAuth2Error, client.request_access_token, 'test_code')

    def test_request_access_token_custom_parser(self):
        def parse_query_string_response(query):
            return dict([pair.split('=') for pair in query.split('&')])

        client = oauth2.OAuth2Client(client_id='test_client_id',
                              client_secret='test_client_secret',
                              access_token_endpoint='http://www.example.com/access_token',
                              grant_type='client_credentials')

        urlopen_mock = self._create_urlopen_mock()
        resp_mock = self._create_file_mock()

        urlopen_mock('http://www.example.com/access_token?client_secret=test_client_secret&grant_type=client_credentials&client_id=test_client_id',
                     {}).AndReturn(resp_mock)
        resp_mock.read().AndReturn('access_token=test_access_token&token_type=test_token_type&refresh_token=test_refresh_token')

        # Monkey patch
        tmp = oauth2.urlopen
        oauth2.urlopen = urlopen_mock

        self._mox.ReplayAll()
        token = client.request_access_token(custom_parser=parse_query_string_response)
        self._mox.VerifyAll()

        oauth2.urlopen = tmp

        self.assertEquals('test_access_token', token.access_token)
        self.assertEquals('test_token_type', token.token_type)
        self.assertEquals('test_refresh_token', token.refresh_token)

    def test_request_access_token_no_token_in_response(self):
        client = oauth2.OAuth2Client(client_id='test_client_id',
                              client_secret='test_client_secret',
                              access_token_endpoint='http://www.example.com/access_token',
                              grant_type='client_credentials')

        urlopen_mock = self._create_urlopen_mock()
        resp_mock = self._create_file_mock()

        urlopen_mock('http://www.example.com/access_token?client_secret=test_client_secret&grant_type=client_credentials&client_id=test_client_id',
                     {}).AndReturn(resp_mock)
        resp_mock.read().AndReturn('{"not_access_token": "value"}')

        # Monkey patch
        tmp = oauth2.urlopen
        oauth2.urlopen = urlopen_mock

        self._mox.ReplayAll()
        self.assertRaises(oauth2.AccessTokenResponseError, client.request_access_token)
        self._mox.VerifyAll()

        oauth2.urlopen = tmp

    def test_request_access_token_error_response(self):
        from urllib2 import HTTPError

        client = oauth2.OAuth2Client(client_id='test_client_id',
                                     client_secret='test_client_secret',
                                     access_token_endpoint='http://www.example.com/access_token',
                                     grant_type='client_credentials')

        urlopen_mock = self._create_urlopen_mock()

        # HTTPError.read cannot be directly mocked, so we need to stub it in
        def read(self):
            return '{"error": "invalid_request", "error_description": "error description", "error_uri": "http://www.example.com/error"}'

        HTTPError.read = read
        http_error = HTTPError('http://www.example.com/access_token?client_secret=test_client_secret&grant_type=client_credentials&client_id=test_client_id', 400, 'Bad Request', {}, None)

        urlopen_mock('http://www.example.com/access_token?client_secret=test_client_secret&grant_type=client_credentials&client_id=test_client_id',
                     {}).AndRaise(http_error)

        # Monkey patch
        tmp = oauth2.urlopen
        oauth2.urlopen = urlopen_mock

        self._mox.ReplayAll()
        try:
            client.request_access_token()
        except oauth2.AccessTokenRequestError as e:
            self.assertEquals('invalid_request', e.error_code)
            self.assertEquals('error description', e.error_description)
            self.assertEquals('http://www.example.com/error', e.error_uri)
        except Exception as ex:
            self.fail('Expected exception oauth2.AccessTokenRequestError not raised. Got error %s' % ex)
        finally:
            self._mox.VerifyAll()
            oauth2.urlopen = tmp
            del HTTPError.read

    def test_refresh_access_token_with_default_parser_and_scope(self):
        client = oauth2.OAuth2Client(client_id='test_client_id',
                              client_secret='test_client_secret',
                              access_token_endpoint='http://www.example.com/access_token',
                              grant_type='client_credentials')

        token = oauth2.AccessToken(access_token="test_access_token",
                                   refresh_token="test_refresh_token",
                                   scope=['perm1', 'perm2'])

        urlopen_mock = self._create_urlopen_mock()
        resp_mock = self._create_file_mock()

        urlopen_mock('http://www.example.com/access_token?client_secret=test_client_secret&grant_type=refresh_token&refresh_token=test_refresh_token&client_id=test_client_id&scope=perm1+perm2',
                     {}).AndReturn(resp_mock)
        resp_mock.read().AndReturn('{"access_token": "test_refreshed_access_token","scope": "perm1 perm2"}')

        # Monkey patch
        tmp = oauth2.urlopen
        oauth2.urlopen = urlopen_mock

        self._mox.ReplayAll()
        new_token = client.refresh_access_token(token)
        self._mox.VerifyAll()

        oauth2.urlopen = tmp

        self.assertEquals("test_refreshed_access_token", new_token.access_token)
        self.assertEquals(["perm1", "perm2"], new_token.scope)

    def test_refresh_access_token_no_refresh_token(self):
        client = oauth2.OAuth2Client(client_id='test_client_id',
                              client_secret='test_client_secret',
                              access_token_endpoint='http://www.example.com/access_token',
                              grant_type='client_credentials')

        token = oauth2.AccessToken(access_token="test_access_token")

        self.assertRaises(oauth2.OAuth2Error, client.refresh_access_token, token)

    def test_refresh_access_token_no_token_in_response(self):
        client = oauth2.OAuth2Client(client_id='test_client_id',
                              client_secret='test_client_secret',
                              access_token_endpoint='http://www.example.com/access_token',
                              grant_type='client_credentials')

        token = oauth2.AccessToken(access_token="test_access_token", refresh_token="test_refresh_token")

        urlopen_mock = self._create_urlopen_mock()
        resp_mock = self._create_file_mock()

        urlopen_mock('http://www.example.com/access_token?client_secret=test_client_secret&grant_type=refresh_token&refresh_token=test_refresh_token&client_id=test_client_id',
                     {}).AndReturn(resp_mock)
        resp_mock.read().AndReturn('{"not_access_token": "value"}')

        # Monkey patch
        tmp = oauth2.urlopen
        oauth2.urlopen = urlopen_mock

        self._mox.ReplayAll()
        self.assertRaises(oauth2.AccessTokenResponseError, client.refresh_access_token, token)
        self._mox.VerifyAll()

        oauth2.urlopen = tmp

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
