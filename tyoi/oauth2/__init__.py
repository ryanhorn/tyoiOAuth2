"""
Implements the application side of OAuth2 for the "authoriztion_code" and
"client_credentials" grant types
"""

from urllib import urlencode

from urllib2 import urlopen, HTTPError, Request

from json import loads

from datetime import datetime, timedelta


class OAuth2Error(Exception):
    pass


class AccessTokenRequestError(OAuth2Error):
    error_code_descriptions = {
        'invalid_request': 'The request is missing a unsupported parameter ' +
                           'or parameter, includes multiple credentials, ' +
                           'utilizes more than one mechanism for ' +
                           'authenticating the client, or is otherwise ' +
                           'malformed.',

        'invalid_client': 'Client authentication failed (e.g. unknown ' +
                          'client, no client credentials included, multiple ' +
                          'client credentials included, or unsupported ' +
                          'credentials type).',

        'invalid_grant': 'The provided authorization grant is invalid, ' +
                         'expired, revoked, or does not match the ' +
                         'redirection URI used in the authorization request.',

        'unauthorized_client': 'The authenticated client is not authorized ' +
                               'to use this authorization grant type.',

        'unsupported_grant_type': 'The authorization grant type is not ' +
                                  'supported by the authorization server.',

        'invalid_scope': 'The requested scope is invalid, unknown, ' +
                         'malformed, or exceeds the previously granted scope.'
    }

    def __init__(self, error_code, error_description=None, error_uri=None):
        """
        If the error code provided is of one in the specified list, an
        additional error_code_description property will be set. Its value will
        be that of the description for the error code as defined in the oauth2
        specification.

            error_code - A single error code. Should be one of the following
              (although this will not be enforced):
                
                invalid_request

                invalid_client

                invalid_grant

                unauthorized_client

                unsupported_grant_type

                invalid_scope
        """
        self.error_code = error_code = str(error_code)
        self.error_code_description = AccessTokenRequestError.error_code_descriptions.get(error_code, 'Unknown error code')
        self.error_description = error_description
        self.error_uri = error_uri

    def __str__(self):
        return '%s: %s' % (self.error_code, self.error_code_description)


class AccessTokenResponseError(OAuth2Error):
    pass


class AccessTokenRequest(object):
    def __init__(self, authenticator, grant, endpoint):
        if not callable(authenticator):
            raise OAuth2Error('authenticator must be callable')

        if not callable(grant):
            raise OAuth2Error('grant must be callable')

        self._authenticator = authenticator
        self._grant = grant
        self._endpoint = endpoint

    def build_url_request(self):
        """
        Consults the authenticator and grant for HTTP request parameters and
        headers to send with the access token request, builds the request using
        the stored endpoint and returns it.
        """
        params = {}
        headers = {}
        self._authenticator(params, headers)
        self._grant(params)
        return Request(self._endpoint, urlencode(params), headers)

    def send(self, response_decoder=None):
        """
        Creates and sends a request to the OAuth server, decodes the response
        and returns the resulting token object.

            response_decoder - A custom callable can be supplied to override
              the default method of extracting AccessToken parameters from the
              response. This is necessary for server implementations which do
              not conform to the more recent OAuth2 specification
              (ex: Facebook). By default, this will assume the response is
              encoded using JSON. The callable should return a dictionary with
              keys and values as follows:

                access_token - The access token

                token_type - The token type

                expires_in - The number of seconds in which the token expires

                refresh_token - The refresh token

                scope - The permission scope (as a space delimited string)
        """
        decoder = loads
        if response_decoder is not None and callable(response_decoder):
            decoder = response_decoder

        request = self.build_url_request()
        try:
            f = urlopen(request)
        except HTTPError as e:
            try:
                error_resp = e.read()
                error_data = loads(error_resp)
            except Exception:
                raise AccessTokenResponseError('Access request returned an error, but the response could not be read: %s ' % error_resp)

            if error_data.get('error') is None:
                raise AccessTokenResponseError('Access request returned an error, but did not include an error code')

            raise AccessTokenRequestError(error_data['error'], error_data.get('error_description'), error_data.get('error_uri'))
        token_data = decoder(f.read())
        return self._create_access_token(token_data)

    def _create_access_token(self, token_data):
        access_token = token_data.get('access_token')

        if access_token is None:
            raise AccessTokenResponseError('No access token returned in response')

        token_type = token_data.get('token_type')
        expires_in = token_data.get('expires_in')

        if expires_in is not None:
            expires_in = datetime.now() + timedelta(seconds=int(expires_in))

        refresh_token = token_data.get('refresh_token')
        scope = token_data.get('scope')

        if scope is not None:
            scope = scope.split(' ')

        return AccessToken(access_token, token_type, expires_in, refresh_token, scope)


class AccessToken(object):
    def __init__(self, access_token, token_type='bearer', expires=None,
                 refresh_token=None, scope=None):
        """
        Sets the provided arguments.

            access_token - The access token

            token_type - The token type

            expires - datetime.datetime object representing when the access
              token expires

            refresh_token - A refresh token that can be used to generate new
              access tokens

            scope - A list of permissions available to the access token
        """
        self.access_token = access_token
        self.token_type = token_type
        self.expires = expires
        self.refresh_token = refresh_token
        self.scope = scope

    def __str__(self):
        """
        Returns a string representation, which in this case is the access token
        string
        """
        return self.access_token
