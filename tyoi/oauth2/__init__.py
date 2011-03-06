"""
Implements the application side of OAuth2 for the "authoriztion_code" and
"client_credentials" grant types
"""

from urllib import urlencode

from urllib2 import urlopen

from json import loads


class OAuth2Error(Exception):
    pass


class AccessTokenRequestError(OAuth2Error):
    pass


class UnsupportedGrantTypeError(OAuth2Error):
    pass


class AccessToken(object):
    def __init__(self, access_token, token_type='bearer', expires_in=None,
                 refresh_token=None, scope=None):
        self.access_token = access_token
        self.token_type = token_type
        self.expires_in = expires_in
        self.refresh_token = refresh_token
        self.scope = scope

    def __str__(self):
        return self.access_token


class OAuth2Client(object):
    def __init__(self, client_id, client_secret, grant_type,
                 access_token_endpoint, auth_endpoint=None, redirect_uri=None,
                 scope=None):
        """
        Sets the provided arguments.

            client_id - Required. The client id

            client_secret - Required. The client secret

            grant_type - Required. The grant type. Only "authorization_code"
                         and "client_credentials" are supported

            access_token_endpoint - Required. Base url for requesting an access
                                    token

            auth_endpoint - Required when grant_type is "authorization_code".
                            Base url for redirecting a user for authentication
                            and authorization

            redirect_uri - The uri to redirect the user to after
                           authentication/authorization

            scope - An iterable of requested permissions
        """
        if grant_type not in ('authorization_code', 'client_credentials'):
            raise UnsupportedGrantTypeError('Unsupported grant type "%s"' %
                                            grant_type)

        if 'authorization_code' == grant_type and auth_endpoint is None:
            raise OAuth2Error('auth_endpoint is required with the\
                               authorization_code grant type')

        self._client_id = client_id
        self._client_secret = client_secret
        self._grant_type = grant_type
        self._access_token_endpoint = access_token_endpoint
        self._auth_endpoint = auth_endpoint
        self._redirect_uri = redirect_uri
        self._scope = scope

    def get_auth_uri(self, state=None):
        """
        Returns the uri for user authentication/authorization

            state - The state argument will be passed back when the user is
                    redirected back to the application after authenticating
        """
        if 'client_credentials' == self._grant_type:
            raise OAuth2Error('get_auth_uri can only be used with the\
                              "authorization_code" grant type')

        params = {'response_type': 'code', 'client_id': self._client_id}

        if self._scope is not None:
            params['scope'] = ' '.join(self._scope)

        if state is not None:
            params['state'] = state

        return '%s?%s' % (self._auth_endpoint, urlencode(params))

    def request_access_token(self, code=None, custom_parser=None):
        """
        Builds the access token request url, sends a POST request using
        application/x-www-form-urlencoded encoding. If no custom parser is
        supplied, the response is JSON decoded and used to create an
        AccessToken object.

            code - The access code returned by an authorization request.
              Required for the "authorization_code" grant type. Raises
              tyoi.oauth2.InvalidAccessTokenRequestError if not supplied
              when using the "authorization_code" grant type

            custom_parser - A custom callable can be supplied to override the
              default method of extracting AccessToken parameters from the
              response. This is necessary for oAuth2 implementations which do
              not adhere to the standard (ex: Facebook). The callable should
              return a dictionary with keys and values as follows:

                access_token - The access token

                token_type - The token type

                expires_in - The number of seconds in which the token expires

                refresh_token - The refresh token

                scope - The permission scope (as a space delimited string)
        """
        if 'authorization_code' == self._grant_type and code is None:
            raise AccessTokenRequestError('code is required when using the "authorization_code" grant type')

        def default_parser(resp):
            return loads(resp)

        parser = custom_parser or default_parser

        f = urlopen('%s?%s' % (self._access_token_endpoint,
                               urlencode({'client_id': self._client_id,
                                          'client_secret': self._client_secret,
                                          'grant_type': self._grant_type})),
                               {})
        data = parser(f.read())
        access_token = data.get('access_token')
        token_type = data.get('token_type')
        expires_in = data.get('expires_in')
        refresh_token = data.get('refresh_token')
        scope = data.get('scope')
        return AccessToken(access_token, token_type, expires_in, refresh_token, scope)
