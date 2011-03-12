"""
Contains grants representing possible OAuth2 grant types
"""
from urllib import urlencode

class AuthorizationCode(object):
    """
    Callable which adds the appropriate parameters for requesting an access
    token using the authorization_code grant type
    """
    def __init__(self, code, redirect_uri):
        self._code = code
        self._redirect_uri = redirect_uri

    def __call__(self, parameters):
        parameters['code'] = self._code
        parameters['redirect_uri'] = self._redirect_uri
        parameters['grant_type'] = 'authorization_code'

    @staticmethod
    def build_auth_uri(endpoint, client_id, redirect_uri=None, scope=None, state=None):
        """
        Helper method builds the uri that a user must be redirected to for
        authentication/authorization using the authorization_code grant type.

            endpoint - The authorization endpoint

            client_id - The client id

            redirect_uri - The redirect uri

            scope - A list of permissions to request

            state - An application state that will be sent back by the
              authorization server
        """
        params = {'response_type': 'code', 'client_id': client_id}
        if redirect_uri is not None:
            params['redirect_uri'] = redirect_uri

        if scope is not None:
            params['scope'] = ' '.join(scope)

        if state is not None:
            params['state'] = state

        return '%s?%s' % (endpoint, urlencode(params))

class ClientCredentials(object):
    """
    Callable which adds the appropriate parameters for requesting an access
    token using the client_credentials grant type
    """
    def __init__(self, scope=None):
        self._scope = scope

    def __call__(self, parameters):
        parameters['grant_type'] = 'client_credentials'
        if self._scope is not None:
            parameters['scope'] = ' '.join(self._scope)

class RefreshToken(object):
    """
    Callable which adds the appropriate parameters for requesting an access
    token using the refresh_token grant type
    """
    def __init__(self, refresh_token, scope=None):
        self._refresh_token = refresh_token
        self._scope = scope

    def __call__(self, parameters):
        parameters['grant_type'] = 'refresh_token'
        parameters['refresh_token'] = self._refresh_token
        if self._scope is not None:
            parameters['scope'] = ' '.join(self._scope)
