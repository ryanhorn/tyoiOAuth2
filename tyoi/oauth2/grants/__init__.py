"""
Contains grants representing possible OAuth2 grant types
"""

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
