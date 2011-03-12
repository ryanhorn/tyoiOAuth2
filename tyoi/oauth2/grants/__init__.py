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
