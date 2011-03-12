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
