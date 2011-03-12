"""
Contains authenticators representing possible OAuth2 authentication methods
"""

class ClientPassword(object):
    """
    Callable which adds the appropriate parameters for requesting an access
    token using the standard client password authentication method
    """
    def __init__(self, id, secret):
        self._id = id
        self._secret = secret

    def __call__(self, parameters, headers):
        parameters['client_id'] = self._id
        parameters['client_secret'] = self._secret
