class UnsupportedGrantTypeError(Exception):
    pass


class Client(object):
    def __init__(self, grant_type):
        if grant_type not in ('authorization_code', 'client_credentials'):
            raise UnsupportedGrantTypeError('Unsupported grant type "%s"' %
                                            grant_type)
