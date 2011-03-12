Overview
========
This module provides a set of components, which together serve as an OAuth2 
"Client" capable of issuing access token requests to an OAuth2 "Authorization 
Server" on behalf of a "Resource Owner" (see 
http://tools.ietf.org/html/draft-ietf-oauth-v2-12#section-1.1 for the various 
role definitions). It is designed for flexibility and extensibility by 
decoupling the different parts of an access token request.

The module is covered by unit tests and has been tested in real world scenarios 
using OAuth2 server implementations provided by Facebook, Google and 
Foursquare. See the Real World Examples section for details.

As the OAuth2 specification is still a moving target, the module is subject to 
change. In addition, any real world examples provided are likely to break when 
the server implementations introduce backwards incompatible changes.

Usage
==========

Access tokens are requested using an AccessTokenRequest object, which takes an 
"authenticator", "grant" and request endpoint. Authenticators and grants are 
callables which are given a chance to modify the request parameters and headers 
prior to the request being sent to the authorization server. The module 
provides authenticators and grants which cover most of the authentication 
methods and grant types defined by the current specification.

Example:

    from tyoi.oauth2 import AccessTokenRequest
    from tyoi.oauth2.grants import ClientCredentials
    from tyoi.oauth2.authenticators import ClientPassword

    authenticator = ClientPassword('my_client_id', 'my_client_secret')
    grant = ClientCredentials()
    request = AccessTokenRequest(authenticator, grant,
                                 'http://www.example.com')
    token = request.send()

The return value of send is an AccessToken object, which has the following 
properties:

* access_token - The access token string
* token_type - The access token type
* expires - A datetime.datetime object representing when the access token 
* expires
* refresh_token - A refresh token that can be used to generate new access 
* tokens
* scope - A list of permissions available to the access token

Authenticators
--------------
Authenticators represent the different authentication methods for making an 
access token request. An authenticator must be a callable that takes two 
arguments: a dictionary of request parameters and a dictionary of headers to 
send with the access token request. The authenticator will be called by the 
AccessTokenRequest object prior to making a request and must add any required 
request parameters and/or headers.

### Provided Authenticators

#### tyoi.oauth2.authenticators.ClientPassword
Implements Client Password authentication (see 
http://tools.ietf.org/html/draft-ietf-oauth-v2-12#section-2.1)

Instantiate with the following arguments:

* id: The client id
* secret: The client secret
  

Grants
------
Grants represent the different grant types that can be exchanged for an access 
token. A grant must be a callable that takes a single argument: a dictionary of 
request parameters. Just like an authenticator, a grant will be called by the 
AccessTokenRequest object prior to making a request and must add any required 
request parameters.

### Provided Grants

#### tyoi.oauth2.grants.AuthorizationCode
Implements the Authorization Code grant type (see 
http://tools.ietf.org/html/draft-ietf-oauth-v2-12#section-4.1)

Instantiate with the following arguments:

* code: The authorization code returned by an authorization server
* redirect_uri: The redirect uri sent in the original authorization request

Also contains a static helper method "build_auth_uri" which builds the uri that 
a user must be redirected to for authentication/authorization. It takes the 
following arguments:

* endpoint: The authorization endpoint
* client_id: The client id
* redirect_uri (optional): The redirect uri
* scope (optional): A list of permissions to request
* state (optional): An application state that will be sent back by the 
* authorization server
  

#### tyoi.oauth2.grants.ClientCredentials
Implements the Client Credentials grant type (see 
http://tools.ietf.org/html/draft-ietf-oauth-v2-12#section-4.4)

Instantiate with the following arguments:

* scope (optional): A list of permissions to request  
  

#### tyoi.oauth2.grants.RefreshToken
Implements the Refresh Token grant type (see 
http://tools.ietf.org/html/draft-ietf-oauth-v2-12#section-6)

Instantiate with the following arguments:

* refresh_token: The refresh token issued with an access token request
* scope (optional): A list of permissions to request

Custom Response Decoder
=======================
The current specification states that the access token response body will be 
serialized into a JSON structure. Due to some server implementations not being 
up to date with the spec (such as Facebook), a custom callable can be supplied 
to AccessTokenRequest.send. This will override the default method of extracting 
access token parameters. The callable will be passed the response body and must 
return a dictionary with the following keys and values:

* access_token - The access token
* token_type - The token type
* expires_in - The number of seconds in which the token expires
* refresh_token - The refresh token
* scope - The permission scope (as a space delimited string)

Example for when an response body is encoded using 
application/x-www-form-urlencoded:

    from urlparse import parse_qs

    ...

    def response_decoder(body):
        params = {}
        for k, v in parse_qs(body).iteritems():
            if len(v) > 1:
                params[k] = v
            else:
                params[k] = v[0]
        return params

    request.send(response_decoder)

Handling Errors
===================================================================
If the server responds to an access token request with an error code, the 
request object will attempt to parse the response body as per 
http://tools.ietf.org/html/draft-ietf-oauth-v2-12#section-5.2. If the body 
*can* be parsed, an AccessTokenRequestError will be raised. This object will 
contain the following properties:

* error_code - The error code
* error_code_description - The error code description as listed in the 
                           specification or "Unknown code".
* error_description - The error description (or None if no error description 
                      was returned)
* error_uri - The uri to a web page with more information on the error (or None 
              if no error uri was returned)

If the body *cannot* be parsed, an AccessTokenResponseError will be raised with 
the string included in the body.

An AccessTokenResponseError will also be raised in the following situations:

* If the body can be parsed but no code is provided.
* If the request is successful, but no access token is returned

Real World Examples
===================

Facebook using the authorization_code grant type
------------------------------------------------

    from tyoi.oauth2 import AccessTokenRequest
    from tyoi.oauth2.grants import AuthorizationCode
    from tyoi.oauth2.authenticators import ClientPassword

    from urlparse import parse_qs

    CLIENT_ID = 'FB_CLIENT_ID'
    CLIENT_SECRET = 'FB_CLIENT_SECRET'
    ACCESS_TOKEN_ENDPOINT = 'https://graph.facebook.com/oauth/access_token'
    AUTH_ENDPOINT = 'https://www.facebook.com/dialog/oauth'
    REDIRECT_URI = 'http://www.yourapp.com/redirect'

    # Assumes query_params contains a dictionary of query params sent to the
    # application via GET

    if 'code' not in query_params:
        auth_uri = AuthorizationCode.build_auth_uri(AUTH_ENDPOINT, CLIENT_ID,
                                                    REDIRECT_URI)
        # Redirect to auth_uri
        ...

    grant = AuthorizationCode(query_params['code'], REDIRECT_URI)
    authenticator = ClientPassword(CLIENT_ID, CLIENT_SECRET)
    request = AccessTokenRequest(authenticator, grant, ACCESS_TOKEN_ENDPOINT)

    # As of this writing, Facebook sends a response using
    # application/x-www-form-urlencoded encoding, so we need a custom decoder
    def response_decoder(body):
        params = {}
        for k, v in parse_qs(body).iteritems():
            if len(v) > 1:
                params[k] = v
            else:
                params[k] = v[0]
        return params

    token = request.send(response_decoder)

    token.access_token
    token.token_type
    token.expires
    token.refresh_token
    token.scope

Facebook using the client_credentials grant type
------------------------------------------------

This is useful for performing application administrative actions such as 
working with test users.

    from tyoi.oauth2 import AccessTokenRequest
    from tyoi.oauth2.grants import ClientCredentials
    from tyoi.oauth2.authenticators import ClientPassword

    from urlparse import parse_qs

    CLIENT_ID = 'FB_CLIENT_ID'
    CLIENT_SECRET = 'FB_CLIENT_SECRET'
    ACCESS_TOKEN_ENDPOINT = 'https://graph.facebook.com/oauth/access_token'

    # Assumes query_params contains a dictionary of query params sent to the
    # application via GET

    grant = ClientCredentials()
    authenticator = ClientCredentials(CLIENT_ID, CLIENT_SECRET)
    request = AccessTokenRequest(authenticator, grant, ACCESS_TOKEN_ENDPOINT)

    # As of this writing, Facebook sends a response using
    # application/x-www-form-urlencoded encoding, so we need a custom decoder
    def response_decoder(body):
        params = {}
        for k, v in parse_qs(body).iteritems():
            if len(v) > 1:
                params[k] = v
            else:
                params[k] = v[0]
        return params

    token = request.send(response_decoder)

    token.access_token
    token.token_type
    token.expires
    token.refresh_token
    token.scope


Google using the authorization_code and refresh_token grant types
------------------------------------------------

    from tyoi.oauth2 import AccessTokenRequest
    from tyoi.oauth2.grants import AuthorizationCode, RefreshToken
    from tyoi.oauth2.authenticators import ClientPassword

    CLIENT_ID = 'GOOGLE_CLIENT_ID'
    CLIENT_SECRET = 'GOOGLE_CLIENT_SECRET'
    ACCESS_TOKEN_ENDPOINT = 'https://accounts.google.com/o/oauth2/token'
    AUTH_ENDPOINT = 'https://accounts.google.com/o/oauth2/auth'
    REDIRECT_URI = 'http://www.yourapp.com/redirect'
    # Google requires that you specify a scope
    SCOPE = ['https://www.google.com/m8/feeds/']

    # Assumes query_params contains a dictionary of query params sent to the
    # application via GET

    if 'code' not in query_params:
        auth_uri = AuthorizationCode.build_auth_uri(AUTH_ENDPOINT, CLIENT_ID,
                                                    REDIRECT_URI, SCOPE)
        # Redirect to auth_uri
        ...

    grant = AuthorizationCode(query_params['code'], REDIRECT_URI)
    authenticator = ClientPassword(CLIENT_ID, CLIENT_SECRET)
    request = AccessTokenRequest(authenticator, grant, ACCESS_TOKEN_ENDPOINT)

    token = request.send()

    token.access_token
    token.token_type
    token.expires
    token.refresh_token
    token.scope

    # Refresh Token
    grant = RefreshToken(token.refresh_token)
    request = AccessTokenRequest(authenticator, grant, ACCESS_TOKEN_ENDPOINT)

    refresh_token = request.send()

    refresh_token.access_token
    refresh_token.token_type
    refresh_token.expires
    refresh_token.refresh_token
    refresh_token.scope


Foursquare using the authorization_code grant type
--------------------------------------------------
    from tyoi.oauth2 import AccessTokenRequest
    from tyoi.oauth2.grants import AuthorizationCode
    from tyoi.oauth2.authenticators import ClientPassword

    CLIENT_ID = 'FOURSQUARE_CLIENT_ID'
    CLIENT_SECRET = 'FOURSQUARE_CLIENT_SECRET'
    ACCESS_TOKEN_ENDPOINT = 'https://foursquare.com/oauth2/access_token'
    AUTH_ENDPOINT = 'https://foursquare.com/oauth2/authorize'
    REDIRECT_URI = 'http://www.yourapp.com/redirect'

    # Assumes query_params contains a dictionary of query params sent to the
    # application via GET

    if 'code' not in query_params:
        auth_uri = AuthorizationCode.build_auth_uri(AUTH_ENDPOINT, CLIENT_ID,
                                                    REDIRECT_URI, SCOPE)
        # Redirect to auth_uri
        ...

    grant = AuthorizationCode(query_params['code'], REDIRECT_URI)
    authenticator = ClientPassword(CLIENT_ID, CLIENT_SECRET)
    request = AccessTokenRequest(authenticator, grant, ACCESS_TOKEN_ENDPOINT)

    token = request.send()

    token.access_token
    token.token_type
    token.expires
    token.refresh_token
    token.scope
