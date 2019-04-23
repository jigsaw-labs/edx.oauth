"""
Auth0 implementation based on:
https://manage.auth0.com/dashboard/us/jigsawlabs/applications/Z9MehfTgspn1HOeoWzu0RO5UvhS5i9EZ/quickstart

"""
from urllib2 import urlopen
from jose import jwt
from social_core.backends.oauth import BaseOAuth2


class Auth0(BaseOAuth2):
    """Auth0 OAuth authentication backend"""
    name = 'auth0'
    SCOPE_SEPARATOR = ' '
    ACCESS_TOKEN_METHOD = 'POST'
    EXTRA_DATA = [
        ('picture', 'picture')
    ]
    BASE_URL = 'https://jigsawlabs.auth0.com'
    AUTHORIZATION_URL = BASE_URL + '/oauth/authorize'
    ACCESS_TOKEN_URL = BASE_URL + '/oauth/token'
    USER_QUERY = BASE_URL + '/api/user?'

    SOCIAL_AUTH_TRAILING_SLASH = False  # Remove trailing slash from routes
    SOCIAL_AUTH_AUTH0_DOMAIN = 'jigsawlabs.auth0.com'
    SOCIAL_AUTH_AUTH0_KEY = 'Z9MehfTgspn1HOeoWzu0RO5UvhS5i9EZ'
    SOCIAL_AUTH_AUTH0_SECRET = 'QL7viKKrNQn2nMdmdYJnBM0Q9n8DNqyUhltX8deT-cphOtmKSQulzeMO7TTMufEC'

    SOCIAL_AUTH_AUTH0_SCOPE = [
    'openid',
    'profile'
    ]

    def authorization_url(self):
        return self.BASE_URL + '/authorize'

    def access_token_url(self):
        return self.BASE_URL + '/oauth/token'

    def get_user_id(self, details, response):
        """Return current user id."""
        return details['user_id']

    def get_user_details(self, response):
        # Obtain JWT and the keys to validate the signature
        id_token = response.get('id_token')
        jwks = urlopen(self.BASE_URL + '/.well-known/jwks.json')
        issuer = self.BASE_URL + '/'
        audience = self.setting('KEY')  # CLIENT_ID
        payload = jwt.decode(id_token, jwks.read(), algorithms=['RS256'], audience=audience, issuer=issuer)

        return {'username': payload['nickname'],
                'first_name': payload['name'],
                'picture': payload['picture'],
                'user_id': payload['sub']}
