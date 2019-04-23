"""
Auth0 implementation based on:
https://manage.auth0.com/dashboard/us/jigsawlabs/applications/Z9MehfTgspn1HOeoWzu0RO5UvhS5i9EZ/quickstart
"""
import json
from jose import jwt
from urllib import urlencode
from urllib2 import urlopen
from social_core.backends.oauth import BaseOAuth2

from logging import getLogger
logger = getLogger(__name__)

DEBUG_LOG = True

class Auth0OAuth2(BaseOAuth2):
    """Auth0 OAuth authentication backend"""
    name = 'auth0'
    SCOPE_SEPARATOR = ' '
    ACCESS_TOKEN_METHOD = 'POST'
    EXTRA_DATA = [
        ('picture', 'picture')
    ]
    # mcdaniel: configure backend
    SOCIAL_AUTH_AUTH0_SCOPE = [
        'openid',
        'profile'
    ]

    BASE_URL = 'https://jigsawlabs.auth0.com'
    AUTHORIZATION_URL = BASE_URL + '/oauth/authorize'
    ACCESS_TOKEN_URL = BASE_URL + '/oauth/token'
    USER_QUERY = BASE_URL + '/api/user?'

    SOCIAL_AUTH_TRAILING_SLASH = False  # Remove trailing slash from routes
    KEY = 'Z9MehfTgspn1HOeoWzu0RO5UvhS5i9EZ'
    SECRET = 'QL7viKKrNQn2nMdmdYJnBM0Q9n8DNqyUhltX8deT-cphOtmKSQulzeMO7TTMufEC'

    def authorization_url(self):
        url = self.AUTHORIZATION_URL
        if self.DEBUG_LOG:
            logger.info('authorization_url(): {}'.format(url))
        return url

    def access_token_url(self):
        url = self.ACCESS_TOKEN_URL
        if self.DEBUG_LOG:
            logger.info('access_token_url(): {}'.format(url))
        return url

    def get_user_id(self, details, response):
        """Return current user id."""
        if self.DEBUG_LOG:
            logger.info('get_user_id(): {}'.format(details['user_id']))
        return url
        return details['user_id']

    def urlopen(self, url):
        if self.DEBUG_LOG:
            logger.info('urlopen() - url: {}'.format(url))
        return urlopen(url).read().decode("utf-8")

    def get_user_details(self, response):
        dict = {'username': 'nickname',
                'email': 'email',
                'email_verified': 'email_verified'
                'fullname': 'fullname',
                'first_name': 'first_name',
                'last_name': 'last_name',
                'picture': 'picture',
                'user_id': 'user_id'}

        if self.DEBUG_LOG:
            logger.info('get_user_details(): {}'.format(dict))
        return dict



    """
    def get_user_details(self, response):
        # Obtain JWT and the keys to validate the signature
        id_token = response.get('id_token')
        jwks = self.get_json(self.api_path('.well-known/jwks.json'))
        issuer = self.api_path()
        audience = self.SOCIAL_AUTH_AUTH0OAUTH2_KEY  # CLIENT_ID
        payload = jwt.decode(id_token,
                             jwks,
                             algorithms=['RS256'],
                             audience=audience,
                             issuer=issuer)
        fullname, first_name, last_name = self.get_user_names(payload['name'])
        return {'username': payload['nickname'],
                'email': payload['email'],
                'email_verified': payload.get('email_verified', False),
                'fullname': fullname,
                'first_name': first_name,
                'last_name': last_name,
                'picture': payload['picture'],
                'user_id': payload['sub']}

    """

    def get_key_and_secret(self):
        if self.DEBUG_LOG:
            logger.info('get_key_and_secret() - client_id: {}'.format(self.KEY))

        return (self.KEY, self.SECRET)
