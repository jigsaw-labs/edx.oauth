"""
Auth0 implementation based on:
https://auth0.com/docs/quickstart/webapp/django/01-login
"""
from jose import jwt
from .oauth import BaseOAuth2

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

    SOCIAL_AUTH_TRAILING_SLASH = False  # Remove trailing slash from routes
    SOCIAL_AUTH_AUTH0OAUTH2_DOMAIN = 'jigsawlabs.auth0.com'
    SOCIAL_AUTH_AUTH0OAUTH2_KEY = 'Z9MehfTgspn1HOeoWzu0RO5UvhS5i9EZ'
    SOCIAL_AUTH_AUTH0OAUTH2_SECRET = 'QL7viKKrNQn2nMdmdYJnBM0Q9n8DNqyUhltX8deT-cphOtmKSQulzeMO7TTMufEC'
    SOCIAL_AUTH_AUTH0OAUTH2_LOGIN_URL = '/login/auth0'
    SOCIAL_AUTH_AUTH0OAUTH2_LOGIN_REDIRECT_URL = '/dashboard'

    def api_path(self, path=''):
        """Build API path for Auth0 domain"""
        return 'https://{domain}/{path}'.format(domain=self.SOCIAL_AUTH_AUTH0OAUTH2_DOMAIN,
                                                path=path)

    def authorization_url(self):
        url = self.api_path('authorize')
        if self.DEBUG_LOG:
            logger.info('authorization_url(): {}'.format(url))
        return url

    def access_token_url(self):
        url = self.api_path('oauth/token')
        if self.DEBUG_LOG:
            logger.info('access_token_url(): {}'.format(url))
        return url

    def get_user_id(self, details, response):
        """Return current user id."""
        if self.DEBUG_LOG:
            logger.info('get_user_id(): {}'.format(details['user_id']))
        return url
        return details['user_id']

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

    def get_key_and_secret(self):
        if self.DEBUG_LOG:
            logger.info('get_key_and_secret() - client_id: {}'.format(settings.SOCIAL_AUTH_AUTH0OAUTH2_KEY))

        return (settings.SOCIAL_AUTH_AUTH0OAUTH2_KEY, settings.SOCIAL_AUTH_AUTH0OAUTH2_SECRET)
