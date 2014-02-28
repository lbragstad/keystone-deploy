"""A secure echo service, protected by ``auth_token``.

When the ``auth_token`` module authenticates a request, the echo service will
respond with all the environment variables presented to it by ``auth_token``.
"""
import json

from keystoneclient.middleware import auth_token


AUTH_TOKEN_CONF = {
    'auth_protocol': 'http',
    'auth_host': '192.168.111.222',
    'auth_port': 35357,
    'auth_uri': 'http://192.168.111.222:35357/',
    'admin_token': 'ADMIN',
    'admin_user': None,
    'admin_password': None,
    'admin_tenant_name': 'admin',
    'certfile': None,
    'keyfile': None,
    'cafile': None,
    'memcached_servers': ['127.0.0.1:11211'],
    'token_cache_time': 300,
    'revocation_cache_time': 60,
    'memcache_security_strategy': 'ENCRYPT',
    'memcache_secret_key': '5bdc5pilx0o7re34z3yc2yt4x',
    'include_service_catalog': True}


def echo_app(environ, start_response):
    """A WSGI application that echoes the CGI environment to the user."""
    start_response('200 OK', [('Content-Type', 'application/json')])
    environment = dict((k, v) for k, v in environ.iteritems()
                       if k.startswith('HTTP_X_'))
    yield json.dumps(environment, indent=2)


application = auth_token.AuthProtocol(echo_app, AUTH_TOKEN_CONF)
