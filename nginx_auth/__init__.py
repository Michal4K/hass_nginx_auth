import logging
import os
import json
import shelve
import secrets
import voluptuous as vol
from http import HTTPStatus
from typing import Any, cast
from aiohttp import web
from multidict import MultiDictProxy
from homeassistant.core import callback
from homeassistant.components.http import HomeAssistantView
from homeassistant.helpers import config_validation as cv
from urllib.parse import urlparse
from urllib.parse import parse_qs


_LOGGER = logging.getLogger(__name__)

DOMAIN = 'nginx_auth'

CONFIG_SCHEMA = vol.Schema({
    DOMAIN: vol.All(
        cv.ensure_list,
        [
            vol.Schema({
                vol.Required('service'): cv.string,
                vol.Required('users'): vol.All(cv.ensure_list, [cv.string])
            })
        ]
    )
}, extra=vol.ALLOW_EXTRA)

async def async_setup(hass, config):
    service = []
    users = []
    for service_config in config[DOMAIN]:
        service.append(service_config['service'])
        users.append(service_config['users'])
    hass.data['service'] = service
    hass.data['users'] = users
    
    hass.http.register_view(AuthTokenValidation(hass))
    hass.http.register_view(AuthJS())
    
    return True

class AuthTokenValidation(HomeAssistantView):
    url = '/nginx_auth/auth'
    name = 'nginx_auth:auth'
    requires_auth = False

    def __init__(self, hass):
        self.hass = hass
        self.tokens = shelve.open('tokens_store')
        self.service = self.hass.data.get("service")
        self.users = self.hass.data.get("users")
        _LOGGER.debug(f"s: {self.service} {self.users}")

    async def get(self, request):
        origin_url = request.headers.get('X-Original-URI')
        _LOGGER.debug(f"{origin_url}")
        parsed_url = urlparse(origin_url)
        token = request.cookies.get('auth_token')
        _LOGGER.debug("token type:" + str(type(token)))
        if(token is None):
            return self.json({"status": "UNAUTHORIZED"}, status_code=HTTPStatus.UNAUTHORIZED)
        _LOGGER.debug(f"token: {token}")
        is_auth = self.hass.auth.async_validate_access_token(token)
        try:
            user = self.tokens.get(token, "None")
            authoriezed_user = self.users[(self.service.index(parsed_url.netloc))]
            is_auth = user in authoriezed_user
            _LOGGER.debug(f"auth: {is_auth}, {authoriezed_user}")
            if(is_auth is True):
                return self.json({'status': "OK"}, status_code=HTTPStatus.OK)
            return self.json({"status": "UNAUTHORIZED"}, status_code=HTTPStatus.UNAUTHORIZED)
        except Exception as e:
            _LOGGER.debug(e)
            return self.json({"status": "BAD REQUEST"}, status_code=HTTPStatus.BAD_REQUEST)

    async def post(self, request):
        token = (await request.json())["auth_token"]
        _LOGGER.debug(f"token: {token}")
        try:
            is_auth = self.hass.auth.async_validate_access_token(token)
            _LOGGER.debug(f"auth: {is_auth}")
            user = is_auth.user.name
            if(is_auth != None):
                token = secrets.token_urlsafe(64)
                self.tokens[token] = user
                self.tokens.sync()
                return self.json({'token': token}, status_code=HTTPStatus.OK)
            return self.json({"status": "Invalid auth token"}, status_code=HTTPStatus.BAD_REQUEST)
        except:
            return self.json({"status": "BAD REQUEST"}, status_code=HTTPStatus.BAD_REQUEST)

class AuthJS(HomeAssistantView):
    """Serve js file for extrackting HA session token"""

    url = '/nginx_auth/get_access_token'
    name = 'nginx_auth:get_access_token'
    requires_auth = False

    async def get(self, request):
        host = request.headers.get('Host')
        try:
            with open(os.path.join(os.path.dirname(__file__), 'get_access_token.html'), 'r') as file:
                response = file.read()
            response = response.replace("<has_endpoint>", host)
            return web.Response(body=response, content_type='text/html', status=HTTPStatus.OK)
        except FileNotFoundError:
            return self.json({"status": "BAD REQUEST"}, status_code=HTTPStatus.BAD_REQUEST)

