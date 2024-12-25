# forked from https://github.com/floxay/python-riot-auth

from __future__ import annotations

import json
from base64 import urlsafe_b64decode
from secrets import token_hex, token_urlsafe
from typing import TYPE_CHECKING, Any
from urllib.parse import parse_qsl, urldefrag, urlsplit

import aiohttp

from .errors import RiotAuthenticationError, RiotRatelimitError

if TYPE_CHECKING:
    from collections.abc import Sequence


class RiotAuth:
    RIOT_CLIENT_USER_AGENT = token_urlsafe(111).replace('_', 'W').replace('-', 'w')

    def __init__(self) -> None:
        self._cookie_jar = aiohttp.CookieJar()
        self.access_token: str | None = None
        self.scope: str | None = None
        self.id_token: str | None = None
        self.token_type: str | None = None
        self.expires_at: int = 0
        self.user_id: str | None = None
        self.entitlements_token: str | None = None

    def __update(
        self,
        extract_jwt: bool = False,
        key_attr_pairs: Sequence[tuple[str, str]] = (
            ('sub', 'user_id'),
            ('exp', 'expires_at'),
        ),
        **kwargs: dict[str, Any],
    ) -> None:
        # ONLY PREDEFINED PUBLIC KEYS ARE SET, rest is silently ignored!
        predefined_keys = [key for key in self.__dict__ if key[0] != '_']

        self.__dict__.update((key, val) for key, val in kwargs.items() if key in predefined_keys)

        if extract_jwt:  # extract additional data from access JWT
            additional_data = self.__get_keys_from_access_token(key_attr_pairs)
            self.__dict__.update((key, val) for key, val in additional_data if key in predefined_keys)

    def __get_keys_from_access_token(self, key_attr_pairs: Sequence[tuple[str, str]]) -> list[tuple[str, Any]]:
        assert self.access_token is not None
        payload = self.access_token.split('.')[1]
        decoded = urlsafe_b64decode(f'{payload}===')
        temp_dict: dict[str, Any] = json.loads(decoded)
        return [(attr, temp_dict.get(key)) for key, attr in key_attr_pairs]

    def __set_tokens_from_uri(self, data: dict[str, Any]) -> None:
        mode = data['response']['mode']
        uri = data['response']['parameters']['uri']

        result = getattr(urlsplit(uri), mode)
        data = dict(parse_qsl(result))
        self.__update(extract_jwt=True, **data)

    async def __fetch_entitlements_token(self, session: aiohttp.ClientSession) -> None:
        headers = {
            'Accept-Encoding': 'deflate, gzip, zstd',
            # "user-agent": RiotAuth.RIOT_CLIENT_USER_AGENT % "entitlements",
            'user-agent': RiotAuth.RIOT_CLIENT_USER_AGENT,
            'Cache-Control': 'no-cache',
            'Accept': 'application/json',
            'Authorization': f'{self.token_type} {self.access_token}',
        }

        async with session.post(
            'https://entitlements.auth.riotgames.com/api/token/v1',
            headers=headers,
            json={},
            # json={"urn": "urn:entitlement:%"},
        ) as r:
            self.entitlements_token = (await r.json())['entitlements_token']

    async def redeem_cookies(self, cookies: str) -> None:
        """
        Redeem cookies for authentication.
        """

        if cookies:
            self._cookie_jar.clear()

        async with aiohttp.ClientSession() as session:
            async with session.get(
                'https://auth.riotgames.com/authorize?redirect_uri=https%3A%2F%2Fplayvalorant.com%2Fopt_in&client_id=play-valorant-web-prod&response_type=token%20id_token&scope=account%20openid&nonce=1',
                headers={
                    'Accept-Language': 'en-US,en;q=0.5',
                    'user-agent': RiotAuth.RIOT_CLIENT_USER_AGENT,
                    'cookie': cookies,
                    'referer': f'https://{token_hex(5)}.riotgames.com/',
                },
                allow_redirects=False,
            ) as resp:
                text = await resp.text()

                if resp.status != 303:
                    raise RiotAuthenticationError('Cookies is expired.')

                if resp.status == 429 and resp.headers.get('location', '').startswith('/auth-error?error=rate_limited'):
                    # int(resp.headers.get('retry-after', 0))
                    raise RiotRatelimitError('Rate limited.')

                if resp.status == 403 and resp.headers.get('x-frame-options') == 'SAMEORIGIN':
                    raise RiotAuthenticationError('Cloudflare block.')

                if resp.headers.get('location', '').startswith('/login'):
                    raise RiotAuthenticationError('Invalid Cookies.')

                self._cookie_jar = session.cookie_jar  # type: ignore[assignment]

                fragment = urldefrag(text).fragment
                data: dict[str, Any] = dict(parse_qsl(fragment))

                self.__update(extract_jwt=True, **data)

                await self.__fetch_entitlements_token(session=session)

    async def re_redeem_cookies(self) -> bool:
        """
        Reauthenticate using cookies.

        Returns a ``bool`` indicating success or failure.
        """
        try:
            await self.redeem_cookies('')
        except RiotAuthenticationError:  # because credentials are empty
            return False
        else:
            return True
