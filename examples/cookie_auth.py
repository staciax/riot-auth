import asyncio

from riot_auth import RiotAuth


async def main() -> None:
    auth = RiotAuth()

    # How to get cookies?
    # https://github.com/giorgi-o/SkinPeek/wiki/How-to-get-your-Riot-cookies

    cookies = ''

    await auth.redeem_cookies(cookies)

    print(f'Access Token Type: {auth.token_type}\n')
    print(f'Access Token: {auth.access_token}\n')
    print(f'Entitlements Token: {auth.entitlements_token}\n')
    print(f'User ID: {auth.user_id}')

    print(await auth.re_redeem_cookies())


if __name__ == '__main__':
    asyncio.run(main())
