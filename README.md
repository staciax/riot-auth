## riot-auth
riot-auth is a simple authentication with cookies. 
this project forked from [python-riot-auth](https://github.com/floxay/python-riot-auth) by [floxay](https://github.com/floxay)

## Installation

```bash
# pip
pip install git+https://github.com/staciax/riot-auth.git

# uv
uv add git+https://github.com/staciax/riot-auth.git
```

## Usage

```python
import asyncio

from riot_auth import RiotAuth

# How to get cookies
# https://github.com/giorgi-o/SkinPeek/wiki/How-to-get-your-Riot-cookies

async def main():
    auth = RiotAuth()

    cookies = 'your riot account cookies'

    await auth.redeem_cookies(cookies)

    print(auth.access_token)


asyncio.run(main())
```

