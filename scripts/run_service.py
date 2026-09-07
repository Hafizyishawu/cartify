#!/usr/bin/env python3
"""Run the Certifiles service for development.

Not a production server. http.server is single process, has no TLS, and does no
hardening; the domain logic underneath is what a real deployment would carry
across. Secure cookies are off by default here because development runs over
plain HTTP, and that is exactly the setting to turn back on anywhere else.
"""

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from certifiles.accounts import AccountStore
from certifiles.domains import new_server_secret
from certifiles.log import TransparencyLog
from certifiles.mail import FileMailer
from certifiles.ratelimit import RateLimiter
from certifiles.service import Services, serve
from certifiles.sessions import SessionStore
from certifiles.tokens import TokenStore


class NoResolver:
    """Refuses every DNS lookup rather than pretending one succeeded.

    Domain verification needs a real resolver. Returning nothing would read as
    "you do not control this domain"; refusing reads as "this was not checked",
    which is the truthful answer in development.
    """

    def txt(self, name):
        raise RuntimeError("no DNS resolver is configured in development")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--port", type=int, default=8770)
    parser.add_argument("--data", type=Path, default=Path("var"))
    parser.add_argument("--web", type=Path, default=Path("web"))
    parser.add_argument(
        "--secure-cookies", action="store_true",
        help="set the Secure flag; required anywhere the site is served over TLS",
    )
    args = parser.parse_args()
    args.data.mkdir(parents=True, exist_ok=True)

    services = Services(
        accounts=AccountStore(args.data / "accounts.db"),
        sessions=SessionStore(args.data / "sessions.db"),
        limiter=RateLimiter(args.data / "ratelimit.db"),
        log=TransparencyLog(args.data / "log.db"),
        web_root=args.web,
        tokens=TokenStore(args.data / "tokens.db"),
        mailer=FileMailer(args.data / "mail"),
        resolver=NoResolver(),
        domain_secret=new_server_secret(),
        base_url=f"http://127.0.0.1:{args.port}",
        secure_cookies=args.secure_cookies,
    )
    server = serve(services, port=args.port)
    print(f"  certifiles on http://127.0.0.1:{server.server_address[1]}")
    print(f"  data in {args.data}/   web from {args.web}/")
    print(f"  email is written to {args.data}/mail/ and not delivered")
    if not args.secure_cookies:
        print("  cookies are NOT marked Secure: development only")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n  stopped")
