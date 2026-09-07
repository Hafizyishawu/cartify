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
from certifiles.doh import default_resolver
from certifiles.domains import new_server_secret
from certifiles.log import TransparencyLog
from certifiles.mail import FileMailer
from certifiles.ratelimit import RateLimiter
from certifiles.service import Services, serve
from certifiles.sessions import SessionStore
from certifiles.tokens import TokenStore


def load_domain_secret(path: Path) -> bytes:
    """Read the challenge secret, minting it once on first run.

    It has to survive a restart. The challenge is an HMAC under this secret, so
    a fresh one every launch would silently invalidate a TXT record the user
    already published, and the failure would look like their DNS was wrong.
    """
    if path.exists():
        return path.read_bytes()
    secret = new_server_secret()
    path.touch(mode=0o600)
    path.write_bytes(secret)
    return secret


class NoResolver:
    """Refuses every DNS lookup rather than pretending one succeeded.

    Kept for running with no network at all. Returning nothing would read as
    "you do not control this domain"; refusing reads as "this was not checked",
    which is the only truthful answer when no lookup happened.
    """

    def txt(self, name):
        raise RuntimeError("DNS lookups are disabled (--dns none)")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--port", type=int, default=8770)
    parser.add_argument("--data", type=Path, default=Path("var"))
    parser.add_argument("--web", type=Path, default=Path("web"))
    parser.add_argument(
        "--secure-cookies", action="store_true",
        help="set the Secure flag; required anywhere the site is served over TLS",
    )
    parser.add_argument(
        "--dns", choices=("doh", "none"), default="doh",
        help="doh queries two independent DNS-over-HTTPS resolvers and requires "
             "them to agree; none refuses every lookup, for running offline",
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
        resolver=default_resolver() if args.dns == "doh" else NoResolver(),
        domain_secret=load_domain_secret(args.data / "domain-secret"),
        base_url=f"http://127.0.0.1:{args.port}",
        secure_cookies=args.secure_cookies,
    )
    server = serve(services, port=args.port)
    print(f"  certifiles on http://127.0.0.1:{server.server_address[1]}")
    print(f"  data in {args.data}/   web from {args.web}/")
    print(f"  email is written to {args.data}/mail/ and not delivered")
    if args.dns == "doh":
        print("  domain checks query two DNS-over-HTTPS resolvers and require agreement")
    else:
        print("  domain checks are disabled and will report that they could not run")
    if not args.secure_cookies:
        print("  cookies are NOT marked Secure: development only")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n  stopped")
