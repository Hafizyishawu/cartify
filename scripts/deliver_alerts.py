#!/usr/bin/env python3
"""Send queued near-match alerts.

Separate from the service on purpose. Registration queues rows and returns;
this drains the queue. In production it runs as a worker on a schedule, so a
slow or unreachable mail server delays notifications instead of delaying the
registrations they are about.

Idempotent: an alert already sent is never sent again, and a send that fails
leaves the row queued for the next run until it has been tried enough times to
conclude the address is unreachable.
"""

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from certifiles.accounts import AccountStore
from certifiles.alerts import AlertStore, deliver
from certifiles.mail import FileMailer, SmtpMailer

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--data", type=Path, default=Path("var"))
    parser.add_argument("--base-url", default="http://127.0.0.1:3000")
    parser.add_argument("--limit", type=int, default=100)
    parser.add_argument(
        "--smtp", metavar="HOST:PORT",
        help="deliver for real; without it messages are written to <data>/mail/",
    )
    parser.add_argument("--smtp-user", default="")
    parser.add_argument("--smtp-sender", default="alerts@certifiles.com")
    args = parser.parse_args()

    if args.smtp:
        import os

        password = os.environ.get("CERTIFILES_SMTP_PASSWORD")
        if not password:
            # Refusing rather than falling back to a file: an operator who
            # asked for real delivery and silently got a directory would not
            # find out until an artist asked why they were never told.
            raise SystemExit("CERTIFILES_SMTP_PASSWORD is required with --smtp")
        host, _, port = args.smtp.partition(":")
        mailer = SmtpMailer(host, int(port or 587), args.smtp_user, password,
                            args.smtp_sender)
    else:
        mailer = FileMailer(args.data / "mail")

    with AlertStore(args.data / "alerts.db") as alerts, \
         AccountStore(args.data / "accounts.db") as accounts:
        sent = deliver(alerts, accounts, mailer, args.base_url, limit=args.limit)
        waiting = len(alerts.undelivered())
        abandoned = alerts.abandoned()

    print(f"  {sent} message{'' if sent == 1 else 's'} sent")
    print(f"  {waiting} still queued")
    if abandoned:
        # Loud, because silence here means artists are not being told and
        # nothing else in the system would surface it.
        print(f"  {abandoned} abandoned after repeated failures, needs attention")
        raise SystemExit(1)
