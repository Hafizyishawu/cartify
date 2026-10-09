"""Sending email, behind a boundary.

Delivery is network work with credentials attached, so it sits behind a
protocol the same way signing and anchoring do. The messages themselves, and
the rules about what may appear in them, are here and testable with nothing
running.

Three rules the templates enforce rather than trust the caller to remember:

- **No secret is ever logged.** A mailer that prints what it sent turns a log
  file into a set of live password reset links.
- **A link says what it does and how long it lasts**, because a user deciding
  whether to click one deserves to know before clicking.
- **Nothing here reveals whether an address is registered.** The reset flow
  answers identically either way, so an unregistered address gets a message
  saying no account exists rather than silence, which would itself be an
  answer.
"""

from __future__ import annotations

import re
import smtplib
import ssl
from dataclasses import dataclass
from email.message import EmailMessage
from pathlib import Path
from typing import Protocol

# A header value containing a newline lets an attacker append headers of their
# own, which is how a "from" address becomes a "bcc" to somewhere else.
HEADER_UNSAFE = re.compile(r"[\r\n]")


class MailError(RuntimeError):
    """The mailer refused to send."""


@dataclass(frozen=True, slots=True)
class Message:
    to: str
    subject: str
    body: str

    def __post_init__(self) -> None:
        for field, value in (("to", self.to), ("subject", self.subject)):
            if HEADER_UNSAFE.search(value):
                raise MailError(f"{field} must not contain a line break")


class Mailer(Protocol):
    def send(self, message: Message) -> None: ...


class FileMailer:
    """Writes messages to a directory instead of sending them.

    For development, and honest about it: a link that reaches a file on disk is
    not a link that reached a person, so nothing here should be mistaken for
    working delivery.
    """

    def __init__(self, directory: str | Path) -> None:
        self.directory = Path(directory)
        self.directory.mkdir(parents=True, exist_ok=True)
        self.sent: list[Message] = []

    def send(self, message: Message) -> None:
        self.sent.append(message)
        safe = re.sub(r"[^a-z0-9@._-]", "_", message.to.lower())
        target = self.directory / f"{len(self.sent):04d}-{safe}.txt"
        target.write_text(
            f"To: {message.to}\nSubject: {message.subject}\n\n{message.body}\n"
        )


class SmtpMailer:
    """Real delivery over SMTP with STARTTLS.

    Credentials come from the caller, which means from the environment or a
    secret store, never from a file in the repository.
    """

    def __init__(self, host: str, port: int, username: str, password: str,
                 sender: str, timeout: int = 10) -> None:
        if not sender or HEADER_UNSAFE.search(sender):
            raise MailError("sender must be a single-line address")
        self._host, self._port = host, port
        self._username, self._password = username, password
        self._sender, self._timeout = sender, timeout

    def send(self, message: Message) -> None:
        email = EmailMessage()
        email["From"] = self._sender
        email["To"] = message.to
        email["Subject"] = message.subject
        email.set_content(message.body)
        context = ssl.create_default_context()
        with smtplib.SMTP(self._host, self._port, timeout=self._timeout) as smtp:
            smtp.starttls(context=context)
            smtp.login(self._username, self._password)
            smtp.send_message(email)


# ---- messages ------------------------------------------------------------

def verification_message(to: str, link: str) -> Message:
    return Message(
        to=to,
        subject="Confirm your email address",
        body=(
            "Confirm this address to raise the assurance level recorded on work you\n"
            "register from now on. Existing records keep the level they were issued\n"
            "under; nothing can reach back and change them.\n\n"
            f"{link}\n\n"
            "The link works once and expires in 24 hours.\n\n"
            "If you did not create a Certifiles account, ignore this. No account\n"
            "action happens until the link is used."
        ),
    )


def password_reset_message(to: str, link: str) -> Message:
    return Message(
        to=to,
        subject="Reset your Certifiles password",
        body=(
            "Use this link to set a new password:\n\n"
            f"{link}\n\n"
            "The link works once and expires in 30 minutes. Every signed-in session\n"
            "is ended when it is used.\n\n"
            "You will still need your authenticator app afterwards. Resetting a\n"
            "password does not bypass your second factor, so someone with access to\n"
            "this inbox alone cannot take the account.\n\n"
            "If you did not ask for this, nothing has changed and you can ignore it."
        ),
    )


def no_account_message(to: str) -> Message:
    """Sent when a reset is requested for an address with no account.

    Silence would itself answer the question of whether an address is
    registered, so the flow always sends something and the two messages differ
    only in what they say to the person who actually receives them.
    """
    return Message(
        to=to,
        subject="Reset your Certifiles password",
        body=(
            "Someone asked to reset a Certifiles password for this address, but no\n"
            "account is registered here.\n\n"
            "If that was you, you may have used a different address.\n\n"
            "No account exists to take any action on, so there is nothing to do."
        ),
    )


def recovery_used_message(to: str) -> Message:
    return Message(
        to=to,
        subject="A recovery code was used on your account",
        body=(
            "A recovery code was used to sign in to your Certifiles account, and\n"
            "that code is now spent.\n\n"
            "If this was you, set up a new authenticator app and generate a fresh\n"
            "set of codes.\n\n"
            "If it was not you, someone else holds one of your recovery codes.\n"
            "Change your password and regenerate your codes now."
        ),
    )
