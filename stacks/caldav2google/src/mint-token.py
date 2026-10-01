#!/usr/bin/env python3
"""Mint token.json for caldav2google on a machine WITH a browser (e.g. your Mac).

Reuses the SAME Google OAuth client as Hermes (credentials.json) but mints a
fresh, calendar-only token — independent fate from Hermes's token.

Usage (run in a dir that contains credentials.json):

    python3 -m venv .venv && . .venv/bin/activate
    pip install "google-auth-oauthlib>=1.2,<2"
    python3 mint-token.py        # opens a browser; approve the Calendar scope

Then copy the resulting token.json into the stack's data/ directory on CT111.
credentials.json is NOT needed in the container (token.json carries the
client id/secret needed to refresh).
"""

from google_auth_oauthlib.flow import InstalledAppFlow

# Must match caldav2google's scope exactly.
SCOPES = ["https://www.googleapis.com/auth/calendar"]


def main() -> None:
    flow = InstalledAppFlow.from_client_secrets_file("credentials.json", SCOPES)
    creds = flow.run_local_server(port=0)
    with open("token.json", "w", encoding="utf-8") as f:
        f.write(creds.to_json())
    print("Wrote token.json — copy it into the stack's data/ directory on CT111.")


if __name__ == "__main__":
    main()
