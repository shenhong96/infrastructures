"""Module for authenticating with Google Calendar API.

Patched variant for the homelab deploy: persists credentials as a portable
``token.json`` (authorized_user JSON via ``Credentials.to_json()``) instead of
``token.pickle``. This lets the token be minted on one machine (e.g. a Mac with
a browser) and consumed in the headless container without pickle/library
version coupling. Behaviour is otherwise identical to upstream.
"""

import os
from typing import List

from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import Resource, build

from src.logger import setup_logger

logger = setup_logger(__name__)

SCOPES: List[str] = ["https://www.googleapis.com/auth/calendar"]
TOKEN_FILE = "token.json"
CLIENT_FILE = "credentials.json"


def authenticate_google() -> Resource:
    """Authenticate with Google Calendar API and return a service object.

    Loads credentials from ``token.json`` if present, refreshes them when
    expired, or runs the interactive OAuth2 flow (browser) as a last resort.
    The refreshed/new token is written back to ``token.json``.

    Returns:
        Resource: An authenticated Google Calendar API service object.
    """
    creds: Credentials | None = None
    if os.path.exists(TOKEN_FILE):
        logger.debug("Loading existing credentials from %s", TOKEN_FILE)
        creds = Credentials.from_authorized_user_file(TOKEN_FILE, SCOPES)

    if not creds or not creds.valid:
        if creds and creds.expired and creds.refresh_token:
            logger.info("Refreshing expired credentials")
            creds.refresh(Request())
        else:
            logger.info("Starting new OAuth2 flow")
            flow = InstalledAppFlow.from_client_secrets_file(CLIENT_FILE, SCOPES)
            creds = flow.run_local_server(port=0)

        logger.debug("Saving credentials to %s", TOKEN_FILE)
        with open(TOKEN_FILE, "w", encoding="utf-8") as token:
            token.write(creds.to_json())

    return build("calendar", "v3", credentials=creds)


def search_calendar_id(service: Resource, calendar_name: str) -> str:
    """List all available Google calendars and return the ID of the target calendar.

    Args:
        service: Authenticated Google Calendar API service object.
        calendar_name: Name of the target Google Calendar.

    Returns:
        str: The calendar ID of the target Google Calendar.

    Raises:
        ValueError: If the target calendar is not found.
    """
    logger.info(f"Searching for calendar: {calendar_name}")
    calendars_result = service.calendarList().list().execute()
    calendars = calendars_result.get("items", [])
    logger.debug(f"Found {len(calendars)} calendars in total")

    for calendar in calendars:
        if calendar["summary"].lower() == calendar_name.lower():
            logger.info(f"Found matching calendar with ID: {calendar['id']}")
            return calendar["id"]

    error_msg = f"No calendar named '{calendar_name}' found"
    logger.error(error_msg)
    raise ValueError(error_msg)
