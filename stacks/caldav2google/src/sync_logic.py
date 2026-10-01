"""Logic for syncing events between a local calendar and Google Calendar.

Patched variant for the homelab deploy. Upstream's ``_create_google_event_body``
always emitted ``start.dateTime``/``end.dateTime`` and reconstructed RRULEs with
``isoformat()``. That breaks two common cases against the Google API (HTTP 400):

  * All-day events (CalDAV ``VALUE=DATE``) must use ``start.date``/``end.date``,
    not ``dateTime`` with a bare ``YYYY-MM-DD`` string.
  * Recurrence values such as ``UNTIL`` must be in iCal basic format
    (``YYYYMMDDTHHMMSSZ``), not ISO 8601 with dashes/colons/offsets.

Only ``_create_google_event_body`` (and small helpers) is changed; the rest is
byte-for-byte upstream.
"""

import json
import os
import time
from datetime import date, datetime, timedelta, timezone
from typing import Any, Dict, List, Tuple

from googleapiclient.discovery import Resource

from src.logger import setup_logger

logger = setup_logger(__name__)

EventDict = Dict[str, Any]
EventsDict = Dict[str, EventDict]

error_events: List[EventDict] = []


def _sanitize_event_for_json(event_data: Dict[str, Any]) -> Dict[str, Any]:
    """Sanitize event data to ensure it's JSON serializable.

    Args:
        event_data: Dictionary containing event details.

    Returns:
        Dict[str, Any]: Sanitized dictionary.
    """
    sanitized = event_data.copy()

    if "rrule" in sanitized and sanitized["rrule"]:
        rrule = sanitized["rrule"].copy()
        for key, value in rrule.items():
            if isinstance(value, list):
                rrule[key] = [item.isoformat() if isinstance(item, (datetime, date)) else item for item in value]
        sanitized["rrule"] = rrule

    return sanitized


def compare_events(
    local_events: EventsDict,
    server_events: EventsDict,
) -> Tuple[List[EventDict], List[EventDict], List[EventDict]]:
    """Compare local and server events to determine changes.

    Args:
        local_events: Dictionary of locally stored events.
        server_events: Dictionary of events from the server.

    Returns:
        Tuple containing lists of new, updated, and deleted events.
    """
    new_events: List[EventDict] = []
    updated_events: List[EventDict] = []
    deleted_events: List[EventDict] = []

    logger.info(f"Comparing {len(server_events)} server events with {len(local_events)} local events")

    # Update server_events with Google event IDs from local_events
    for uid, event in server_events.items():
        if uid in local_events:
            event["google_event_id"] = local_events[uid].get("google_event_id")

    for uid, event in server_events.items():
        if uid not in local_events:
            logger.debug(f"New event found: {event['summary']} (UID: {uid})")
            new_events.append(event)
        elif event["last_modified"] != local_events[uid].get("last_modified"):
            logger.debug(f"Modified event found: {event['summary']} (UID: {uid})")
            updated_events.append(event)

    for uid, event in local_events.items():
        if uid not in server_events:
            logger.debug(f"Deleted event found: {event['summary']} (UID: {uid})")
            deleted_events.append(event)

    logger.info(
        f"Found {len(new_events)} new events, {len(updated_events)} modified events, "
        f"and {len(deleted_events)} deleted events",
    )
    return new_events, updated_events, deleted_events


def load_local_sync(file_path: str) -> EventsDict:
    """Load the locally synced events from a JSON file.

    Args:
        file_path: Path to the JSON file.

    Returns:
        EventsDict: Dictionary of previously synced events.
    """
    logger.info(f"Loading local sync data from {file_path}")
    if not os.path.exists(file_path):
        logger.info("No existing sync file found, starting fresh")
        return {}

    try:
        with open(file_path, "r") as file:
            events = json.load(file)
            logger.info(f"Successfully loaded {len(events)} events from local sync file")
            return events
    except json.JSONDecodeError as e:
        logger.error(f"Error decoding JSON from {file_path}: {str(e)}")
        return {}
    except Exception as e:
        logger.error(f"Unexpected error loading sync file: {str(e)}")
        return {}


def save_local_sync(file_path: str, events: EventsDict) -> None:
    """Save the events to the local sync JSON file.

    Args:
        file_path: Path to the JSON file.
        events: Dictionary of events to save.
    """
    logger.info(f"Saving {len(events)} events to local sync file")
    sanitized_events = {}

    for event_id, event_data in events.items():
        try:
            sanitized_events[event_id] = _sanitize_event_for_json(event_data)
        except Exception as e:
            logger.error(f"Failed to sanitize event {event_id} ({event_data.get('summary', 'No summary')}): {str(e)}")
            continue

    try:
        with open(file_path, "w") as file:
            json.dump(sanitized_events, file, indent=4, default=str)
            logger.info(f"Successfully saved {len(sanitized_events)} events to {file_path}")
    except Exception as e:
        logger.error(f"Failed to save sync file: {str(e)}")
        logger.debug("Attempting to identify problematic events...")

        for event_id, event_data in sanitized_events.items():
            try:
                json.dumps(event_data)
            except TypeError as e:
                logger.error(f"JSON serialization failed for event: {event_id}")
                logger.error(f"Event summary: {event_data.get('summary', 'No summary')}")
                logger.error(f"Error: {str(e)}")

                for key, value in event_data.items():
                    try:
                        json.dumps({key: value})
                    except TypeError:
                        logger.error(f"Problematic field: {key} = {value} (type: {type(value)})")


def _is_date_only(value: Any) -> bool:
    """True if the value represents an all-day (date, no time) boundary."""
    return isinstance(value, str) and len(value) == 10 and "T" not in value


def _ical_basic(item: Any) -> str:
    """Render a recurrence value in iCal basic format (e.g. UNTIL=YYYYMMDDTHHMMSSZ)."""
    if isinstance(item, datetime):
        if item.tzinfo is not None:
            return item.astimezone(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        return item.strftime("%Y%m%dT%H%M%S")
    if isinstance(item, date):
        return item.strftime("%Y%m%d")
    s = str(item)
    if "T" in s:  # ISO datetime string -> basic; drop offset, mark UTC if present
        try:
            dt = datetime.fromisoformat(s)
            if dt.tzinfo is not None:
                return dt.astimezone(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
            return dt.strftime("%Y%m%dT%H%M%S")
        except ValueError:
            return s.replace("-", "").replace(":", "").split("+")[0]
    if len(s) == 10 and s.count("-") == 2:  # ISO date -> basic
        return s.replace("-", "")
    return s


def _create_google_event_body(event: EventDict) -> Dict[str, Any]:
    """Create the event body for Google Calendar API.

    Handles all-day events (``date``) vs timed events (``dateTime``) and
    serializes recurrence rules in iCal basic format.

    Args:
        event: Dictionary containing event details.

    Returns:
        Dict[str, Any]: Formatted event body for Google Calendar API.
    """
    start = event["start"]
    end = event.get("end")
    all_day = _is_date_only(start)

    google_event: Dict[str, Any] = {
        "summary": event["summary"],
        "description": event.get("description", ""),
        "location": event.get("location", ""),
    }

    if all_day:
        # Google all-day events use exclusive end dates; default to start + 1 day.
        if not _is_date_only(end):
            try:
                end = (datetime.strptime(start, "%Y-%m-%d").date() + timedelta(days=1)).strftime("%Y-%m-%d")
            except ValueError:
                end = start
        google_event["start"] = {"date": start}
        google_event["end"] = {"date": end}
    else:
        if not end:
            end = start
        google_event["start"] = {"dateTime": start, "timeZone": "UTC"}
        google_event["end"] = {"dateTime": end, "timeZone": "UTC"}

    if event.get("rrule"):
        logger.debug(f"Processing recurring event rules for {event['summary']}")
        rrule_parts = []
        for key, value in event["rrule"].items():
            if isinstance(value, list):
                value = ",".join(_ical_basic(v) for v in value)
            else:
                value = _ical_basic(value)
            rrule_parts.append(f"{key}={value}")
        google_event["recurrence"] = [f"RRULE:{';'.join(rrule_parts)}"]

        if event.get("exdate"):
            logger.debug(f"Processing {len(event['exdate'])} excluded dates")
            ex_values = [_ical_basic(d) for d in event["exdate"]]
            if all_day:
                google_event["recurrence"].append("EXDATE;VALUE=DATE:" + ",".join(ex_values))
            else:
                google_event["recurrence"].append("EXDATE:" + ",".join(ex_values))

    return google_event


def add_event_to_google(service: Resource, event: EventDict, calendar_id: str) -> None:
    """Add or update a single event in Google Calendar.

    Args:
        service: Authenticated Google Calendar API service object.
        event: Dictionary containing event details.
        calendar_id: ID of the target Google Calendar.
    """
    logger.info(f"Processing event: {event['summary']} (UID: {event['uid']})")

    try:
        google_event = _create_google_event_body(event)

        if event.get("google_event_id"):
            logger.info(
                f"Updating existing event in Google Calendar: {event['summary']} (GoogleID: {event['google_event_id']})",
            )
            created_event = (
                service.events()
                .update(
                    calendarId=calendar_id,
                    eventId=event["google_event_id"],
                    body=google_event,
                )
                .execute()
            )
            logger.info(f"Successfully updated event: {event['summary']} (Google ID: {created_event['id']})")
        else:
            logger.info(f"Creating new event in Google Calendar: {event['summary']}")
            created_event = (
                service.events()
                .insert(
                    calendarId=calendar_id,
                    body=google_event,
                )
                .execute()
            )
            event["google_event_id"] = created_event["id"]
            logger.info(f"Successfully created event: {event['summary']} (Google ID: {created_event['id']})")

    except Exception as e:
        logger.error(f"Failed to add/update event {event['summary']} (UID: {event['uid']})")
        logger.error(f"Error: {str(e)}")
        error_events.append(event)

    finally:
        time.sleep(0.5)


def delete_event_from_google(service: Resource, event: EventDict, calendar_id: str) -> None:
    """Delete a single event from Google Calendar.

    Args:
        service: Authenticated Google Calendar API service object.
        event: Dictionary containing event details.
        calendar_id: ID of the target Google Calendar.
    """
    try:
        google_event_id = event.get("google_event_id")
        if not google_event_id:
            logger.warning(
                f"No Google Calendar ID found for event {event.get('summary', 'Unknown')} "
                f"(UID: {event.get('uid', 'Unknown')})",
            )
            return

        summary = event.get("summary", "Unknown Event")

        logger.info(f"Deleting event: {summary} (Google ID: {google_event_id})")
        service.events().delete(calendarId=calendar_id, eventId=google_event_id).execute()
        logger.info(f"Successfully deleted event: {summary}")

    except Exception as e:
        logger.error(f"Failed to delete event: {event.get('summary', 'Unknown')} (UID: {event.get('uid', 'Unknown')})")
        logger.error(f"Error: {str(e)}")

    finally:
        time.sleep(0.5)
