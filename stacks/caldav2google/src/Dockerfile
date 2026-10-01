# caldav2google — one-way Nextcloud (CalDAV) -> Google Calendar sync.
# Upstream has no Dockerfile and is a run-once script, so we vendor it at a
# pinned commit, install its runtime deps, patch auth to use portable token.json
# (no pickle), and add a scheduling loop via entrypoint.sh.
FROM python:3.12-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
        git ca-certificates curl \
    && rm -rf /var/lib/apt/lists/*

ARG C2G_REPO=https://github.com/rogsme/caldav2google
# Pin for reproducibility (HEAD of main at scaffold time). Bump deliberately.
ARG C2G_REF=156a9cccb5b05777a506dc4c0fd8c3a7d2fdc4ef
RUN git clone "$C2G_REPO" /app && git -C /app checkout "$C2G_REF"

# Runtime deps (mirrors upstream pyproject; Poetry not needed at runtime).
RUN pip install --no-cache-dir \
        "caldav>=1.4.0,<2" \
        "icalendar>=6.1.0,<7" \
        "google-api-python-client>=2.154.0" \
        "google-auth>=2.36,<3" \
        "google-auth-httplib2>=0.2.0" \
        "google-auth-oauthlib>=1.2.1,<2" \
        "python-dotenv>=1.0.1"

# Patch: load/save credentials as portable token.json (authorized_user JSON)
# instead of token.pickle, so the token minted on another machine is not tied
# to a specific pickled-library version.
COPY auth_google.py /app/src/auth_google.py

# Patch: emit all-day events as date (not dateTime) and serialize recurrence
# rules in iCal basic format, so all-day/recurring events stop 400'ing.
COPY sync_logic.py /app/src/sync_logic.py

COPY entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod +x /usr/local/bin/entrypoint.sh

ENV PYTHONPATH=/app \
    PYTHONUNBUFFERED=1 \
    SYNC_INTERVAL=600

# CWD == where caldav2google reads credentials.json / token.json and writes
# calendar_sync.json. We bind-mount a host dir here so state + token persist.
WORKDIR /data
ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
