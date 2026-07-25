"""
LootLabs -> LicenseGate key dispenser
======================================
Three routes:

  GET /start     - visitor lands here, gets a one-time id (puid), gets sent
                    to your LootLabs link with that id attached.
  GET /postback   - LootLabs' SERVER calls this (not the user's browser)
                    the moment tasks are actually completed. This is the
                    trusted signal -- nothing here is decided based on
                    what the user's browser tells us.
  GET /claim      - user's browser lands here after LootLabs redirects them.
                    Only hands out a key if /postback already marked their
                    puid "completed". Refreshing this page is safe -- it
                    re-shows the same key instead of burning a second one.

Nothing here requires you to touch it once it's deployed and wired up.

---------------------------------------------------------------------------
SETUP
---------------------------------------------------------------------------
1. pip install -r requirements.txt
2. Copy .env.example to .env and fill in the four values (see comments in
   that file for exactly where to find each one).
3. Import a batch of pre-generated LicenseGate keys:
       python import_keys.py keys.txt      (one key per line)
   Bulk-create those keys in the LicenseGate dashboard first, export/copy
   them into keys.txt, then run the import.
4. Run locally to test:
       flask --app app run --debug
   Visit http://127.0.0.1:5000/start in a browser.
5. Deploy (Render/Railway/Fly.io/a VPS -- anything that runs a WSGI app).
   Point LootLabs' Postback setting (Advanced tab) at:
       https://your-deployed-domain.com/postback?token=<POSTBACK_TOKEN>
   and set your Monetized Link's Destination URL to:
       https://your-deployed-domain.com/claim
   The link you actually hand out to users/customers is:
       https://your-deployed-domain.com/start
   (not the raw loot-link.com URL -- /start is what attaches their puid
   before sending them into LootLabs' flow.)

---------------------------------------------------------------------------
NOTES ON THE DESIGN CHOICES
---------------------------------------------------------------------------
- The POSTBACK_TOKEN isn't something LootLabs sends you or asks for -- it's
  a random secret YOU make up and paste into the postback URL field in
  LootLabs' dashboard yourself, as part of the URL. LootLabs will just
  call whatever URL you configured, token included, then append its own
  click_id/ip/unique_id params after it. Since LootLabs doesn't document
  any authentication on the postback call itself, this token is what stops
  a stranger from finding your /postback endpoint and POSTing fake
  "completed" events to mint themselves free keys.
- /claim does NOT hard-require the completion IP to match the claiming
  browser's IP, even though LootLabs sends the completion IP. Mobile users
  routinely switch between WiFi and cellular mid-session, which would
  cause real users to get falsely blocked. The completion IP is still
  logged per-claim so you can eyeball obvious abuse patterns later. If you
  want strict IP-locking, see the commented-out check in claim().
- Key issuance is wrapped in a SQLite BEGIN IMMEDIATE transaction so two
  people claiming at the exact same instant can never be handed the same
  key.
"""

import os
import sqlite3
import secrets
import time
from contextlib import contextmanager
from urllib.parse import urlencode

from flask import Flask, request, redirect, render_template, make_response, abort

app = Flask(__name__)

DB_PATH = os.environ.get("DATABASE_PATH", os.path.join(os.path.dirname(__file__), "dispenser.db"))
LOOTLABS_LOOT_URL = os.environ.get("LOOTLABS_LOOT_URL")  # e.g. https://loot-link.com/s?xxxx
POSTBACK_TOKEN = os.environ.get("POSTBACK_TOKEN")
COOKIE_NAME = "puid"
COOKIE_MAX_AGE = 60 * 60 * 24  # 24h -- plenty of time to finish LootLabs tasks


def _startup_check():
    missing = [
        name
        for name, val in [
            ("LOOTLABS_LOOT_URL", LOOTLABS_LOOT_URL),
            ("POSTBACK_TOKEN", POSTBACK_TOKEN),
        ]
        if not val
    ]
    if missing:
        raise RuntimeError(
            f"Missing required environment variable(s): {', '.join(missing)}. "
            "Copy .env.example to .env and fill them in."
        )


_startup_check()


# ---------------------------------------------------------------------------
# Storage
# ---------------------------------------------------------------------------
@contextmanager
def db():
    conn = sqlite3.connect(DB_PATH, timeout=10)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    try:
        yield conn
        conn.commit()
    finally:
        conn.close()


def init_db():
    with db() as conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS claims (
                puid TEXT PRIMARY KEY,
                start_ip TEXT,
                created_at INTEGER,
                status TEXT NOT NULL DEFAULT 'pending',   -- pending | completed
                completion_ip TEXT,
                completed_at INTEGER,
                claimed_key TEXT,
                claimed_at INTEGER
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS processed_postbacks (
                unique_id TEXT PRIMARY KEY,
                received_at INTEGER
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS keys (
                key TEXT PRIMARY KEY,
                issued INTEGER NOT NULL DEFAULT 0,
                issued_to_puid TEXT,
                issued_at INTEGER
            )
            """
        )


init_db()


# ---------------------------------------------------------------------------
# /start -- issue a puid, send the visitor into the LootLabs flow
# ---------------------------------------------------------------------------
@app.route("/start")
def start():
    puid = secrets.token_urlsafe(24)
    with db() as conn:
        conn.execute(
            "INSERT INTO claims (puid, start_ip, created_at, status) VALUES (?, ?, ?, 'pending')",
            (puid, request.remote_addr, int(time.time())),
        )

    separator = "&" if "?" in LOOTLABS_LOOT_URL else "?"
    loot_url = f"{LOOTLABS_LOOT_URL}{separator}puid={puid}"

    resp = make_response(redirect(loot_url, code=302))
    resp.set_cookie(
        COOKIE_NAME,
        puid,
        max_age=COOKIE_MAX_AGE,
        httponly=True,
        samesite="Lax",
        secure=request.is_secure,
    )
    return resp


# ---------------------------------------------------------------------------
# /postback -- LootLabs' server calls this. This is the only place that is
# allowed to mark a claim "completed".
# ---------------------------------------------------------------------------
@app.route("/postback")
def postback():
    token = request.args.get("token", "")
    if not secrets.compare_digest(token, POSTBACK_TOKEN or ""):
        abort(403)

    puid = request.args.get("click_id")
    completion_ip = request.args.get("ip")
    unique_id = request.args.get("unique_id")

    if not puid or not unique_id:
        return "missing parameters", 400

    with db() as conn:
        # Dedupe: if LootLabs retries the same postback, only process once.
        try:
            conn.execute(
                "INSERT INTO processed_postbacks (unique_id, received_at) VALUES (?, ?)",
                (unique_id, int(time.time())),
            )
        except sqlite3.IntegrityError:
            return "OK (duplicate, ignored)"

        row = conn.execute("SELECT puid FROM claims WHERE puid = ?", (puid,)).fetchone()
        if row is None:
            # Someone completed tasks with a puid we never issued via /start.
            return "OK (unknown puid, ignored)"

        conn.execute(
            "UPDATE claims SET status = 'completed', completion_ip = ?, completed_at = ? WHERE puid = ?",
            (completion_ip, int(time.time()), puid),
        )

    return "OK"


# ---------------------------------------------------------------------------
# /claim -- user's browser lands here after LootLabs redirects them.
# ---------------------------------------------------------------------------
@app.route("/claim")
def claim():
    puid = request.cookies.get(COOKIE_NAME)
    if not puid:
        return render_template("error.html", message="No session found. Please start again."), 400

    with db() as conn:
        row = conn.execute("SELECT * FROM claims WHERE puid = ?", (puid,)).fetchone()
        if row is None:
            return render_template("error.html", message="Session not recognized. Please start again."), 400

        if row["status"] != "completed":
            separator = "&" if "?" in LOOTLABS_LOOT_URL else "?"
            resume_url = f"{LOOTLABS_LOOT_URL}{separator}puid={puid}"
            return render_template("pending.html", resume_url=resume_url)

        # Already claimed earlier (e.g. page refresh) -- show the same key,
        # never issue a second one for the same puid.
        if row["claimed_key"]:
            return render_template("success.html", key=row["claimed_key"])

        # Optional stricter check (off by default -- see module docstring):
        # if row["completion_ip"] != request.remote_addr:
        #     return render_template("error.html", message="IP mismatch."), 400

        # Atomically claim one unused key.
        conn.execute("BEGIN IMMEDIATE")
        key_row = conn.execute("SELECT key FROM keys WHERE issued = 0 LIMIT 1").fetchone()
        if key_row is None:
            return render_template(
                "error.html",
                message="All keys are currently claimed. Contact support to get one issued manually.",
            ), 503

        key = key_row["key"]
        conn.execute(
            "UPDATE keys SET issued = 1, issued_to_puid = ?, issued_at = ? WHERE key = ?",
            (puid, int(time.time()), key),
        )
        conn.execute(
            "UPDATE claims SET claimed_key = ?, claimed_at = ? WHERE puid = ?",
            (key, int(time.time()), puid),
        )

    return render_template("success.html", key=key)


@app.route("/")
def index():
    return redirect("/start")


if __name__ == "__main__":
    app.run(debug=True)
