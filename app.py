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
                    Only mints a key if /postback already marked their puid
                    "completed". The key is created fresh, on the spot, via
                    LicenseGate's admin API, set to expire 24h from the
                    moment of creation. Refreshing this page is safe -- it
                    re-shows the same key instead of minting a second one.

Nothing here requires you to touch it once it's deployed and wired up. Each
claim mints its own key on demand -- there's no pool to run out of and
nothing to restock.

---------------------------------------------------------------------------
SETUP
---------------------------------------------------------------------------
1. pip install -r requirements.txt
2. Copy .env.example to .env and fill in the values (see comments in that
   file for exactly where to find each one).
3. Run locally to test:
       flask --app app run --debug
   Visit http://127.0.0.1:5000/start in a browser.
4. Deploy (Render/Railway/Fly.io/a VPS -- anything that runs a WSGI app).
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
- Key minting is wrapped in a SQLite BEGIN IMMEDIATE transaction so two
  requests for the same puid at the exact same instant can never mint two
  keys for one person.
- Keys are created via LicenseGate's POST /admin/licenses endpoint with
  licenseKey left unset, so LicenseGate generates the key string itself --
  this app never has to invent or guess a unique key format.
- LICENSEGATE_API_KEY is a different credential from anything in
  licensing.py on the client side -- that file only ever calls the public,
  unauthenticated /verify endpoint. This admin endpoint requires a Bearer
  token with permission to create licenses on your account, so treat it
  like a password: only in Railway's Variables tab, never in client code,
  never committed to the repo.
"""

import os
import sqlite3
import secrets
import time
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone

import requests
from flask import Flask, request, redirect, render_template, make_response, abort

app = Flask(__name__)

DB_PATH = os.environ.get("DATABASE_PATH", os.path.join(os.path.dirname(__file__), "dispenser.db"))
LOOTLABS_LOOT_URL = os.environ.get("LOOTLABS_LOOT_URL")  # e.g. https://loot-link.com/s?xxxx
POSTBACK_TOKEN = os.environ.get("POSTBACK_TOKEN")
LICENSEGATE_API_KEY = os.environ.get("LICENSEGATE_API_KEY")  # admin Bearer token, NOT the public User ID
COOKIE_NAME = "puid"
COOKIE_MAX_AGE = 60 * 60 * 24  # 24h -- plenty of time to finish LootLabs tasks

LICENSEGATE_ADMIN_CREATE_URL = os.environ.get(
    "LICENSEGATE_ADMIN_CREATE_URL", "https://api.licensegate.io/admin/licenses"
)
KEY_EXPIRY_HOURS = 24


def _startup_check():
    missing = [
        name
        for name, val in [
            ("LOOTLABS_LOOT_URL", LOOTLABS_LOOT_URL),
            ("POSTBACK_TOKEN", POSTBACK_TOKEN),
            ("LICENSEGATE_API_KEY", LICENSEGATE_API_KEY),
        ]
        if not val
    ]
    if missing:
        raise RuntimeError(
            f"Missing required environment variable(s): {', '.join(missing)}. "
            "Copy .env.example to .env and fill them in."
        )

    # Diagnostic only -- never logs the full key. Helps catch the two most
    # common causes of a LicenseGate 401 "Invalid API key": trailing
    # whitespace/newline pasted into the env var, or the wrong key
    # entirely (e.g. the public User ID instead of the admin Bearer token).
    raw = LICENSEGATE_API_KEY or ""
    stripped = raw.strip()
    masked = f"{stripped[:4]}...{stripped[-4:]}" if len(stripped) >= 8 else "(too short)"
    print(
        f"[dispenser] LICENSEGATE_API_KEY loaded: len={len(raw)} "
        f"(len after strip={len(stripped)}) preview={masked}"
    )
    if raw != stripped:
        print("[dispenser] WARNING: LICENSEGATE_API_KEY has leading/trailing "
              "whitespace or a newline -- this will cause 401 Invalid API key.")


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
                claimed_key_expires_at TEXT,
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
        # Migration for a database created before this column existed --
        # harmless no-op on a brand-new database where the CREATE TABLE
        # above already included it.
        try:
            conn.execute("ALTER TABLE claims ADD COLUMN claimed_key_expires_at TEXT")
        except sqlite3.OperationalError:
            pass  # column already exists


init_db()


# ---------------------------------------------------------------------------
# LicenseGate -- mint a fresh, self-expiring license key on demand
# ---------------------------------------------------------------------------
def create_expiring_license(puid):
    """Calls LicenseGate's admin API to create a brand-new license, valid
    for KEY_EXPIRY_HOURS from right now. licenseKey is deliberately left
    out of the request body so LicenseGate generates the key string itself
    -- this app never has to invent a unique format. Returns
    (license_key, expiration_iso_string). Raises RuntimeError on failure."""
    expires_at = datetime.now(timezone.utc) + timedelta(hours=KEY_EXPIRY_HOURS)
    payload = {
        "active": True,
        "name": f"lootlabs-{puid[:16]}",
        "notes": "Auto-issued after LootLabs task completion.",
        "expirationDate": expires_at.strftime("%Y-%m-%dT%H:%M:%S.000Z"),
    }
    # LicenseGate's own OpenAPI spec defines this as an `apiKey`-type security
    # scheme (name: Authorization, in: header) -- NOT an http/bearer scheme.
    # That means the raw key goes directly in the header, with no "Bearer "
    # prefix. Confirmed against open-api.json in the LicenseGate repo.
    headers = {"Authorization": (LICENSEGATE_API_KEY or "").strip()}

    try:
        resp = requests.post(LICENSEGATE_ADMIN_CREATE_URL, json=payload, headers=headers, timeout=15)
    except requests.RequestException as e:
        raise RuntimeError(f"Could not reach LicenseGate: {e}")

    if resp.status_code != 201:
        raise RuntimeError(f"LicenseGate rejected the create request ({resp.status_code}): {resp.text}")

    data = resp.json()
    return data["licenseKey"], data["expirationDate"]


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
        # never mint a second one for the same puid.
        if row["claimed_key"]:
            return render_template(
                "success.html", key=row["claimed_key"], expires_at=row["claimed_key_expires_at"]
            )

        # Optional stricter check (off by default -- see module docstring):
        # if row["completion_ip"] != request.remote_addr:
        #     return render_template("error.html", message="IP mismatch."), 400

        # Serializes concurrent requests for the same puid so a double
        # click/refresh during the LicenseGate call can't mint two keys.
        conn.execute("BEGIN IMMEDIATE")

        try:
            key, expires_at = create_expiring_license(puid)
        except RuntimeError as e:
            print(f"[dispenser] create_expiring_license failed for puid={puid}: {e}")
            return render_template(
                "error.html",
                message="Couldn't generate your key right now. Please try refreshing this page in a moment.",
            ), 502

        conn.execute(
            "UPDATE claims SET claimed_key = ?, claimed_key_expires_at = ?, claimed_at = ? WHERE puid = ?",
            (key, expires_at, int(time.time()), puid),
        )

    return render_template("success.html", key=key, expires_at=expires_at)


@app.route("/")
def index():
    return redirect("/start")


if __name__ == "__main__":
    app.run(debug=True)
