"""
Import a batch of pre-generated LicenseGate license keys into the dispenser's
local pool.

Usage:
    python import_keys.py keys.txt

keys.txt should have one license key per line (whatever you bulk-created in
the LicenseGate dashboard). Blank lines and lines starting with # are
skipped. Already-imported keys (same key string) are skipped automatically,
so it's safe to re-run this with an updated file.

This is a command-line script on purpose, not a web route -- key management
shouldn't be reachable over HTTP at all.
"""

import os
import sqlite3
import sys

DB_PATH = os.environ.get("DATABASE_PATH", os.path.join(os.path.dirname(__file__), "dispenser.db"))


def main():
    if len(sys.argv) != 2:
        print("Usage: python import_keys.py keys.txt")
        sys.exit(1)

    path = sys.argv[1]
    if not os.path.exists(path):
        print(f"File not found: {path}")
        sys.exit(1)

    with open(path) as f:
        keys = [line.strip() for line in f if line.strip() and not line.strip().startswith("#")]

    if not keys:
        print("No keys found in file.")
        sys.exit(1)

    conn = sqlite3.connect(DB_PATH)
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

    added = 0
    skipped = 0
    for key in keys:
        try:
            conn.execute("INSERT INTO keys (key, issued) VALUES (?, 0)", (key,))
            added += 1
        except sqlite3.IntegrityError:
            skipped += 1  # already imported

    conn.commit()

    remaining = conn.execute("SELECT COUNT(*) FROM keys WHERE issued = 0").fetchone()[0]
    total = conn.execute("SELECT COUNT(*) FROM keys").fetchone()[0]
    conn.close()

    print(f"Added {added} new key(s), skipped {skipped} duplicate(s).")
    print(f"Pool status: {remaining} unclaimed / {total} total.")


if __name__ == "__main__":
    main()
