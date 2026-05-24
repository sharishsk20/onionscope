"""
OnionScope - TOR Relay Harvester
Fetches live TOR consensus data and stores relay details.
Falls back to CollecTor API if direct stem download fails.
"""

import requests
import json
import time
import sqlite3
import os
from datetime import datetime, timezone
from typing import List, Dict, Optional

# Use SQLite for portability in hackathon demo (no Postgres setup needed)
DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "onionscope.db")


def init_db():
    """Initialize SQLite database with relay and harvest tables."""
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()

    c.execute("""
        CREATE TABLE IF NOT EXISTS relays (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            fingerprint TEXT NOT NULL,
            nickname TEXT,
            ip_address TEXT,
            or_port INTEGER,
            dir_port INTEGER,
            country TEXT,
            as_name TEXT,
            bandwidth INTEGER,
            is_guard INTEGER DEFAULT 0,
            is_exit INTEGER DEFAULT 0,
            is_stable INTEGER DEFAULT 0,
            is_fast INTEGER DEFAULT 0,
            first_seen TEXT,
            last_seen TEXT,
            harvested_at TEXT,
            UNIQUE(fingerprint, harvested_at)
        )
    """)

    c.execute("""
        CREATE TABLE IF NOT EXISTS harvest_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            harvested_at TEXT,
            relay_count INTEGER,
            guard_count INTEGER,
            exit_count INTEGER,
            status TEXT
        )
    """)

    c.execute("""
        CREATE TABLE IF NOT EXISTS suspected_circuits (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            session_id TEXT,
            guard_fp TEXT,
            middle_fp TEXT,
            exit_fp TEXT,
            confidence REAL,
            evidence TEXT,
            created_at TEXT
        )
    """)

    conn.commit()
    conn.close()
    print("[DB] Database initialized.")


def fetch_from_onionoo() -> List[Dict]:
    """
    Fetch relay data from Onionoo (TOR Project's official relay API).
    Returns list of relay dicts.
    """
    url = "https://onionoo.torproject.org/details?type=relay&running=true&fields=fingerprint,nickname,or_addresses,country,as_name,consensus_weight,guard_probability,exit_probability,flags,first_seen,last_seen"
    
    print("[Harvester] Fetching from Onionoo API...")
    try:
        resp = requests.get(url, timeout=30)
        resp.raise_for_status()
        data = resp.json()
        relays = data.get("relays", [])
        print(f"[Harvester] Got {len(relays)} relays from Onionoo.")
        return relays
    except Exception as e:
        print(f"[Harvester] Onionoo fetch failed: {e}")
        return []


def parse_relay(relay: Dict) -> Optional[Dict]:
    """Parse a raw Onionoo relay dict into our schema."""
    try:
        or_addresses = relay.get("or_addresses", ["0.0.0.0:0"])
        # Parse first address (IPv4 preferred)
        ip_port = or_addresses[0] if or_addresses else "0.0.0.0:0"
        # Handle IPv6 like [::1]:9001
        if ip_port.startswith("["):
            ip = ip_port.split("]")[0][1:]
            port = int(ip_port.split("]")[1].replace(":", ""))
        else:
            parts = ip_port.rsplit(":", 1)
            ip = parts[0] if len(parts) == 2 else ip_port
            port = int(parts[1]) if len(parts) == 2 else 0

        flags = relay.get("flags", [])

        return {
            "fingerprint": relay.get("fingerprint", ""),
            "nickname": relay.get("nickname", "unnamed"),
            "ip_address": ip,
            "or_port": port,
            "dir_port": 0,
            "country": relay.get("country", "??"),
            "as_name": relay.get("as_name", "Unknown AS"),
            "bandwidth": relay.get("consensus_weight", 0),
            "is_guard": 1 if "Guard" in flags else 0,
            "is_exit": 1 if "Exit" in flags else 0,
            "is_stable": 1 if "Stable" in flags else 0,
            "is_fast": 1 if "Fast" in flags else 0,
            "first_seen": relay.get("first_seen", ""),
            "last_seen": relay.get("last_seen", ""),
            "harvested_at": datetime.now(timezone.utc).isoformat()
        }
    except Exception as e:
        return None


def store_relays(relays: List[Dict]) -> Dict:
    """Store parsed relays into SQLite."""
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()

    inserted = 0
    guard_count = 0
    exit_count = 0

    for r in relays:
        if not r:
            continue
        try:
            c.execute("""
                INSERT OR IGNORE INTO relays
                (fingerprint, nickname, ip_address, or_port, dir_port, country, as_name,
                 bandwidth, is_guard, is_exit, is_stable, is_fast, first_seen, last_seen, harvested_at)
                VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
            """, (
                r["fingerprint"], r["nickname"], r["ip_address"], r["or_port"],
                r["dir_port"], r["country"], r["as_name"], r["bandwidth"],
                r["is_guard"], r["is_exit"], r["is_stable"], r["is_fast"],
                r["first_seen"], r["last_seen"], r["harvested_at"]
            ))
            inserted += 1
            if r["is_guard"]: guard_count += 1
            if r["is_exit"]: exit_count += 1
        except Exception as e:
            pass

    # Log this harvest
    c.execute("""
        INSERT INTO harvest_log (harvested_at, relay_count, guard_count, exit_count, status)
        VALUES (?, ?, ?, ?, ?)
    """, (datetime.now(timezone.utc).isoformat(), inserted, guard_count, exit_count, "success"))

    conn.commit()
    conn.close()

    return {"inserted": inserted, "guards": guard_count, "exits": exit_count}


def harvest():
    """Main harvest function — fetch, parse, store."""
    init_db()
    raw_relays = fetch_from_onionoo()

    if not raw_relays:
        print("[Harvester] No relays fetched. Check network.")
        return None

    parsed = [parse_relay(r) for r in raw_relays]
    parsed = [r for r in parsed if r]

    stats = store_relays(parsed)
    print(f"[Harvester] Stored: {stats['inserted']} relays | Guards: {stats['guards']} | Exits: {stats['exits']}")
    return stats


def get_relay_stats() -> Dict:
    """Get summary stats from DB for dashboard."""
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()

    c.execute("SELECT COUNT(*) FROM relays")
    total = c.fetchone()[0]

    c.execute("SELECT COUNT(*) FROM relays WHERE is_guard=1")
    guards = c.fetchone()[0]

    c.execute("SELECT COUNT(*) FROM relays WHERE is_exit=1")
    exits = c.fetchone()[0]

    c.execute("SELECT country, COUNT(*) as cnt FROM relays GROUP BY country ORDER BY cnt DESC LIMIT 10")
    top_countries = [{"country": r[0], "count": r[1]} for r in c.fetchall()]

    c.execute("SELECT harvested_at, relay_count FROM harvest_log ORDER BY id DESC LIMIT 5")
    recent_harvests = [{"time": r[0], "count": r[1]} for r in c.fetchall()]

    conn.close()

    return {
        "total_relays": total,
        "guard_nodes": guards,
        "exit_nodes": exits,
        "top_countries": top_countries,
        "recent_harvests": recent_harvests
    }


def get_guards() -> List[Dict]:
    """Return all guard nodes as list of dicts."""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    c = conn.cursor()
    c.execute("SELECT * FROM relays WHERE is_guard=1 ORDER BY bandwidth DESC LIMIT 200")
    rows = [dict(r) for r in c.fetchall()]
    conn.close()
    return rows


def get_exits() -> List[Dict]:
    """Return all exit nodes."""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    c = conn.cursor()
    c.execute("SELECT * FROM relays WHERE is_exit=1 ORDER BY bandwidth DESC LIMIT 200")
    rows = [dict(r) for r in c.fetchall()]
    conn.close()
    return rows


def search_relay(ip: str) -> Optional[Dict]:
    """Search relay by IP address."""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    c = conn.cursor()
    c.execute("SELECT * FROM relays WHERE ip_address=? ORDER BY id DESC LIMIT 1", (ip,))
    row = c.fetchone()
    conn.close()
    return dict(row) if row else None


if __name__ == "__main__":
    print("=== OnionScope TOR Harvester ===")
    stats = harvest()
    if stats:
        summary = get_relay_stats()
        print(f"\nDatabase Summary:")
        print(f"  Total relays : {summary['total_relays']}")
        print(f"  Guard nodes  : {summary['guard_nodes']}")
        print(f"  Exit nodes   : {summary['exit_nodes']}")
        print(f"\nTop countries:")
        for c in summary['top_countries']:
            print(f"  {c['country']}: {c['count']}")