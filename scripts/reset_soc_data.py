#!/usr/bin/env python3
"""
TGAM-SOC Database & Telemetry Reset Utility
Clears all temporary attack data, incidents, events, MITRE mappings,
and test telemetry endpoints/commands, restoring a pristine state.
"""

import os
import sys
import sqlite3

# Set workspace root
WORKSPACE_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
BACKEND_DIR = os.path.join(WORKSPACE_ROOT, "SOC", "backend")
DB_PATH = os.path.join(BACKEND_DIR, "soc_central.db")
LEGACY_DB = os.path.join(BACKEND_DIR, "soc.db")
WIN_LOG = os.path.join(WORKSPACE_ROOT, "windows-telemetry", "agent.log")
WIN_PID = os.path.join(WORKSPACE_ROOT, "windows-telemetry", ".agent.pid")

sys.path.insert(0, BACKEND_DIR)

if hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(encoding='utf-8')

def reset_all_data():
    print("=" * 65)
    print("  TGAM-SOC: RESET TEMPORARY ATTACK & TELEMETRY DATA")
    print("=" * 65)

    counts = {}
    if os.path.exists(DB_PATH):
        try:
            conn = sqlite3.connect(DB_PATH)
            cur = conn.cursor()
            tables = [t[0] for t in cur.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()]
            for tbl in tables:
                if not tbl.startswith("sqlite_"):
                    try:
                        c = cur.execute(f"SELECT COUNT(*) FROM {tbl}").fetchone()[0]
                        counts[tbl] = c
                    except Exception:
                        pass
            conn.close()
        except Exception as e:
            print(f"  [!] Warning inspecting DB: {e}")

    # Remove database file and any journal/wal files
    for path in [DB_PATH, f"{DB_PATH}-wal", f"{DB_PATH}-shm", LEGACY_DB]:
        if os.path.exists(path):
            try:
                os.remove(path)
                print(f"  [OK] Removed database file: {os.path.basename(path)}")
            except Exception as e:
                print(f"  [!] Could not remove {path}: {e}")

    # Re-initialize clean schema
    os.chdir(BACKEND_DIR)
    from app.database import init_db
    init_db()
    print("  [OK] Recreated pristine SOC central database with empty schema.")

    # Reset windows telemetry logs/pid if present
    if os.path.exists(WIN_LOG):
        try:
            with open(WIN_LOG, "w") as f:
                f.write("")
            print("  [OK] Cleared windows-telemetry agent.log")
        except Exception:
            pass

    if os.path.exists(WIN_PID):
        try:
            os.remove(WIN_PID)
            print("  [OK] Removed windows-telemetry .agent.pid")
        except Exception:
            pass

    # Summary report
    print("\n  Summary of cleared records:")
    print("  ---------------------------------------------")
    if counts:
        for tbl, cnt in counts.items():
            print(f"    - {tbl:<25}: {cnt:>4} cleared")
    else:
        print("    (No prior records found)")
    print("  ---------------------------------------------")
    print("  [SUCCESS] Central SOC database and telemetry devices successfully cleared!\n")

if __name__ == "__main__":
    reset_all_data()
