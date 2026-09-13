"""
AEGIS Mission Database — SQLite-backed storage for all mission data.
Tables: missions, findings, actions, evidence, iocs, credentials.
Every write is atomic and auditable.
"""
import sqlite3
import os
import csv
import json
import hashlib
from datetime import datetime


class MissionDB:
    def __init__(self, db_path):
        self.db_path = db_path
        os.makedirs(os.path.dirname(db_path) if os.path.dirname(db_path) else ".", exist_ok=True)
        self.conn = sqlite3.connect(db_path)
        self.conn.row_factory = sqlite3.Row
        self.conn.execute("PRAGMA journal_mode=WAL")
        self.conn.execute("PRAGMA foreign_keys=ON")
        self.create_tables()

    def create_tables(self):
        c = self.conn.cursor()
        c.executescript("""
            CREATE TABLE IF NOT EXISTS missions (
                id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                target TEXT NOT NULL,
                scope TEXT DEFAULT '',
                classification TEXT DEFAULT 'UNCLASSIFIED',
                status TEXT DEFAULT 'ACTIVE',
                operator TEXT DEFAULT 'darknode',
                created TEXT NOT NULL,
                updated TEXT NOT NULL,
                notes TEXT DEFAULT ''
            );
            CREATE TABLE IF NOT EXISTS findings (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                mission_id TEXT NOT NULL,
                severity TEXT NOT NULL,
                title TEXT NOT NULL,
                detail TEXT DEFAULT '',
                module TEXT DEFAULT '',
                mitre TEXT DEFAULT '',
                evidence_hash TEXT DEFAULT '',
                host TEXT DEFAULT '',
                port INTEGER DEFAULT 0,
                service TEXT DEFAULT '',
                cve TEXT DEFAULT '',
                cvss REAL DEFAULT 0.0,
                status TEXT DEFAULT 'OPEN',
                remediation TEXT DEFAULT '',
                created TEXT NOT NULL,
                FOREIGN KEY (mission_id) REFERENCES missions(id)
            );
            CREATE TABLE IF NOT EXISTS actions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                mission_id TEXT NOT NULL,
                command TEXT NOT NULL,
                output TEXT DEFAULT '',
                result TEXT DEFAULT '',
                operator TEXT DEFAULT 'darknode',
                module TEXT DEFAULT '',
                approved INTEGER DEFAULT 1,
                created TEXT NOT NULL,
                FOREIGN KEY (mission_id) REFERENCES missions(id)
            );
            CREATE TABLE IF NOT EXISTS evidence (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                mission_id TEXT NOT NULL,
                filename TEXT NOT NULL,
                sha256 TEXT NOT NULL,
                description TEXT DEFAULT '',
                source_module TEXT DEFAULT '',
                created TEXT NOT NULL,
                FOREIGN KEY (mission_id) REFERENCES missions(id)
            );
            CREATE TABLE IF NOT EXISTS iocs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                mission_id TEXT NOT NULL,
                ioc_type TEXT NOT NULL,
                value TEXT NOT NULL,
                context TEXT DEFAULT '',
                confidence TEXT DEFAULT 'medium',
                source TEXT DEFAULT '',
                created TEXT NOT NULL,
                FOREIGN KEY (mission_id) REFERENCES missions(id)
            );
            CREATE TABLE IF NOT EXISTS credentials (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                mission_id TEXT NOT NULL,
                service TEXT NOT NULL,
                host TEXT DEFAULT '',
                username TEXT NOT NULL,
                credential_type TEXT NOT NULL,
                value TEXT NOT NULL,
                source TEXT DEFAULT '',
                created TEXT NOT NULL,
                FOREIGN KEY (mission_id) REFERENCES missions(id)
            );
            CREATE INDEX IF NOT EXISTS idx_findings_mission ON findings(mission_id);
            CREATE INDEX IF NOT EXISTS idx_findings_severity ON findings(severity);
            CREATE INDEX IF NOT EXISTS idx_actions_mission ON actions(mission_id);
            CREATE INDEX IF NOT EXISTS idx_iocs_mission ON iocs(mission_id);
            CREATE INDEX IF NOT EXISTS idx_iocs_type ON iocs(ioc_type);
            CREATE INDEX IF NOT EXISTS idx_creds_mission ON credentials(mission_id);
        """)
        self.conn.commit()

    def _now(self):
        return datetime.utcnow().isoformat() + "Z"

    # --- Missions ---
    def create_mission(self, mission_id, name, target, scope="", classification="UNCLASSIFIED", operator="darknode"):
        now = self._now()
        self.conn.execute(
            "INSERT INTO missions (id, name, target, scope, classification, operator, created, updated) VALUES (?,?,?,?,?,?,?,?)",
            (mission_id, name, target, scope, classification, operator, now, now)
        )
        self.conn.commit()

    def get_mission(self, mission_id):
        row = self.conn.execute("SELECT * FROM missions WHERE id=?", (mission_id,)).fetchone()
        return dict(row) if row else None

    def list_missions(self):
        rows = self.conn.execute("SELECT * FROM missions ORDER BY created DESC").fetchall()
        return [dict(r) for r in rows]

    def update_mission_status(self, mission_id, status):
        self.conn.execute(
            "UPDATE missions SET status=?, updated=? WHERE id=?",
            (status, self._now(), mission_id)
        )
        self.conn.commit()

    def update_mission_notes(self, mission_id, notes):
        self.conn.execute(
            "UPDATE missions SET notes=?, updated=? WHERE id=?",
            (notes, self._now(), mission_id)
        )
        self.conn.commit()

    # --- Findings ---
    def add_finding(self, mission_id, severity, title, detail="", module="", mitre="",
                    evidence_hash="", host="", port=0, service="", cve="", cvss=0.0, remediation=""):
        self.conn.execute(
            """INSERT INTO findings (mission_id, severity, title, detail, module, mitre,
               evidence_hash, host, port, service, cve, cvss, remediation, created)
               VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (mission_id, severity, title, detail, module, mitre,
             evidence_hash, host, port, service, cve, cvss, remediation, self._now())
        )
        self.conn.commit()

    def get_findings(self, mission_id, severity=None, module=None):
        sql = "SELECT * FROM findings WHERE mission_id=?"
        params = [mission_id]
        if severity:
            sql += " AND severity=?"
            params.append(severity)
        if module:
            sql += " AND module=?"
            params.append(module)
        sql += " ORDER BY CASE severity WHEN 'CRITICAL' THEN 0 WHEN 'HIGH' THEN 1 WHEN 'MEDIUM' THEN 2 WHEN 'LOW' THEN 3 ELSE 4 END, created DESC"
        return [dict(r) for r in self.conn.execute(sql, params).fetchall()]

    def update_finding_status(self, finding_id, status):
        self.conn.execute("UPDATE findings SET status=? WHERE id=?", (status, finding_id))
        self.conn.commit()

    # --- Actions ---
    def add_action(self, mission_id, command, output="", result="", operator="darknode", module="", approved=True):
        self.conn.execute(
            """INSERT INTO actions (mission_id, command, output, result, operator, module, approved, created)
               VALUES (?,?,?,?,?,?,?,?)""",
            (mission_id, command, output, result, operator, module, 1 if approved else 0, self._now())
        )
        self.conn.commit()

    def get_actions(self, mission_id):
        return [dict(r) for r in self.conn.execute(
            "SELECT * FROM actions WHERE mission_id=? ORDER BY created ASC", (mission_id,)
        ).fetchall()]

    # --- Evidence ---
    def add_evidence(self, mission_id, filename, sha256, description="", source_module=""):
        self.conn.execute(
            "INSERT INTO evidence (mission_id, filename, sha256, description, source_module, created) VALUES (?,?,?,?,?,?)",
            (mission_id, filename, sha256, description, source_module, self._now())
        )
        self.conn.commit()

    def get_evidence(self, mission_id):
        return [dict(r) for r in self.conn.execute(
            "SELECT * FROM evidence WHERE mission_id=? ORDER BY created ASC", (mission_id,)
        ).fetchall()]

    # --- IOCs ---
    def add_ioc(self, mission_id, ioc_type, value, context="", confidence="medium", source=""):
        existing = self.conn.execute(
            "SELECT id FROM iocs WHERE mission_id=? AND ioc_type=? AND value=?",
            (mission_id, ioc_type, value)
        ).fetchone()
        if existing:
            return
        self.conn.execute(
            "INSERT INTO iocs (mission_id, ioc_type, value, context, confidence, source, created) VALUES (?,?,?,?,?,?,?)",
            (mission_id, ioc_type, value, context, confidence, source, self._now())
        )
        self.conn.commit()

    def get_iocs(self, mission_id, ioc_type=None):
        sql = "SELECT * FROM iocs WHERE mission_id=?"
        params = [mission_id]
        if ioc_type:
            sql += " AND ioc_type=?"
            params.append(ioc_type)
        sql += " ORDER BY created DESC"
        return [dict(r) for r in self.conn.execute(sql, params).fetchall()]

    # --- Credentials ---
    def add_credential(self, mission_id, service, username, credential_type, value, host="", source=""):
        self.conn.execute(
            """INSERT INTO credentials (mission_id, service, host, username, credential_type, value, source, created)
               VALUES (?,?,?,?,?,?,?,?)""",
            (mission_id, service, host, username, credential_type, value, source, self._now())
        )
        self.conn.commit()

    def get_credentials(self, mission_id):
        return [dict(r) for r in self.conn.execute(
            "SELECT * FROM credentials WHERE mission_id=? ORDER BY created DESC", (mission_id,)
        ).fetchall()]

    # --- Statistics ---
    def get_stats(self, mission_id):
        stats = {}
        for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
            row = self.conn.execute(
                "SELECT COUNT(*) as cnt FROM findings WHERE mission_id=? AND severity=?",
                (mission_id, sev)
            ).fetchone()
            stats[sev.lower()] = row["cnt"] if row else 0
        stats["total_findings"] = sum(stats.values())
        row = self.conn.execute("SELECT COUNT(*) as cnt FROM actions WHERE mission_id=?", (mission_id,)).fetchone()
        stats["actions"] = row["cnt"] if row else 0
        row = self.conn.execute("SELECT COUNT(*) as cnt FROM iocs WHERE mission_id=?", (mission_id,)).fetchone()
        stats["iocs"] = row["cnt"] if row else 0
        row = self.conn.execute("SELECT COUNT(*) as cnt FROM credentials WHERE mission_id=?", (mission_id,)).fetchone()
        stats["credentials"] = row["cnt"] if row else 0
        row = self.conn.execute("SELECT COUNT(*) as cnt FROM evidence WHERE mission_id=?", (mission_id,)).fetchone()
        stats["evidence"] = row["cnt"] if row else 0
        return stats

    # --- Export ---
    def export_findings_csv(self, mission_id, path):
        findings = self.get_findings(mission_id)
        if not findings:
            return False
        with open(path, "w", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=findings[0].keys())
            writer.writeheader()
            writer.writerows(findings)
        return True

    def export_iocs_csv(self, mission_id, path):
        iocs = self.get_iocs(mission_id)
        if not iocs:
            return False
        with open(path, "w", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=iocs[0].keys())
            writer.writeheader()
            writer.writerows(iocs)
        return True

    def close(self):
        self.conn.close()

    @staticmethod
    def hash_file(filepath):
        h = hashlib.sha256()
        with open(filepath, "rb") as f:
            for chunk in iter(lambda: f.read(8192), b""):
                h.update(chunk)
        return h.hexdigest()
