import json
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path

LIBYA = timezone(timedelta(hours=2))


def now_iso():
    return datetime.now(LIBYA).isoformat(timespec="seconds")


SCHEMA = """
PRAGMA foreign_keys=ON;
CREATE TABLE IF NOT EXISTS settings(key TEXT PRIMARY KEY,value TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS admins(id INTEGER PRIMARY KEY,name TEXT NOT NULL,password TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS groups(id INTEGER PRIMARY KEY,name TEXT UNIQUE NOT NULL);
CREATE TABLE IF NOT EXISTS persons(
 id INTEGER PRIMARY KEY, code TEXT UNIQUE NOT NULL, name TEXT NOT NULL,
 group_id INTEGER NOT NULL REFERENCES groups(id), active INTEGER NOT NULL DEFAULT 1,
 consent_at TEXT NOT NULL, created_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS samples(
 id INTEGER PRIMARY KEY,person_id INTEGER NOT NULL REFERENCES persons(id) ON DELETE CASCADE,
 feature TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS sessions(
 id INTEGER PRIMARY KEY,title TEXT NOT NULL,group_id INTEGER NOT NULL REFERENCES groups(id),
 started_at TEXT NOT NULL,late_minutes INTEGER NOT NULL,closed_at TEXT);
CREATE TABLE IF NOT EXISTS roster(
 session_id INTEGER NOT NULL REFERENCES sessions(id),person_id INTEGER NOT NULL REFERENCES persons(id),
 PRIMARY KEY(session_id,person_id));
CREATE TABLE IF NOT EXISTS attendance(
 id INTEGER PRIMARY KEY,session_id INTEGER NOT NULL REFERENCES sessions(id),
 person_id INTEGER NOT NULL REFERENCES persons(id),recorded_at TEXT NOT NULL,
 status TEXT NOT NULL CHECK(status IN ('present','late')),method TEXT NOT NULL,
 score REAL, UNIQUE(session_id,person_id));
CREATE TABLE IF NOT EXISTS audit(
 id INTEGER PRIMARY KEY,at TEXT NOT NULL,action TEXT NOT NULL,detail TEXT NOT NULL);
"""


class Store:
    def __init__(self, path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self.connect() as db:
            db.executescript(SCHEMA)
            db.execute("INSERT OR IGNORE INTO settings VALUES('threshold','0.50')")
            db.execute("PRAGMA user_version=1")

    @contextmanager
    def connect(self):
        db = sqlite3.connect(self.path, timeout=15)
        db.row_factory = sqlite3.Row
        db.execute("PRAGMA foreign_keys=ON")
        try:
            yield db
            db.commit()
        except Exception:
            db.rollback()
            raise
        finally:
            db.close()

    def rows(self, sql, params=()):
        with self.connect() as db:
            return [dict(r) for r in db.execute(sql, params)]

    def one(self, sql, params=()):
        rows = self.rows(sql, params)
        return rows[0] if rows else None

    def audit(self, db, action, detail):
        db.execute("INSERT INTO audit(at,action,detail) VALUES(?,?,?)", (now_iso(),action,detail))

    def candidates(self, session_id=None, exclude=None):
        sql = "SELECT p.id,s.feature FROM persons p JOIN samples s ON s.person_id=p.id WHERE p.active=1"
        args = []
        if session_id is not None:
            sql += " AND p.id IN (SELECT person_id FROM roster WHERE session_id=?)"
            args.append(session_id)
        if exclude is not None:
            sql += " AND p.id!=?"
            args.append(exclude)
        result = {}
        for row in self.rows(sql, args):
            result.setdefault(row['id'], []).append(json.loads(row['feature']))
        return result

    def record(self, session_id, person_id, method, score=None, reason=""):
        stamp = now_iso()
        with self.connect() as db:
            # This write transaction serializes recording with session closure.
            db.execute("BEGIN IMMEDIATE")
            session = db.execute("SELECT * FROM sessions WHERE id=?", (session_id,)).fetchone()
            if not session or session['closed_at']:
                raise ValueError("الجلسة مغلقة أو غير موجودة")
            person = db.execute("SELECT * FROM persons WHERE id=? AND active=1", (person_id,)).fetchone()
            member = db.execute("SELECT 1 FROM roster WHERE session_id=? AND person_id=?", (session_id, person_id)).fetchone()
            if not person or not member:
                raise ValueError("الشخص ليس ضمن قائمة هذه الجلسة")
            late_at = datetime.fromisoformat(session['started_at']) + timedelta(minutes=session['late_minutes'])
            status = 'late' if datetime.fromisoformat(stamp) > late_at else 'present'
            cursor = db.execute("INSERT OR IGNORE INTO attendance(session_id,person_id,recorded_at,status,method,score) VALUES(?,?,?,?,?,?)",
                                (session_id,person_id,stamp,status,method,score))
            if cursor.rowcount:
                self.audit(db, 'attendance', f"session={session_id};person={person_id};method={method};reason={reason}")
            row = db.execute("SELECT * FROM attendance WHERE session_id=? AND person_id=?", (session_id,person_id)).fetchone()
            return dict(row), bool(cursor.rowcount)

    def report(self, session_id):
        return self.rows("""SELECT p.id,p.code,p.name,g.name AS group_name,p.active,
            COALESCE(a.status,'absent') AS status,a.id AS attendance_id,a.recorded_at,a.method,a.score
            FROM roster r JOIN persons p ON p.id=r.person_id JOIN groups g ON g.id=p.group_id
            LEFT JOIN attendance a ON a.person_id=p.id AND a.session_id=r.session_id
            WHERE r.session_id=? ORDER BY p.name""", (session_id,))

    def backup(self, target):
        with self.connect() as db:
            destination = sqlite3.connect(target)
            try:
                db.backup(destination)
            finally:
                destination.close()
