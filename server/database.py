"""
SQLite database (built into Python, nothing to install).

The file is created automatically at server/data/attendance.db.
"""

import sqlite3
from contextlib import contextmanager
from pathlib import Path

DATA_DIR = Path(__file__).parent / "data"
UPLOAD_DIR = DATA_DIR / "uploads"
DB_PATH = DATA_DIR / "attendance.db"

UPLOAD_DIR.mkdir(parents=True, exist_ok=True)

SCHEMA = """
CREATE TABLE IF NOT EXISTS classes (
    id          TEXT PRIMARY KEY,           -- FY, SY-A, SY-B, TY-A, TY-B, BTECH
    label       TEXT NOT NULL,
    year        TEXT NOT NULL,
    division    TEXT NOT NULL,
    coordinator TEXT
);

CREATE TABLE IF NOT EXISTS users (
    id                   TEXT PRIMARY KEY,
    role                 TEXT NOT NULL CHECK (role IN ('student', 'faculty')),
    name                 TEXT NOT NULL,
    email                TEXT UNIQUE,       -- optional for students (the list has no emails)
    password_hash        TEXT NOT NULL,
    prn                  TEXT UNIQUE,
    roll_no              INTEGER,
    class_id             TEXT REFERENCES classes(id),
    designation          TEXT,
    must_change_password INTEGER NOT NULL DEFAULT 0,
    created_at           TEXT NOT NULL
);

-- Which classes a faculty member coordinates. No rows = sees every class (HoD).
CREATE TABLE IF NOT EXISTS faculty_classes (
    faculty_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    class_id   TEXT NOT NULL REFERENCES classes(id),
    PRIMARY KEY (faculty_id, class_id)
);

-- Old: ERP attendance typed in by students. No longer used (coordinators import it now).
CREATE TABLE IF NOT EXISTS erp_attendance (
    student_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    course_id  TEXT NOT NULL,
    attended   INTEGER NOT NULL,
    total      INTEGER NOT NULL,
    updated_at TEXT NOT NULL,
    PRIMARY KEY (student_id, course_id)
);

CREATE TABLE IF NOT EXISTS applications (
    id            TEXT PRIMARY KEY,
    student_id    TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    class_id      TEXT NOT NULL,
    kind          TEXT NOT NULL CHECK (kind IN ('event', 'medical')),
    category      TEXT NOT NULL,
    event_name    TEXT NOT NULL,
    description   TEXT NOT NULL DEFAULT '',
    start_date    TEXT NOT NULL,
    end_date      TEXT NOT NULL,
    lectures      TEXT NOT NULL,            -- JSON list of affected lectures
    evidence_type TEXT NOT NULL,            -- certificate / authority_permission / medical_certificate
    status        TEXT NOT NULL DEFAULT 'pending',
    unread        INTEGER NOT NULL DEFAULT 1,
    student_unread INTEGER NOT NULL DEFAULT 0,   -- student hasn't seen the decision yet
    certificate_pending INTEGER NOT NULL DEFAULT 0, -- pre-approval only; certificate to be uploaded after the event
    reminder_sent_at TEXT,                        -- last reminder sent to faculty
    remark        TEXT NOT NULL DEFAULT '',
    submitted_at  TEXT NOT NULL,
    reviewed_at   TEXT,
    reviewed_by   TEXT
);

CREATE TABLE IF NOT EXISTS documents (
    id             TEXT PRIMARY KEY,
    application_id TEXT NOT NULL REFERENCES applications(id) ON DELETE CASCADE,
    kind           TEXT NOT NULL,           -- approval_letter / evidence
    stored_name    TEXT NOT NULL,
    original_name  TEXT NOT NULL,
    mime_type      TEXT NOT NULL,
    size           INTEGER NOT NULL
);

-- ERP attendance imported by the class coordinator: one snapshot per upload
-- (e.g. "Till CIA-1", "Till CIA-2"), each with the date the ERP figures were taken.
CREATE TABLE IF NOT EXISTS erp_imports (
    id          TEXT PRIMARY KEY,
    class_id    TEXT NOT NULL REFERENCES classes(id),
    label       TEXT NOT NULL,
    as_of       TEXT NOT NULL,
    file_name   TEXT NOT NULL,
    uploaded_by TEXT NOT NULL,
    uploaded_at TEXT NOT NULL,
    UNIQUE (class_id, label)
);

CREATE TABLE IF NOT EXISTS erp_records (
    import_id  TEXT NOT NULL REFERENCES erp_imports(id) ON DELETE CASCADE,
    student_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    course_id  TEXT NOT NULL,
    attended   INTEGER NOT NULL,
    total      INTEGER NOT NULL,
    PRIMARY KEY (import_id, student_id, course_id)
);

CREATE INDEX IF NOT EXISTS idx_users_class ON users(class_id);

-- ERP "Subject wise Attendance" matrix: subjects of one upload, and each student's numbers per slot.
CREATE TABLE IF NOT EXISTS erp_subjects (
    import_id   TEXT NOT NULL REFERENCES erp_imports(id) ON DELETE CASCADE,
    ord         INTEGER NOT NULL,
    subject_key TEXT NOT NULL,
    code        TEXT NOT NULL,
    name        TEXT NOT NULL,
    label       TEXT NOT NULL,
    slots       TEXT NOT NULL,      -- JSON list, e.g. ["Lab", "Lecture"]
    course_id   TEXT,               -- matching time-table course (for event lectures), if any
    PRIMARY KEY (import_id, subject_key)
);

CREATE TABLE IF NOT EXISTS erp_cells (
    import_id   TEXT NOT NULL REFERENCES erp_imports(id) ON DELETE CASCADE,
    student_id  TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    subject_key TEXT NOT NULL,
    slot        TEXT NOT NULL,
    conducted   INTEGER NOT NULL,
    present     INTEGER NOT NULL,
    PRIMARY KEY (import_id, student_id, subject_key, slot)
);

-- In-app notifications (new application / reviewed / reminder)
CREATE TABLE IF NOT EXISTS notifications (
    id             TEXT PRIMARY KEY,
    user_id        TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    title          TEXT NOT NULL,
    body           TEXT NOT NULL,
    kind           TEXT NOT NULL,       -- new_application / reviewed / reminder
    application_id TEXT,
    created_at     TEXT NOT NULL,
    read_at        TEXT                 -- NULL = unread
);
CREATE INDEX IF NOT EXISTS idx_notif_user ON notifications(user_id, read_at, created_at DESC);

CREATE INDEX IF NOT EXISTS idx_apps_student ON applications(student_id);
CREATE INDEX IF NOT EXISTS idx_apps_class ON applications(class_id);
"""


@contextmanager
def get_db():
    """Opens a connection, commits if everything worked, rolls back on error."""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


# Columns added after the first release. Older databases get them here, so nobody has to
# delete their data when updating.
MIGRATIONS = [
    ("applications", "student_unread", "INTEGER NOT NULL DEFAULT 0"),
    ("applications", "certificate_pending", "INTEGER NOT NULL DEFAULT 0"),
    ("applications", "reminder_sent_at", "TEXT"),
    ("erp_imports", "division", "TEXT NOT NULL DEFAULT ''"),
    ("erp_imports", "period_from", "TEXT"),
    ("erp_imports", "period_to", "TEXT"),
]


def init_db():
    with get_db() as conn:
        conn.executescript(SCHEMA)
        for table, column, definition in MIGRATIONS:
            existing = {r["name"] for r in conn.execute(f"PRAGMA table_info({table})")}
            if column not in existing:
                conn.execute(f"ALTER TABLE {table} ADD COLUMN {column} {definition}")
