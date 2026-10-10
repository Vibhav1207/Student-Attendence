"""
Deletes ALL data before going live: faculty accounts, logins and passwords, applications,
uploaded letters and certificates, ERP uploads and notifications. Then loads the classes and the
student list again (students get no password until a coordinator issues starting passwords).

    python reset_data.py          asks you to type RESET first
    python reset_data.py --yes    no question (for scripts)

Stop the backend (Ctrl + C) before running this.
"""

import shutil
import sys

from database import DATA_DIR, DB_PATH


def main():
    print("This permanently deletes everything in", DATA_DIR.resolve())
    print("  - all faculty accounts, logins and passwords")
    print("  - all applications, uploaded letters and certificates")
    print("  - all ERP uploads, notifications and reports data")
    if "--yes" not in sys.argv:
        if input("Type RESET to continue: ").strip() != "RESET":
            print("Cancelled. Nothing was deleted.")
            return

    targets = [DB_PATH, DB_PATH.with_name(DB_PATH.name + "-journal"),
               DB_PATH.with_name(DB_PATH.name + "-wal"), DB_PATH.with_name(DB_PATH.name + "-shm"),
               DATA_DIR / "uploads", DATA_DIR / "credentials"]
    try:
        for t in targets:
            if t.is_dir():
                shutil.rmtree(t)
            elif t.exists():
                t.unlink()
    except PermissionError:
        print("\nCouldn't delete the database: it's still in use.")
        print("Stop the backend first (Ctrl + C in its window), close any Excel files, then run this again.")
        sys.exit(1)

    print("\nOld data deleted. Loading classes and students again...\n")
    import import_data
    import_data.main()
    print("\nDone. The database is clean and ready for deployment.")
    print("Next: start the backend, sign up as faculty, and issue starting passwords from the Students page.")


if __name__ == "__main__":
    main()
