#!/usr/bin/env python3
"""Create a point-in-time backup of Discere's persistent app data.

The script is intentionally dependency-free so it can run inside a Render shell.
It uses SQLite's online backup API for app.db, then archives user files and
legacy output folders into one tar.gz file.
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import sqlite3
import tarfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Iterable, List


DEFAULT_STORAGE_DIR = Path(os.getenv("EMAIL_SUMMARIZER_STORAGE_DIR", "/var/data/storage"))
DEFAULT_OUTPUT_DIR = Path(os.getenv("EMAIL_SUMMARIZER_OUTPUT_DIR", "/var/data/output"))
DEFAULT_BACKUP_DIR = Path(os.getenv("EMAIL_SUMMARIZER_BACKUP_DIR", "/var/data/backups"))


def utc_stamp() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")


def dir_size(path: Path) -> int:
    if not path.exists():
        return 0
    if path.is_file():
        return path.stat().st_size
    total = 0
    for item in path.rglob("*"):
        if item.is_file():
            total += item.stat().st_size
    return total


def copy_tree_if_exists(source: Path, destination: Path) -> bool:
    if not source.exists():
        return False
    if source.is_file():
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source, destination)
        return True
    shutil.copytree(source, destination, dirs_exist_ok=True)
    return True


def backup_sqlite_database(source_db: Path, destination_db: Path) -> Dict[str, str]:
    destination_db.parent.mkdir(parents=True, exist_ok=True)
    if not source_db.exists():
        return {"status": "missing", "source": str(source_db)}

    source_uri = source_db.resolve().as_uri() + "?mode=ro"
    source = sqlite3.connect(source_uri, uri=True)
    try:
        destination = sqlite3.connect(destination_db)
        try:
            source.backup(destination)
        finally:
            destination.close()
    finally:
        source.close()

    # Re-open cleanly so integrity_check result is read from a cursor.
    check = sqlite3.connect(destination_db)
    try:
        result = check.execute("PRAGMA integrity_check").fetchone()
        if not result or result[0] != "ok":
            raise RuntimeError(f"SQLite backup integrity check failed: {result}")
    finally:
        check.close()

    return {"status": "ok", "source": str(source_db), "destination": str(destination_db)}


def create_archive(stage_dir: Path, archive_path: Path) -> None:
    archive_path.parent.mkdir(parents=True, exist_ok=True)
    with tarfile.open(archive_path, "w:gz") as archive:
        archive.add(stage_dir, arcname=stage_dir.name)


def write_manifest(
    stage_dir: Path,
    storage_dir: Path,
    output_dir: Path,
    db_result: Dict[str, str],
    copied_paths: Iterable[Dict[str, str]],
) -> None:
    manifest = {
        "created_at": datetime.now(timezone.utc).isoformat(),
        "storage_dir": str(storage_dir),
        "output_dir": str(output_dir),
        "database": db_result,
        "copied_paths": list(copied_paths),
        "notes": [
            "This archive may contain encrypted credentials, OAuth tokens, email-derived summaries, source email JSON, and attachments.",
            "Store it in a private location with access limited to admins only.",
            "Keep EMAIL_SUMMARIZER_ENCRYPTION_KEY safe separately; encrypted profile data cannot be restored without it.",
        ],
    }
    (stage_dir / "manifest.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")


def build_backup(storage_dir: Path, output_dir: Path, backup_dir: Path, keep_stage: bool) -> Path:
    stamp = utc_stamp()
    backup_dir.mkdir(parents=True, exist_ok=True)
    stage_dir = backup_dir / f"discere-backup-{stamp}"
    stage_dir.mkdir(parents=True, exist_ok=False)

    copied: List[Dict[str, str]] = []
    db_result = backup_sqlite_database(storage_dir / "app" / "app.db", stage_dir / "storage" / "app" / "app.db")

    for relative_path in ["app/email_summarizer.key", "users"]:
        source = storage_dir / relative_path
        destination = stage_dir / "storage" / relative_path
        if copy_tree_if_exists(source, destination):
            copied.append({"source": str(source), "destination": str(destination), "bytes": str(dir_size(source))})

    if copy_tree_if_exists(output_dir, stage_dir / "output"):
        copied.append({"source": str(output_dir), "destination": str(stage_dir / "output"), "bytes": str(dir_size(output_dir))})

    write_manifest(stage_dir, storage_dir, output_dir, db_result, copied)
    archive_path = backup_dir / f"{stage_dir.name}.tar.gz"
    create_archive(stage_dir, archive_path)

    if not keep_stage:
        shutil.rmtree(stage_dir)

    return archive_path


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Back up Discere persistent storage and SQLite data.")
    parser.add_argument("--storage-dir", type=Path, default=DEFAULT_STORAGE_DIR)
    parser.add_argument("--output-dir", type=Path, default=DEFAULT_OUTPUT_DIR)
    parser.add_argument("--backup-dir", type=Path, default=DEFAULT_BACKUP_DIR)
    parser.add_argument("--keep-stage", action="store_true", help="Keep the uncompressed staging folder for inspection.")
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    archive_path = build_backup(args.storage_dir, args.output_dir, args.backup_dir, args.keep_stage)
    print(f"Backup created: {archive_path}")


if __name__ == "__main__":
    main()
