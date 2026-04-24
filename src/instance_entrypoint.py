from __future__ import annotations

import base64
import json
import os
import sys
from pathlib import Path
from urllib.parse import urlsplit
from urllib.request import urlopen


def read_template_source(template_location: str) -> str:
    location = template_location.strip()
    if not location:
        raise RuntimeError("PLAINBOOK_TEMPLATE_LOCATION is empty")

    parsed_location = urlsplit(location)
    if parsed_location.scheme in {"http", "https"}:
        with urlopen(location) as response_stream:
            raw_bytes = response_stream.read()
            charset = response_stream.headers.get_content_charset() or "utf-8"
            return raw_bytes.decode(charset)
    if parsed_location.scheme == "gs":
        if not parsed_location.netloc or not parsed_location.path:
            raise RuntimeError(f"Invalid Google Cloud Storage location: {location}")
        gcs_url = f"https://storage.googleapis.com/{parsed_location.netloc}{parsed_location.path}"
        with urlopen(gcs_url) as response_stream:
            raw_bytes = response_stream.read()
            charset = response_stream.headers.get_content_charset() or "utf-8"
            return raw_bytes.decode(charset)
    if parsed_location.scheme == "file":
        template_path = Path(parsed_location.path)
    else:
        template_path = Path(location)
        if not template_path.is_absolute():
            template_path = Path(__file__).resolve().parent / template_path

    return template_path.read_text(encoding="utf-8")


def write_empty_notebook(notebook_path: Path) -> None:
    notebook_path.write_text(
        json.dumps({"cells": [], "metadata": {}, "nbformat": 4, "nbformat_minor": 5}),
        encoding="utf-8",
    )


def write_notebook_if_valid(notebook_path: Path, notebook_raw: str) -> bool:
    try:
        parsed = json.loads(notebook_raw)
    except json.JSONDecodeError:
        return False
    if isinstance(parsed, dict) and parsed.get("nbformat") and isinstance(parsed.get("cells"), list):
        notebook_path.write_text(notebook_raw, encoding="utf-8")
        return True
    return False


def write_study_code_startup_file(ipython_dir: Path, study_code: str) -> None:
    startup_dir = ipython_dir / "profile_default" / "startup"
    startup_dir.mkdir(parents=True, exist_ok=True)
    startup_file = startup_dir / "99_study_code.py"
    startup_file.write_text(
        "import builtins\n"
        f"builtins.PLAINBOOK_STUDY_CODE = {study_code!r}\n"
        f"builtins.STUDY_CODE = {study_code!r}\n",
        encoding="utf-8",
    )


def configure_upload_credentials(workspace_root: Path) -> None:
    key_json = os.environ.get("PLAINBOOK_UPLOAD_KEY_JSON", "").strip()
    if not key_json:
        return
    credentials_path = workspace_root / "upload-key.json"
    credentials_path.write_text(key_json, encoding="utf-8")
    os.chmod(credentials_path, 0o600)
    os.environ["GOOGLE_APPLICATION_CREDENTIALS"] = str(credentials_path)


def restore_submitted_notebook(notebook_path: Path, study_code: str, submission_key: str) -> bool:
    bucket_name = os.environ.get("GCS_STUDY_BUCKET", "plaincoding-bucket").strip() or "plaincoding-bucket"
    object_path = f"plainbook/user-studies/{study_code}/{submission_key}/notebook.plnb"
    try:
        from google.cloud import storage

        client = storage.Client()
        blob = client.bucket(bucket_name).blob(object_path)
        if not blob.exists(client):
            return False
        notebook_raw = blob.download_as_text()
    except Exception as exc:
        print(f"[instance-entrypoint] Failed to restore notebook from gs://{bucket_name}/{object_path}: {exc}")
        return False
    return write_notebook_if_valid(notebook_path, notebook_raw)


def main() -> None:
    notebook_path = Path(os.environ.get("PLAINBOOK_INSTANCE_NOTEBOOK", "/workspace/notebook.plnb"))
    workspace_root = notebook_path.parent
    workspace_root.mkdir(parents=True, exist_ok=True)
    ipython_dir = Path(os.environ.get("IPYTHONDIR", str(Path.home() / ".ipython")))

    study_code = os.environ.get("PLAINBOOK_STUDY_CODE", "").strip()
    submission_key = os.environ.get("PLAINBOOK_CONTAINER_INSTANCE_ID", "").strip()
    if study_code:
        os.environ["PLAINBOOK_STUDY_CODE"] = study_code
        os.environ["STUDY_CODE"] = study_code
        write_study_code_startup_file(ipython_dir, study_code)
        configure_upload_credentials(workspace_root)

    restored_from_submission = bool(study_code and submission_key) and restore_submitted_notebook(
        notebook_path,
        study_code,
        submission_key,
    )

    if not restored_from_submission:
        template_location = os.environ.get("PLAINBOOK_TEMPLATE_LOCATION", "").strip()
        if template_location:
            template_raw = read_template_source(template_location)
            if not write_notebook_if_valid(notebook_path, template_raw):
                write_empty_notebook(notebook_path)
        elif not notebook_path.exists():
            write_empty_notebook(notebook_path)

    host = os.environ.get("PLAINBOOK_BIND_HOST", "0.0.0.0")
    port = os.environ.get("PLAINBOOK_BIND_PORT", os.environ.get("PORT", "8080")).strip() or "8080"
    auth_token = os.environ.get("PLAINBOOK_INSTANCE_AUTH_TOKEN", "").strip()
    if not auth_token:
        raise RuntimeError("PLAINBOOK_INSTANCE_AUTH_TOKEN is required")

    sys.argv = [
        "plainbook",
        str(notebook_path),
        "--host",
        host,
        "--port",
        port,
    ]
    if study_code:
        sys.argv.append("--user-study")

    import plainbook.main as plainbook_main

    plainbook_main.STUDY_CODE = study_code or None
    plainbook_main.AUTH_TOKEN = auth_token
    plainbook_main.main()


if __name__ == "__main__":
    main()
