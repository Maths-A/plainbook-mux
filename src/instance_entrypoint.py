from __future__ import annotations

import base64
import json
import os
import sys
import time
from pathlib import Path
from urllib.parse import urlsplit
from urllib.request import urlopen

JSON_CONTENT_TYPE = "application/json"

# Kept in sync with MANDATORY_INSTANCE_FLAGS in app.py -- the only thing that
# ever writes PLAINBOOK_INSTANCE_FLAGS. Enforced again here, not only trusted
# from the env var: a launch with a study_code always gets at least
# --user-study --log, even if PLAINBOOK_INSTANCE_FLAGS were somehow tampered
# with or truncated between mux and this container. Anything beyond that is
# free text an admin typed into the mux admin page, not checked against a
# fixed set here either -- see _normalize_instance_flags's docstring in
# app.py for why that is deliberate (in short: it reaches plainbook as one
# literal argv token via subprocess, never through a shell, so it cannot
# inject separate arguments -- at worst plainbook's own argparse rejects it).
MANDATORY_INSTANCE_FLAGS = ["user-study", "log"]


def resolve_instance_flags(study_code: str) -> list[str]:
    """The plainbook flags to launch with: MANDATORY_INSTANCE_FLAGS first
    (always present for a study launch, regardless of what the env var said),
    then whatever else PLAINBOOK_INSTANCE_FLAGS names (a comma-separated list
    set by app.py's build_container_env -- always present for a mux new
    enough to set it, even as ""), deduplicated, in the order given. Falls
    back to the pre-flag-selection default of --user-study --log for a study
    launch when the variable is entirely absent, which only happens against a
    mux image older than this feature."""
    raw = os.environ.get("PLAINBOOK_INSTANCE_FLAGS")
    seen = set(MANDATORY_INSTANCE_FLAGS) if study_code else set()
    extras: list[str] = []
    if raw is not None:
        for part in raw.split(","):
            flag = part.strip()
            if flag and flag not in seen:
                seen.add(flag)
                extras.append(flag)
    mandatory = list(MANDATORY_INSTANCE_FLAGS) if study_code else []
    return mandatory + extras


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
        bucket_name = parsed_location.netloc
        object_path = parsed_location.path.lstrip("/")
        try:
            from google.cloud import storage
        except Exception:
            storage = None

        if storage is not None:
            key_json = os.environ.get("PLAINBOOK_UPLOAD_KEY_JSON", "").strip()
            try:
                if key_json:
                    from google.oauth2 import service_account

                    credentials_info = json.loads(key_json)
                    credentials = service_account.Credentials.from_service_account_info(credentials_info)
                    client = storage.Client(credentials=credentials, project=credentials.project_id)
                else:
                    client = storage.Client()
                blob = client.bucket(bucket_name).blob(object_path)
                if not blob.exists(client):
                    raise RuntimeError(f"Template not found in gs://{bucket_name}/{object_path}")
                return blob.download_as_text()
            except Exception as exc:
                print(f"[instance-entrypoint] Failed to read gs://{bucket_name}/{object_path} via GCS client: {exc}")

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


def _register_fallback_activity_route(plainbook_main_module) -> None:
    """Register /report_activity if the bundled plainbook package does not already expose it."""
    try:
        from bottle import post, response
    except Exception:
        return

    try:
        routes = getattr(plainbook_main_module.default_app(), "routes", [])
        if any(getattr(route, "rule", "") == "/report_activity" for route in routes):
            return
    except Exception:
        # If route inspection fails, fall back to registering the route.
        pass

    @post("/report_activity")
    def report_activity():
        mux_url = os.environ.get("PLAINBOOK_MUX_URL", "").strip()
        container_id = os.environ.get("PLAINBOOK_CONTAINER_INSTANCE_ID", "").strip()
        if not mux_url or not container_id:
            return {"status": "error", "message": "Mux URL or container id not configured"}

        api_url = mux_url.rstrip("/") + f"/api/sessions/{container_id}/activity"
        try:
            from urllib.request import Request, urlopen

            req = Request(api_url, method="POST")
            req.add_header("Content-Type", JSON_CONTENT_TYPE)
            req.add_header("Authorization", f"Bearer {plainbook_main_module.AUTH_TOKEN}")
            urlopen(req, data=b"{}", timeout=5)
            response.content_type = JSON_CONTENT_TYPE
            return {"status": "ok"}
        except Exception as exc:
            response.content_type = JSON_CONTENT_TYPE
            return {"status": "error", "message": str(exc)}


def _register_activity_request_hook(plainbook_main_module) -> None:
    """Report activity from authenticated notebook API traffic.

    This is a fallback for stale frontend bundles that may not emit
    `/report_activity` pings from browser events yet.
    """
    try:
        from bottle import request
    except Exception:
        return

    app = plainbook_main_module.default_app()
    throttle_seconds = 30.0
    state = {"last_sent": 0.0}

    ignored_prefixes = (
        "/static/",
        "/js/",
        "/css/",
        "/images/",
        "/favicon",
    )
    ignored_exact = {
        "/",
        "/login",
        "/report_activity",
    }

    def _has_valid_token() -> bool:
        token = (
            (request.query.get("token") or "").strip()
            or (request.forms.get("token") or "").strip()
        )
        return bool(token and token == getattr(plainbook_main_module, "AUTH_TOKEN", ""))

    def _post_activity_ping() -> None:
        mux_url = os.environ.get("PLAINBOOK_MUX_URL", "").strip()
        container_id = os.environ.get("PLAINBOOK_CONTAINER_INSTANCE_ID", "").strip()
        auth_token = getattr(plainbook_main_module, "AUTH_TOKEN", "")
        if not mux_url or not container_id or not auth_token:
            return
        api_url = mux_url.rstrip("/") + f"/api/sessions/{container_id}/activity"
        from urllib.request import Request, urlopen

        req = Request(api_url, method="POST")
        req.add_header("Content-Type", JSON_CONTENT_TYPE)
        req.add_header("Authorization", f"Bearer {auth_token}")
        urlopen(req, data=b"{}", timeout=5)

    @app.hook("before_request")
    def _activity_hook() -> None:
        try:
            path = (request.path or "").strip()
            if not path or path in ignored_exact:
                return
            if any(path.startswith(prefix) for prefix in ignored_prefixes):
                return
            if not _has_valid_token():
                return

            now = time.time()
            if now - float(state["last_sent"]) < throttle_seconds:
                return

            _post_activity_ping()
            state["last_sent"] = now
        except Exception:
            # best-effort fallback; never block notebook requests
            return


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

    # Optionally report an initial activity ping to the mux so it records last_activity.
    mux_url = os.environ.get("PLAINBOOK_MUX_URL", "").strip()
    auth_token = os.environ.get("PLAINBOOK_INSTANCE_AUTH_TOKEN", "").strip()
    if mux_url and submission_key and auth_token:
        try:
            from urllib.request import Request, urlopen
            import json

            api_url = mux_url.rstrip("/") + f"/api/sessions/{submission_key}/activity"
            req = Request(api_url, method="POST")
            req.add_header("Content-Type", JSON_CONTENT_TYPE)
            req.add_header("Authorization", f"Bearer {auth_token}")
            urlopen(req, data=b"{}", timeout=5)
        except Exception:
            pass

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
    for flag in resolve_instance_flags(study_code):
        sys.argv.append(f"--{flag}")

    import plainbook.main as plainbook_main

    plainbook_main.STUDY_CODE = study_code or None
    plainbook_main.AUTH_TOKEN = auth_token
    if study_code:
        _register_fallback_activity_route(plainbook_main)
        _register_activity_request_hook(plainbook_main)
    plainbook_main.main()


if __name__ == "__main__":
    main()
