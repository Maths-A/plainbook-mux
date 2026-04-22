from __future__ import annotations

import atexit
import hashlib
import hmac
import os
import pwd
import re
import secrets
import shlex
import shutil
import socket
import signal
import subprocess
import sys
import threading
import time
import uuid
import resource
from dataclasses import dataclass, field
from functools import wraps
import inspect
from pathlib import Path
from urllib.error import HTTPError as URLLibHTTPError
from urllib.error import URLError
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit
from urllib.request import Request, urlopen

from bottle import Bottle, HTTPError, redirect, request, response


APP_ROOT = Path(__file__).resolve().parent
RUNTIME_DIR = APP_ROOT / "runtime"
RUNTIME_DIR.mkdir(parents=True, exist_ok=True)

HTML_CONTENT_TYPE = "text/html; charset=utf-8"
JSON_CONTENT_TYPE = "application/json"
TEMPLATE_EXPIRED_MESSAGE = "template expired, please contact the administrator"


def set_no_cache_headers() -> None:
  response.set_header("Cache-Control", "no-store, no-cache, must-revalidate, max-age=0")
  response.set_header("Pragma", "no-cache")
  response.set_header("Expires", "0")

PLAINBOOK_URL_RE = re.compile(r"(?:Please load this URL:|Listening on)\s*(https?://\S+)")
TOKEN_RE = re.compile(r"Authentication token:\s*(\S+)")
ANSI_ESCAPE_RE = re.compile(r"\x1B\[[0-?]*[ -/]*[@-~]")
INSTANCE_PATH_RE = re.compile(r"/instance/([a-zA-Z0-9]+)(?:/|$)")


def _instance_token_secret() -> str:
  return os.environ.get("PLAINBOOK_INSTANCE_TOKEN_SECRET", "").strip() or os.environ.get("MUX_ADMIN_PASSWORD", "").strip() or "plainbook-mux"


def build_instance_auth_token(instance_id: str) -> str:
  secret = _instance_token_secret().encode("utf-8")
  digest = hmac.new(secret, instance_id.encode("utf-8"), hashlib.sha256).hexdigest()
  return digest[:32]


def build_launch_code_hash(launch_code: str) -> str:
  return hashlib.sha256(launch_code.strip().encode("utf-8")).hexdigest()[:16]

HOP_BY_HOP_HEADERS = {
  "connection",
  "keep-alive",
  "proxy-authenticate",
  "proxy-authorization",
  "te",
  "trailers",
  "transfer-encoding",
  "upgrade",
  "host",
  "content-length",
}

ADMIN_PASSWORD = os.environ.get("MUX_ADMIN_PASSWORD")
if not ADMIN_PASSWORD:
  ADMIN_PASSWORD = secrets.token_urlsafe(18)
  print("[plainbook-mux] MUX_ADMIN_PASSWORD not set; generated temporary admin password:")
  print(f"[plainbook-mux] {ADMIN_PASSWORD}")
ADMIN_COOKIE_NAME = "mux_admin_session"
ADMIN_SESSION_TTL_SECONDS = 60 * 60 * 8
admin_sessions: dict[str, float] = {}
admin_sessions_lock = threading.Lock()


import json

TEMPLATE_DIR = APP_ROOT / "template"
TEMPLATE_DIR.mkdir(parents=True, exist_ok=True)
ACCESS_CODES_FILENAME = "access-codes.json"
GENERATED_ACCESS_CODES_FILENAME = "generated-access-codes.json"
ACCESS_CODE_CONFIG_FILE = TEMPLATE_DIR / ACCESS_CODES_FILENAME
GENERATED_ACCESS_CODE_FILE = TEMPLATE_DIR / GENERATED_ACCESS_CODES_FILENAME
STATS_FILE = RUNTIME_DIR / "code_stats.json"


def read_env_int(name: str, default: int, min_value: int = 1) -> int:
  raw = os.environ.get(name, "").strip()
  if not raw:
    return default
  try:
    value = int(raw)
  except ValueError:
    return default
  return max(value, min_value)


ISOLATION_ENABLED = os.environ.get("PLAINBOOK_ENABLE_ISOLATION", "true").lower() in {"1", "true", "yes"}
MACOS_SANDBOX_ENABLED = os.environ.get("PLAINBOOK_USE_SANDBOX_EXEC", "true").lower() in {"1", "true", "yes"}
LINUX_BWRAP_ENABLED = os.environ.get("PLAINBOOK_USE_BWRAP", "false").lower() in {"1", "true", "yes"}
INSTANCE_MEMORY_LIMIT_MB = read_env_int("PLAINBOOK_INSTANCE_MEMORY_MB", 1024, min_value=128)
INSTANCE_CPU_LIMIT_SECONDS = read_env_int("PLAINBOOK_INSTANCE_CPU_SECONDS", 3600, min_value=30)
INSTANCE_NOFILE_LIMIT = read_env_int("PLAINBOOK_INSTANCE_NOFILE", 1024, min_value=64)
PLAINBOOK_BIND_HOST = os.environ.get("PLAINBOOK_BIND_HOST", "127.0.0.1").strip() or "127.0.0.1"
PLAINBOOK_CHILD_PYTHON = os.environ.get("PLAINBOOK_CHILD_PYTHON", "").strip()
INSTANCE_USER = os.environ.get("PLAINBOOK_INSTANCE_USER", "").strip()
KERNEL_STRICT_MODE = os.environ.get("PLAINBOOK_KERNEL_STRICT_MODE", "false").lower() in {"1", "true", "yes"}
INSTANCE_BACKEND = os.environ.get("PLAINBOOK_INSTANCE_BACKEND", "").strip().lower()
if not INSTANCE_BACKEND:
  INSTANCE_BACKEND = "cloud-run" if (os.environ.get("K_SERVICE") or os.environ.get("GOOGLE_CLOUD_PROJECT")) else "process"
INSTANCE_CONTAINER_IMAGE = os.environ.get("PLAINBOOK_INSTANCE_IMAGE", "").strip()
INSTANCE_CONTAINER_PORT = read_env_int("PLAINBOOK_INSTANCE_PORT", 8080, min_value=1)
CLOUD_RUN_PROJECT_ID = os.environ.get("PLAINBOOK_CLOUD_RUN_PROJECT", "").strip() or os.environ.get("GOOGLE_CLOUD_PROJECT", "").strip()
CLOUD_RUN_REGION = os.environ.get("PLAINBOOK_CLOUD_RUN_REGION", "").strip() or os.environ.get("GOOGLE_CLOUD_REGION", "").strip() or os.environ.get("REGION", "").strip() or "us-central1"
CLOUD_RUN_SERVICE_PREFIX = os.environ.get("PLAINBOOK_CLOUD_RUN_SERVICE_PREFIX", "plainbook-instance").strip() or "plainbook-instance"
CLOUD_RUN_CHILD_MIN_SCALE = read_env_int("PLAINBOOK_CLOUD_RUN_CHILD_MIN_SCALE", 1, min_value=0)
CLOUD_RUN_CHILD_MAX_SCALE = read_env_int("PLAINBOOK_CLOUD_RUN_CHILD_MAX_SCALE", 1, min_value=1)
LAUNCH_CODE_RECENT_STOP_GRACE_SECONDS = read_env_int("PLAINBOOK_LAUNCH_CODE_RECENT_STOP_GRACE_SECONDS", 120, min_value=5)
PLAINBOOK_UPLOAD_KEY_FILE = os.environ.get("PLAINBOOK_UPLOAD_KEY_FILE", "").strip()
GCS_STUDY_BUCKET = os.environ.get("GCS_STUDY_BUCKET", "").strip()
PLAINBOOK_UPLOAD_KEY_JSON = os.environ.get("PLAINBOOK_UPLOAD_KEY_JSON", "").strip()
ACCESS_CODE_GCS_BUCKET = os.environ.get("PLAINBOOK_ACCESS_CODE_GCS_BUCKET", "").strip() or GCS_STUDY_BUCKET
ACCESS_CODE_GCS_PREFIX = os.environ.get("PLAINBOOK_ACCESS_CODE_GCS_PREFIX", "plainbook/user-studies/config").strip().strip("/")
if not PLAINBOOK_UPLOAD_KEY_JSON and PLAINBOOK_UPLOAD_KEY_FILE:
  key_file_path = Path(PLAINBOOK_UPLOAD_KEY_FILE)
  if key_file_path.exists() and key_file_path.is_file():
    try:
      PLAINBOOK_UPLOAD_KEY_JSON = key_file_path.read_text(encoding="utf-8").strip()
    except OSError as exc:
      print(f"[plainbook-mux] Warning: could not read upload key file '{PLAINBOOK_UPLOAD_KEY_FILE}': {exc}")
PROOT_ROOTFS_BASE = RUNTIME_DIR / "proot-rootfs"

INSTANCE_UID: int | None = None
INSTANCE_GID: int | None = None
if INSTANCE_USER:
  try:
    user_info = pwd.getpwnam(INSTANCE_USER)
    INSTANCE_UID = user_info.pw_uid
    INSTANCE_GID = user_info.pw_gid
  except KeyError:
    print(f"[plainbook-mux] Warning: instance user '{INSTANCE_USER}' not found; privilege drop disabled")


class CodeStatsManager:
  """Tracks usage statistics for access codes."""
  def __init__(self, stats_file: Path) -> None:
    self.stats_file = stats_file
    self.stats: dict[str, int] = {}
    self.lock = threading.Lock()
    self._load_stats()

  def _load_stats(self) -> None:
    if self.stats_file.exists():
      try:
        with open(self.stats_file, "r") as f:
          self.stats = json.load(f)
      except (json.JSONDecodeError, IOError):
        self.stats = {}
    else:
      self.stats = {}

  def _save_stats(self) -> None:
    try:
      with open(self.stats_file, "w") as f:
        json.dump(self.stats, f, indent=2)
    except IOError:
      pass

  def record_usage(self, code: str) -> None:
    """Record that a code was used."""
    with self.lock:
      self.stats[code] = self.stats.get(code, 0) + 1
      self._save_stats()

  def get_stats(self) -> dict[str, int]:
    """Get current statistics."""
    with self.lock:
      return dict(self.stats)


def resolve_plainbook_command() -> list[str]:
  override = os.environ.get("PLAINBOOK_COMMAND", "").strip()
  if override:
    return shlex.split(override)
  if PLAINBOOK_CHILD_PYTHON:
    return [PLAINBOOK_CHILD_PYTHON, "-m", "plainbook.main"]
  if shutil.which("plainbook"):
    return ["plainbook"]
  return [sys.executable, "-m", "plainbook.main"]


def build_plainbook_command(notebook_path: Path, port: int, user_study_enabled: bool = False) -> list[str]:
  command = [
        *resolve_plainbook_command(),
        str(notebook_path),
        "--host",
    PLAINBOOK_BIND_HOST,
        "--port",
        str(port),
    ]
  if user_study_enabled:
    command.append("--user-study")
  return command


def build_instance_paths(instance_id: str) -> tuple[Path, Path, Path]:
    instance_dir = RUNTIME_DIR / f"instance-{instance_id}"
    tmp_dir = instance_dir / "tmp"
    sandbox_profile_path = instance_dir / "sandbox.sb"
    return instance_dir, tmp_dir, sandbox_profile_path


def build_macos_sandbox_profile(instance_dir: Path) -> str:
    def sb_path(path: Path | str) -> str:
        return str(path).replace("\\", "\\\\").replace('"', '\\"')

    home_dir = Path.home()
    return (
        "(version 1)\n"
        "(allow default)\n"
        f"(deny file-write* (subpath \"{sb_path(home_dir)}\"))\n"
        f"(allow file-write* (subpath \"{sb_path(instance_dir)}\"))\n"
        "(allow file-write* (subpath \"/private/var/folders\"))\n"
        "(allow file-write* (subpath \"/tmp\"))\n"
    )


def build_instance_env(
  instance_dir: Path,
  tmp_dir: Path,
  study_code: str | None = None,
  launch_code: str | None = None,
) -> dict[str, str]:
    guard_code = build_kernel_fs_guard(instance_dir, strict_mode=KERNEL_STRICT_MODE)

    guard_dir = instance_dir / ".guard"
    guard_dir.mkdir(parents=True, exist_ok=True)
    sitecustomize_file = guard_dir / "sitecustomize.py"
    sitecustomize_file.write_text(guard_code, encoding="utf-8")

    ipython_dir = instance_dir / ".ipython"
    startup_dir = ipython_dir / "profile_default" / "startup"
    startup_dir.mkdir(parents=True, exist_ok=True)
    guard_file = startup_dir / "99_fs_guard.py"
    guard_file.write_text(guard_code, encoding="utf-8")

    env = os.environ.copy()
    env["PYTHONUNBUFFERED"] = "1"
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    env["PYTHONNOUSERSITE"] = "1"
    env["HOME"] = str(instance_dir)
    env["TMPDIR"] = str(tmp_dir)
    env["IPYTHONDIR"] = str(ipython_dir)
    existing_pythonpath = env.get("PYTHONPATH", "")
    env["PYTHONPATH"] = f"{guard_dir}{os.pathsep}{existing_pythonpath}" if existing_pythonpath else str(guard_dir)
    env["PLAINBOOK_INSTANCE_ROOT"] = str(instance_dir)
    env["PLAINBOOK_KERNEL_STRICT_MODE"] = "1" if KERNEL_STRICT_MODE else "0"
    submission_key = (launch_code or "").strip() or instance_dir.name
    env["PLAINBOOK_CONTAINER_INSTANCE_ID"] = submission_key
    env["PLAINBOOK_RUNTIME_INSTANCE_ID"] = instance_dir.name
    if study_code:
      env["PLAINBOOK_STUDY_CODE"] = study_code
      if GCS_STUDY_BUCKET:
        env["GCS_STUDY_BUCKET"] = GCS_STUDY_BUCKET
      if PLAINBOOK_UPLOAD_KEY_JSON:
        env["PLAINBOOK_UPLOAD_KEY_JSON"] = PLAINBOOK_UPLOAD_KEY_JSON
    return env


def build_kernel_fs_guard(instance_dir: Path, strict_mode: bool = False) -> str:
    root = str(instance_dir.resolve())
    strict_literal = "True" if strict_mode else "False"
    # The guard is loaded by the IPython kernel startup sequence.
    return f'''import builtins
import inspect
import os
import pathlib
import socket
import subprocess

ROOT = pathlib.Path(r"{root}").resolve()
STRICT_MODE = {strict_literal}
IMPORT_ALLOW_PREFIXES = [
    pathlib.Path("/usr").resolve(),
    pathlib.Path("/lib").resolve(),
    pathlib.Path("/lib64").resolve(),
    pathlib.Path("/bin").resolve(),
    pathlib.Path("/sbin").resolve(),
    pathlib.Path("/etc").resolve(),
    pathlib.Path("/tmp").resolve(),
]

_orig_open = builtins.open
_orig_listdir = os.listdir
_orig_scandir = os.scandir
_orig_walk = os.walk
_orig_chdir = os.chdir
_orig_exists = os.path.exists
_orig_isfile = os.path.isfile
_orig_isdir = os.path.isdir
_orig_islink = os.path.islink
_orig_stat = os.stat
_orig_path_open = pathlib.Path.open
_orig_path_iterdir = pathlib.Path.iterdir
_orig_path_glob = pathlib.Path.glob
_orig_path_rglob = pathlib.Path.rglob
_orig_path_exists = pathlib.Path.exists
_orig_path_read_text = pathlib.Path.read_text
_orig_path_write_text = pathlib.Path.write_text


def _called_from_importlib():
    for frame in inspect.stack(context=0)[:12]:
        name = frame.filename or ""
        if "importlib" in name or "pkgutil" in name or "zipimport" in name:
            return True
    return False


def _resolve_path(target):
    if isinstance(target, int):
        return None
    p = pathlib.Path(str(target))
    if not p.is_absolute():
        p = pathlib.Path.cwd() / p
    return p.resolve(strict=False)


def _is_inside(path_obj, parent):
    try:
        path_obj.relative_to(parent)
        return True
    except Exception:
        return False


def _is_allowed(path_obj, *, write=False):
    if path_obj is None:
        return True
    if _is_inside(path_obj, ROOT):
        return True
    if write:
        return False
    if _called_from_importlib():
        for prefix in IMPORT_ALLOW_PREFIXES:
            if _is_inside(path_obj, prefix):
                return True
    return False


def _guard(path, *, write=False, op="filesystem"):
    resolved = _resolve_path(path)
    if _is_allowed(resolved, write=write):
        return
    raise PermissionError(f"{{op}} denied outside workspace: {{resolved}}")


def _guard_open(file, mode="r", *args, **kwargs):
    write = any(flag in mode for flag in ("w", "a", "+", "x"))
    _guard(file, write=write, op="open")
    return _orig_open(file, mode, *args, **kwargs)


def _guard_listdir(path="."):
    _guard(path, write=False, op="listdir")
    return _orig_listdir(path)


def _guard_scandir(path="."):
    _guard(path, write=False, op="scandir")
    return _orig_scandir(path)


def _guard_walk(top, *args, **kwargs):
    _guard(top, write=False, op="walk")
    return _orig_walk(top, *args, **kwargs)


def _guard_chdir(path):
    _guard(path, write=False, op="chdir")
    return _orig_chdir(path)


def _guard_exists(path):
    _guard(path, write=False, op="exists")
    return _orig_exists(path)


def _guard_isfile(path):
    _guard(path, write=False, op="isfile")
    return _orig_isfile(path)


def _guard_isdir(path):
    _guard(path, write=False, op="isdir")
    return _orig_isdir(path)


def _guard_islink(path):
    _guard(path, write=False, op="islink")
    return _orig_islink(path)


def _guard_stat(path, *args, **kwargs):
    _guard(path, write=False, op="stat")
    return _orig_stat(path, *args, **kwargs)


def _path_open(self, mode="r", *args, **kwargs):
    write = any(flag in mode for flag in ("w", "a", "+", "x"))
    _guard(self, write=write, op="path.open")
    return _orig_path_open(self, mode, *args, **kwargs)


def _path_iterdir(self):
    _guard(self, write=False, op="path.iterdir")
    return _orig_path_iterdir(self)


def _path_glob(self, pattern):
    _guard(self, write=False, op="path.glob")
    return _orig_path_glob(self, pattern)


def _path_rglob(self, pattern):
    _guard(self, write=False, op="path.rglob")
    return _orig_path_rglob(self, pattern)


def _path_exists(self):
    _guard(self, write=False, op="path.exists")
    return _orig_path_exists(self)


def _path_read_text(self, *args, **kwargs):
    _guard(self, write=False, op="path.read_text")
    return _orig_path_read_text(self, *args, **kwargs)


def _path_write_text(self, data, *args, **kwargs):
    _guard(self, write=True, op="path.write_text")
    return _orig_path_write_text(self, data, *args, **kwargs)


def _deny_subprocess(*args, **kwargs):
    raise PermissionError("subprocess is disabled by strict mode")


def _deny_os_system(*args, **kwargs):
    raise PermissionError("os.system is disabled by strict mode")


def _deny_socket(*args, **kwargs):
    raise PermissionError("socket/network access is disabled by strict mode")


builtins.open = _guard_open
os.listdir = _guard_listdir
os.scandir = _guard_scandir
os.walk = _guard_walk
os.chdir = _guard_chdir
os.path.exists = _guard_exists
os.path.isfile = _guard_isfile
os.path.isdir = _guard_isdir
os.path.islink = _guard_islink
os.stat = _guard_stat
pathlib.Path.open = _path_open
pathlib.Path.iterdir = _path_iterdir
pathlib.Path.glob = _path_glob
pathlib.Path.rglob = _path_rglob
pathlib.Path.exists = _path_exists
pathlib.Path.read_text = _path_read_text
pathlib.Path.write_text = _path_write_text

if STRICT_MODE:
    os.system = _deny_os_system
    subprocess.Popen = _deny_subprocess
    subprocess.run = _deny_subprocess
    subprocess.call = _deny_subprocess
    subprocess.check_call = _deny_subprocess
    subprocess.check_output = _deny_subprocess
    socket.socket = _deny_socket
    socket.create_connection = _deny_socket
'''


def build_preexec_fn():
    def _apply_limits() -> None:
        os.setsid()
        try:
            resource.setrlimit(resource.RLIMIT_NOFILE, (INSTANCE_NOFILE_LIMIT, INSTANCE_NOFILE_LIMIT))
        except (ValueError, OSError):
            pass
        try:
            cpu_hard = max(INSTANCE_CPU_LIMIT_SECONDS + 10, INSTANCE_CPU_LIMIT_SECONDS)
            resource.setrlimit(resource.RLIMIT_CPU, (INSTANCE_CPU_LIMIT_SECONDS, cpu_hard))
        except (ValueError, OSError):
            pass
        try:
            memory_limit = INSTANCE_MEMORY_LIMIT_MB * 1024 * 1024
            resource.setrlimit(resource.RLIMIT_AS, (memory_limit, memory_limit))
        except (ValueError, OSError):
            pass
        if INSTANCE_UID is not None and INSTANCE_GID is not None and os.geteuid() == 0:
          try:
            os.setgid(INSTANCE_GID)
            os.setuid(INSTANCE_UID)
          except OSError:
            pass

    return _apply_limits


def _build_proot_rootfs(instance_dir: Path) -> Path:
    rootfs = PROOT_ROOTFS_BASE / instance_dir.name
    rootfs.mkdir(parents=True, exist_ok=True)
    for relative in ("bin", "dev", "etc", "lib", "lib64", "proc", "usr", "tmp", "workspace"):
        (rootfs / relative).mkdir(parents=True, exist_ok=True)
    return rootfs


def build_proot_command(base_cmd: list[str], instance_dir: Path, tmp_dir: Path) -> list[str]:
    """Build a proot command that hides the host filesystem from plainbook.

    The sandbox root only exposes a synthetic root with system runtime paths and
    the per-instance workspace bound at /workspace.
    """
    rootfs = _build_proot_rootfs(instance_dir)
    sandbox_workspace = "/workspace"

    remapped_cmd: list[str] = []
    instance_prefix = str(instance_dir)
    for arg in base_cmd:
        if arg.startswith(instance_prefix):
            remapped_cmd.append(arg.replace(instance_prefix, sandbox_workspace, 1))
        else:
            remapped_cmd.append(arg)

    bind_args: list[str] = []
    for system_path in ["/usr", "/bin", "/sbin", "/lib", "/lib64", "/etc", "/dev", "/proc", "/tmp"]:
        if Path(system_path).exists():
            bind_args.extend(["-b", f"{system_path}:{system_path}"])

    bind_args.extend(["-b", f"{instance_dir}:{sandbox_workspace}"])
    bind_args.extend(["-b", f"{tmp_dir}:{sandbox_workspace}/tmp"])

    return [
        "proot",
        "-R",
        str(rootfs),
        "-w",
        sandbox_workspace,
        *bind_args,
        *remapped_cmd,
    ]


def build_container_entrypoint_command() -> list[str]:
    return ["python", "/app/instance_entrypoint.py"]


def build_container_env(
  instance_id: str,
  template_location: str | None = None,
  study_code: str | None = None,
  launch_code: str | None = None,
  auth_token: str | None = None,
) -> dict[str, str]:
    submission_key = (launch_code or "").strip() or instance_id
    env = {
        "PLAINBOOK_INSTANCE_NOTEBOOK": "/workspace/notebook.plnb",
        "PLAINBOOK_INSTANCE_ROOT": "/workspace",
        "PLAINBOOK_BIND_HOST": "0.0.0.0",
        "PLAINBOOK_BIND_PORT": str(INSTANCE_CONTAINER_PORT),
        "PYTHONUNBUFFERED": "1",
        "PYTHONDONTWRITEBYTECODE": "1",
        "PLAINBOOK_CONTAINER_INSTANCE_ID": submission_key,
        "PLAINBOOK_RUNTIME_INSTANCE_ID": instance_id,
        "PLAINBOOK_KERNEL_STRICT_MODE": "1" if KERNEL_STRICT_MODE else "0",
    }
    if template_location:
      env["PLAINBOOK_TEMPLATE_LOCATION"] = template_location
    if study_code:
      env["PLAINBOOK_STUDY_CODE"] = study_code
      if GCS_STUDY_BUCKET:
        env["GCS_STUDY_BUCKET"] = GCS_STUDY_BUCKET
      if PLAINBOOK_UPLOAD_KEY_JSON:
        env["PLAINBOOK_UPLOAD_KEY_JSON"] = PLAINBOOK_UPLOAD_KEY_JSON
    if auth_token:
      env["PLAINBOOK_INSTANCE_AUTH_TOKEN"] = auth_token
    return env


def require_instance_container_image() -> str:
    if not INSTANCE_CONTAINER_IMAGE:
        raise RuntimeError("PLAINBOOK_INSTANCE_IMAGE must be set when using a container backend")
    return INSTANCE_CONTAINER_IMAGE


def _request_url_is_ready(target_url: str, timeout_seconds: int = 2) -> bool:
    request_obj = Request(target_url, method="GET")
    try:
        with urlopen(request_obj, timeout=timeout_seconds) as upstream:
            return 200 <= upstream.getcode() < 500
    except URLLibHTTPError as exc:
        # A 404 typically means the instance endpoint is gone.
        return exc.code < 500 and exc.code != 404
    except Exception:
        return False


def _build_instance_healthcheck_url(record: "InstanceRecord") -> str:
    raw_url = (record.backend_url or record.public_url or "").strip()
    if not raw_url:
        return ""
    try:
        parsed = urlsplit(raw_url)
        query_items = parse_qsl(parsed.query, keep_blank_values=True)
        if record.token and not any(key == "token" for key, _ in query_items):
            query_items.append(("token", record.token))
        return urlunsplit((parsed.scheme, parsed.netloc, parsed.path, urlencode(query_items), parsed.fragment))
    except Exception:
        return raw_url


def _cloud_run_session_and_project() -> tuple[object, str]:
    try:
        from google.auth import default as google_auth_default
        from google.auth.transport.requests import AuthorizedSession
    except ImportError as exc:  # pragma: no cover - import is expected in deployed envs
        raise RuntimeError("google-auth is required for the Cloud Run backend") from exc

    credentials, project_id = google_auth_default(scopes=["https://www.googleapis.com/auth/cloud-platform"])
    session = AuthorizedSession(credentials)
    resolved_project = CLOUD_RUN_PROJECT_ID or project_id
    if not resolved_project:
        raise RuntimeError("PLAINBOOK_CLOUD_RUN_PROJECT or GOOGLE_CLOUD_PROJECT must be set for the Cloud Run backend")
    return session, resolved_project


def _cloud_run_service_account_email(project_id: str) -> str:
  configured_email = os.environ.get("PLAINBOOK_CLOUD_RUN_INSTANCE_SERVICE_ACCOUNT", "").strip()
  if configured_email:
    return configured_email
  return f"plainbook-uploader@{project_id}.iam.gserviceaccount.com"


def build_cloud_run_service_name(instance_id: str) -> str:
    service_name = f"{CLOUD_RUN_SERVICE_PREFIX}-{instance_id}".lower()
    return service_name[:63].rstrip("-") or f"{CLOUD_RUN_SERVICE_PREFIX}-{instance_id}"[:63]


def build_cloud_run_service_body(
    instance_id: str,
    notebook_path: Path,
    auth_token: str | None = None,
    template_location: str | None = None,
    study_code: str | None = None,
    launch_code: str | None = None,
) -> dict:
    image = require_instance_container_image()
    env_items = [
        {"name": key, "value": value}
        for key, value in build_container_env(
            instance_id,
            template_location=template_location,
            study_code=study_code,
          launch_code=launch_code,
            auth_token=auth_token,
        ).items()
    ]
    _, project_id = _cloud_run_session_and_project()
    labels = {
        "plainbook-instance": instance_id,
    }
    annotations: dict[str, str] = {}
    if launch_code:
        labels["plainbook-launch-hash"] = build_launch_code_hash(launch_code)
    if study_code:
      annotations["plainbook-mux.dev/study-code"] = study_code
    return {
        "invokerIamDisabled": True,
        "labels": labels,
      "annotations": annotations,
        "template": {
            "annotations": {
            "autoscaling.knative.dev/minScale": str(CLOUD_RUN_CHILD_MIN_SCALE),
            "autoscaling.knative.dev/maxScale": str(CLOUD_RUN_CHILD_MAX_SCALE),
            },
            "serviceAccount": _cloud_run_service_account_email(project_id),
            "maxInstanceRequestConcurrency": 1,
            "timeout": "3600s",
            "containers": [
                {
                    "image": image,
                    "command": build_container_entrypoint_command(),
                    "env": env_items,
                    "ports": [{"containerPort": INSTANCE_CONTAINER_PORT}],
                }
            ],
        },
    }


def build_docker_run_command(
    instance_id: str,
    notebook_path: Path,
    template_location: str | None = None,
    study_code: str | None = None,
  launch_code: str | None = None,
    auth_token: str | None = None,
) -> tuple[list[str], str, int]:
    image = require_instance_container_image()
    host_port = find_free_port()
    container_name = build_cloud_run_service_name(instance_id)
    env_items = build_container_env(
        instance_id,
        template_location=template_location,
        study_code=study_code,
      launch_code=launch_code,
        auth_token=auth_token,
    )
    cmd = [
        "docker",
        "run",
        "--detach",
        "--rm",
        "--name",
        container_name,
        "-p",
        f"127.0.0.1:{host_port}:{INSTANCE_CONTAINER_PORT}",
    ]
    for key, value in env_items.items():
        cmd.extend(["-e", f"{key}={value}"])
    cmd.extend([image, *build_container_entrypoint_command()])
    return cmd, container_name, host_port


def _cloud_run_service_to_record(service: dict) -> InstanceRecord | None:
    if not isinstance(service, dict):
      return None
    service_name = service.get("name")
    if not isinstance(service_name, str) or not service_name:
      return None
    service_url = service.get("uri")
    if not isinstance(service_url, str) or not service_url:
      service_url = None
    labels = service.get("labels") if isinstance(service.get("labels"), dict) else {}
    annotations = service.get("annotations") if isinstance(service.get("annotations"), dict) else {}
    instance_id = labels.get("plainbook-instance") if isinstance(labels, dict) else None
    if not isinstance(instance_id, str) or not instance_id:
      parts = service_name.rsplit("/", 1)
      short_name = parts[-1]
      prefix = f"{CLOUD_RUN_SERVICE_PREFIX}-"
      if short_name.startswith(prefix):
        instance_id = short_name[len(prefix):]
      else:
        return None
    token = build_instance_auth_token(instance_id)
    study_code = annotations.get("plainbook-mux.dev/study-code") if isinstance(annotations, dict) else None
    if not isinstance(study_code, str) or not study_code:
      study_code = None
    return InstanceRecord(
      id=instance_id,
      notebook_path=Path("/workspace/notebook.plnb"),
      public_url=service_url,
      token=token,
      status="running",
      study_code=study_code,
      backend_kind="cloud-run",
      backend_ref=service_name.rsplit("/", 1)[-1],
      backend_url=service_url,
    )


def _cloud_run_service_is_ready(service: dict) -> bool:
  status = service.get("status") if isinstance(service, dict) else None
  if not isinstance(status, dict):
    return False

  conditions = status.get("conditions")
  if isinstance(conditions, list):
    for condition in conditions:
      if not isinstance(condition, dict):
        continue
      if condition.get("type") != "Ready":
        continue
      condition_state = condition.get("state")
      condition_status = condition.get("status")
      return condition_state in {"CONDITION_SUCCEEDED", "True", True, "READY"} or condition_status in {"True", True}

    return False

  return isinstance(status.get("url"), str) and bool(status.get("url"))


def _list_cloud_run_services(session: object, project_id: str) -> list[dict]:
  api_url = f"https://run.googleapis.com/v2/projects/{project_id}/locations/{CLOUD_RUN_REGION}/services"
  services: list[dict] = []
  page_token = ""
  while True:
    url = api_url if not page_token else f"{api_url}?pageToken={page_token}"
    result = session.get(url, timeout=60)
    if result.status_code >= 400:
      break
    try:
      body = result.json()
    except ValueError:
      break
    if not isinstance(body, dict):
      break
    for service in body.get("services", []):
      if isinstance(service, dict):
        services.append(service)
    next_page_token = body.get("nextPageToken")
    if not isinstance(next_page_token, str) or not next_page_token:
      break
    page_token = next_page_token
  return services


def _list_cloud_run_instance_records() -> list[InstanceRecord]:
  try:
    session, project_id = _cloud_run_session_and_project()
  except Exception:
    return []
  records: list[InstanceRecord] = []
  for service in _list_cloud_run_services(session, project_id):
    if not _cloud_run_service_is_ready(service):
      continue
    record = _cloud_run_service_to_record(service)
    if record is not None:
      records.append(record)
  return records


def _wait_for_cloud_run_service_ready(session: object, service_resource_url: str, timeout_seconds: int) -> str:
  """Poll Cloud Run service resource until status.url becomes available."""
  deadline = time.time() + timeout_seconds
  while time.time() < deadline:
    response = session.get(service_resource_url, timeout=30)
    if response.status_code < 400:
      try:
        service = response.json()
      except ValueError:
        service = None
      if isinstance(service, dict):
        service_url = service.get("uri")
        if isinstance(service_url, str) and service_url:
          return service_url
        status = service.get("status")
        if isinstance(status, dict):
          service_url = status.get("url")
          if isinstance(service_url, str) and service_url:
            return service_url
    time.sleep(2)
  raise RuntimeError("Cloud Run service did not become ready in time")


def _extract_cloud_run_token(session: object, project_id: str, service_name: str, timeout_seconds: int = 20) -> str | None:
  """Read Cloud Run revision logs and extract plainbook authentication token."""
  deadline = time.time() + timeout_seconds
  api_url = "https://logging.googleapis.com/v2/entries:list"
  log_filter = (
    f'resource.type="cloud_run_revision" '
    f'resource.labels.service_name="{service_name}" '
    '(textPayload:"Authentication token:" OR jsonPayload.message:"Authentication token:")'
  )
  payload = {
    "resourceNames": [f"projects/{project_id}"],
    "filter": log_filter,
    "orderBy": "timestamp desc",
    "pageSize": 20,
  }

  while time.time() < deadline:
    try:
      result = session.post(api_url, json=payload, timeout=30)
      if result.status_code < 400:
        body = result.json() if result.content else {}
        entries = body.get("entries") if isinstance(body, dict) else None
        if isinstance(entries, list):
          for entry in entries:
            if not isinstance(entry, dict):
              continue
            text_payload = entry.get("textPayload")
            if isinstance(text_payload, str):
              match = TOKEN_RE.search(text_payload)
              if match:
                return match.group(1)
            json_payload = entry.get("jsonPayload")
            if isinstance(json_payload, dict):
              message = json_payload.get("message")
              if isinstance(message, str):
                match = TOKEN_RE.search(message)
                if match:
                  return match.group(1)
    except Exception:
      pass
    time.sleep(1)
  return None


def wait_for_backend_ready(target_url: str, timeout_seconds: int) -> bool:
    deadline = time.time() + timeout_seconds
    while time.time() < deadline:
        if _request_url_is_ready(target_url, timeout_seconds=3):
            return True
        time.sleep(1)
    return False


def build_isolated_command(base_cmd: list[str], sandbox_profile_path: Path, instance_dir: Path, tmp_dir: Path) -> tuple[list[str], str | None]:
    """Build the final command with appropriate isolation for the platform.

    Priority:
    1. macOS: sandbox-exec with sandbox profile
    2. Linux: bwrap (bubblewrap) if available
    3. Fallback: resource limits only
    """
    if not ISOLATION_ENABLED:
        return base_cmd, None

    if sys.platform == "darwin" and MACOS_SANDBOX_ENABLED and shutil.which("sandbox-exec"):
        return ["sandbox-exec", "-f", str(sandbox_profile_path), *base_cmd], "macos-sandbox-exec"

    if sys.platform == "linux":
        if shutil.which("proot"):
            return build_proot_command(base_cmd, instance_dir, tmp_dir), "linux-proot"
        if LINUX_BWRAP_ENABLED and shutil.which("bwrap"):
            return build_proot_command(base_cmd, instance_dir, tmp_dir), "linux-proot-fallback"

    return base_cmd, "resource-limits-only"


def get_process_usage(pid: int) -> dict[str, float | None]:
    """Return live CPU/memory usage for a process using ps command.
    
    Works on both macOS and Linux without external dependencies.
    Falls back to zeros if process is not accessible.
    """
    try:
        # Use ps command with -h (BSD) or no header to avoid header row
        # Format options: %cpu (CPU %), %mem (memory %), rss (RSS in KB)
        result = subprocess.run(
            ["ps", "-p", str(pid), "-o", "%cpu=,%mem=,rss=", "-h"],
            capture_output=True,
            text=True,
            timeout=2,
        )
        
        if result.returncode != 0:
            # Process not found
            return {"cpu_percent": 0.0, "memory_mb": 0.0}
        
        output = result.stdout.strip()
        if not output:
            return {"cpu_percent": 0.0, "memory_mb": 0.0}
        
        # Split by whitespace, handling multiple spaces
        parts = output.split()
        if len(parts) < 3:
            return {"cpu_percent": 0.0, "memory_mb": 0.0}
        
        cpu_percent = float(parts[0])
        memory_rss_kb = float(parts[2])
        memory_mb = memory_rss_kb / 1024.0
        
        return {
            "cpu_percent": round(cpu_percent, 2),
            "memory_mb": round(memory_mb, 2),
        }
    except Exception:
        # Fallback: return zeros if anything fails
        return {
            "cpu_percent": 0.0,
            "memory_mb": 0.0,
        }

def get_directory_size_bytes(path: Path) -> int:
  total = 0
  if not path.exists():
    return 0
  try:
    for child in path.rglob("*"):
      try:
        if child.is_file():
          total += child.stat().st_size
      except OSError:
        continue
  except OSError:
    return total
  return total



def find_free_port(start: int = 18080) -> int:
    port = start
    while True:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            try:
                sock.bind(("127.0.0.1", port))
                return port
            except OSError:
                port += 1

def write_notebook_json(path: Path, markdown_text: str = "") -> None:
    notebook = {
        "cells": [
        ],
        "metadata": {},
        "nbformat": 4,
        "nbformat_minor": 5,
    }
    path.write_text(json.dumps(notebook), encoding="utf-8")


def _access_code_store_gcs_enabled() -> bool:
    return bool(ACCESS_CODE_GCS_BUCKET)


def _access_code_store_object_path(filename: str) -> str:
    if ACCESS_CODE_GCS_PREFIX:
        return f"{ACCESS_CODE_GCS_PREFIX}/{filename}"
    return filename


def _read_store_text(local_path: Path, gcs_filename: str) -> str | None:
    if _access_code_store_gcs_enabled():
        try:
            from google.cloud import storage

            client = storage.Client()
            bucket = client.bucket(ACCESS_CODE_GCS_BUCKET)
            blob = bucket.blob(_access_code_store_object_path(gcs_filename))
            if blob.exists(client):
                return blob.download_as_text()
        except Exception as exc:
            print(f"[plainbook-mux] Warning: failed reading gs://{ACCESS_CODE_GCS_BUCKET}/{_access_code_store_object_path(gcs_filename)}: {exc}")

    if not local_path.exists():
        return None
    try:
        return local_path.read_text(encoding="utf-8")
    except OSError:
        return None


def _write_store_text(local_path: Path, gcs_filename: str, payload: str) -> None:
    local_path.parent.mkdir(parents=True, exist_ok=True)
    local_path.write_text(payload, encoding="utf-8")

    if not _access_code_store_gcs_enabled():
        return

    try:
        from google.cloud import storage

        client = storage.Client()
        bucket = client.bucket(ACCESS_CODE_GCS_BUCKET)
        blob = bucket.blob(_access_code_store_object_path(gcs_filename))
        blob.upload_from_string(payload, content_type="application/json")
    except Exception as exc:
        raise RuntimeError(
            f"Failed writing gs://{ACCESS_CODE_GCS_BUCKET}/{_access_code_store_object_path(gcs_filename)}: {exc}"
        ) from exc


def load_access_code_config() -> dict[str, object]:
    raw = _read_store_text(ACCESS_CODE_CONFIG_FILE, ACCESS_CODES_FILENAME)
    if raw is None:
        return {}
    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError:
        return {}
    if isinstance(parsed, dict):
        return parsed
    return {}


def load_generated_access_codes() -> dict[str, object]:
    raw = _read_store_text(GENERATED_ACCESS_CODE_FILE, GENERATED_ACCESS_CODES_FILENAME)
    if raw is None:
        return {}
    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError:
        return {}
    if isinstance(parsed, dict):
        return parsed
    return {}


def save_generated_access_codes(config: dict[str, object]) -> None:
  payload = json.dumps(config, indent=2, sort_keys=True) + "\n"
  _write_store_text(GENERATED_ACCESS_CODE_FILE, GENERATED_ACCESS_CODES_FILENAME, payload)


def list_study_codes() -> list[str]:
    return sorted(load_access_code_config().keys())


def resolve_study_code_for_launch(launch_code: str) -> str | None:
    code = launch_code.strip()
    if not code:
        return None

    access_config = load_access_code_config()
    if code in access_config:
        return code

    generated_config = load_generated_access_codes()
    entry = generated_config.get(code)
    if isinstance(entry, str):
        return entry if entry in access_config else None
    if isinstance(entry, dict):
        study_code = entry.get("study_code")
        if isinstance(study_code, str) and study_code in access_config:
            return study_code
    return None


def mark_generated_code_used(launch_code: str) -> None:
    generated_config = load_generated_access_codes()
    entry = generated_config.get(launch_code)
    if not isinstance(entry, dict):
        return
    used_count = entry.get("used_count", 0)
    if not isinstance(used_count, int):
        used_count = 0
    entry["used_count"] = used_count + 1
    entry["last_used_at"] = int(time.time())
    generated_config[launch_code] = entry
    save_generated_access_codes(generated_config)


def generate_unique_access_code(length: int = 10) -> str:
    alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"
    generated_config = load_generated_access_codes()
    access_config = load_access_code_config()
    while True:
        code = "".join(secrets.choice(alphabet) for _ in range(length))
        if code not in generated_config and code not in access_config:
            return code


def has_access_code(launch_code: str) -> bool:
    return resolve_study_code_for_launch(launch_code) is not None


def save_access_code_config(config: dict[str, object]) -> None:
  payload = json.dumps(config, indent=2, sort_keys=True) + "\n"
  _write_store_text(ACCESS_CODE_CONFIG_FILE, ACCESS_CODES_FILENAME, payload)


def read_access_code_config_text() -> str:
  raw = _read_store_text(ACCESS_CODE_CONFIG_FILE, ACCESS_CODES_FILENAME)
  if raw is None:
    return "{}\n"
  return raw


def get_template_location_for_code(launch_code: str) -> str | None:
    resolved_study_code = resolve_study_code_for_launch(launch_code)
    if not resolved_study_code:
        return None

    config = load_access_code_config()
    entry = config.get(resolved_study_code)
    if isinstance(entry, str):
        return entry.strip() or None
    if isinstance(entry, dict):
        for key in ("template", "template_uri", "template_url", "location", "source"):
            value = entry.get(key)
            if isinstance(value, str) and value.strip():
                return value.strip()
    return None


def fetch_text_from_url(url: str) -> str:
  try:
    with urlopen(url) as response_stream:
      raw_bytes = response_stream.read()
      charset = response_stream.headers.get_content_charset() or "utf-8"
      return raw_bytes.decode(charset)
  except URLLibHTTPError as exc:
    if exc.code in {403, 404}:
      raise FileNotFoundError(TEMPLATE_EXPIRED_MESSAGE) from exc
    raise
  except URLError as exc:
    raise FileNotFoundError(TEMPLATE_EXPIRED_MESSAGE) from exc


def read_template_source(template_location: str) -> str:
    location = template_location.strip()
    if not location:
        raise FileNotFoundError("Template location is empty")

    parsed_location = urlsplit(location)
    if parsed_location.scheme in {"http", "https"}:
        return fetch_text_from_url(location)
    if parsed_location.scheme == "gs":
        if not parsed_location.netloc or not parsed_location.path:
            raise FileNotFoundError(f"Invalid Google Cloud Storage location: {location}")
        gcs_url = f"https://storage.googleapis.com/{parsed_location.netloc}{parsed_location.path}"
        return fetch_text_from_url(gcs_url)
    if parsed_location.scheme == "file":
        template_path = Path(parsed_location.path)
    else:
        template_path = Path(location)
        if not template_path.is_absolute():
            template_path = TEMPLATE_DIR / template_path

    return template_path.read_text(encoding="utf-8")


def prepare_notebook_for_code(notebook_path: Path, launch_code: str | None) -> None:
    template_location = get_template_location_for_code(launch_code or "")
    if template_location is None:
      # If there is no template configured for this access code, let plainbook initialize the notebook itself.
        return

    try:
      template_raw = read_template_source(template_location)
    except (OSError, ValueError) as exc:
      raise FileNotFoundError(
        f"Unable to load template for {launch_code or 'unknown code'} from {template_location}: {exc}"
      ) from exc

    # Accept either a full notebook JSON template or plain text instructions.
    try:
        parsed = json.loads(template_raw)
        if isinstance(parsed, dict) and parsed.get("nbformat") and isinstance(parsed.get("cells"), list):
            notebook_path.write_text(template_raw, encoding="utf-8")
            return
    except json.JSONDecodeError:
        pass

    write_notebook_json(notebook_path, markdown_text=template_raw)


@dataclass
class InstanceRecord:
    id: str
    notebook_path: Path
    port: int = 0
    process: subprocess.Popen | None = None
    created_at: float = field(default_factory=time.time)
    public_url: str | None = None
    token: str | None = None
    status: str = "starting"
    last_output: str = ""
    exit_code: int | None = None
    launch_code: str | None = None
    study_code: str | None = None
    instance_dir: Path | None = None
    isolation_mode: str | None = None
    backend_kind: str = "process"
    backend_ref: str | None = None
    backend_url: str | None = None

    def to_dict(self) -> dict:
        usage = get_process_usage(self.process.pid) if self.process is not None else None
        return {
            "id": self.id,
            "pid": self.process.pid if self.process is not None else None,
            "notebook_path": str(self.notebook_path),
            "port": self.port,
            "public_url": self.public_url,
            "token": self.token,
            "status": self.status,
            "created_at": self.created_at,
            "created_at_label": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(self.created_at)),
            "last_output": self.last_output[-2000:],
            "exit_code": self.exit_code,
            "launch_code": self.launch_code,
            "study_code": self.study_code,
            "instance_dir": str(self.instance_dir) if self.instance_dir else None,
            "isolation_mode": self.isolation_mode,
            "backend_kind": self.backend_kind,
            "backend_ref": self.backend_ref,
            "backend_url": self.backend_url,
            "usage": usage,
        }


class PlainbookLauncher:
  def __init__(self) -> None:
    self._lock = threading.Lock()
    self._instances: dict[str, InstanceRecord] = {}
    self._container_tokens_cache: dict[str, str] = {}  # Maps instance_id to token for containers
    self._recently_stopped_launch_codes: dict[str, float] = {}

  def _prune_recently_stopped_launch_codes_locked(self) -> None:
    now = time.time()
    expired = [code for code, expiry in self._recently_stopped_launch_codes.items() if expiry <= now]
    for code in expired:
      self._recently_stopped_launch_codes.pop(code, None)

  def _mark_launch_code_recently_stopped_locked(self, launch_code: str | None) -> None:
    code = (launch_code or "").strip()
    if not code:
      return
    self._prune_recently_stopped_launch_codes_locked()
    self._recently_stopped_launch_codes[code] = time.time() + LAUNCH_CODE_RECENT_STOP_GRACE_SECONDS

  def _update_record_from_line(self, record: InstanceRecord, line: str) -> None:
    clean_line = ANSI_ESCAPE_RE.sub("", line)
    with self._lock:
      record.last_output += clean_line
      token_match = TOKEN_RE.search(clean_line)
      if token_match:
        record.token = token_match.group(1)
      url_match = PLAINBOOK_URL_RE.search(clean_line)
      if url_match:
        candidate = url_match.group(1).strip().rstrip(")>,.;")
        try:
          parsed = urlsplit(candidate)
          if parsed.scheme in {"http", "https"} and parsed.netloc:
            parsed_path = parsed.path if parsed.path.startswith("/") else f"/{parsed.path}"
            if parsed_path in {"", "/"}:
              record.public_url = f"/instance/{record.id}/"
            else:
              record.public_url = f"/instance/{record.id}{parsed_path}"
        except Exception:
          pass

  def _finalize_record(self, record: InstanceRecord) -> None:
    exit_code = record.process.poll() if record.process is not None else record.exit_code
    with self._lock:
      record.exit_code = exit_code
      if exit_code is not None and record.status not in {"stopping", "stopped"}:
        record.status = "exited" if exit_code else "finished"

  def _spawn_reader(self, record: InstanceRecord) -> None:
    def reader() -> None:
      assert record.process is not None and record.process.stdout is not None
      for line in iter(record.process.stdout.readline, ""):
        if not line:
          break
        self._update_record_from_line(record, line)
        if record.process.poll() is not None:
          break
      self._finalize_record(record)

    thread = threading.Thread(target=reader, daemon=True)
    thread.start()

  def _apply_instance_permissions(self, instance_dir: Path, tmp_dir: Path, notebook_path: Path) -> None:
    if INSTANCE_UID is None or INSTANCE_GID is None or os.geteuid() != 0:
      return
    try:
      os.chown(instance_dir, INSTANCE_UID, INSTANCE_GID)
      os.chmod(instance_dir, 0o700)
    except OSError:
      pass
    for path in [tmp_dir, notebook_path]:
      try:
        os.chown(path, INSTANCE_UID, INSTANCE_GID)
      except OSError:
        pass

  def _record_is_running(self, record: InstanceRecord) -> bool:
    if record.backend_kind == "process":
      return record.process is not None and record.process.poll() is None
    return record.status not in {"stopped", "exited", "finished"}

  def _start_docker_instance(
      self,
      instance_id: str,
      notebook_path: Path,
      template_location: str | None = None,
      study_code: str | None = None,
      launch_code: str | None = None,
  ) -> tuple[str, str, int]:
    container_token = build_instance_auth_token(instance_id)
    cmd, container_name, host_port = build_docker_run_command(
        instance_id,
        notebook_path,
        template_location=template_location,
        study_code=study_code,
      launch_code=launch_code,
        auth_token=container_token,
    )
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
    if result.returncode != 0:
      output = (result.stderr or result.stdout or "").strip()
      raise RuntimeError(output or "Failed to start Docker container")
    container_id = result.stdout.strip() or container_name
    backend_url = f"http://127.0.0.1:{host_port}"
    with self._lock:
      self._container_tokens_cache[instance_id] = container_token
    return container_id, backend_url, host_port

  def _start_cloud_run_instance(
      self,
      instance_id: str,
      notebook_path: Path,
      template_location: str | None = None,
      study_code: str | None = None,
      launch_code: str | None = None,
  ) -> tuple[str, str]:
    service_name = build_cloud_run_service_name(instance_id)
    session, project_id = _cloud_run_session_and_project()
    parent_path = f"projects/{project_id}/locations/{CLOUD_RUN_REGION}"
    api_base_url = f"https://run.googleapis.com/v2/{parent_path}/services"
    api_url = f"{api_base_url}?serviceId={service_name}"
    container_token = build_instance_auth_token(instance_id)
    payload = build_cloud_run_service_body(
      instance_id,
      notebook_path,
      auth_token=container_token,
      template_location=template_location,
      study_code=study_code,
      launch_code=launch_code,
    )
    result = session.post(api_url, json=payload, timeout=120)
    if result.status_code >= 400:
      detail = result.text.strip()
      raise RuntimeError(detail or f"Cloud Run service creation failed with HTTP {result.status_code}")
    service_resource_url = f"{api_base_url}/{service_name}"
    service_url = _wait_for_cloud_run_service_ready(session, service_resource_url, 180)
    with self._lock:
      self._container_tokens_cache[instance_id] = container_token
    return service_name, service_url

  def start(self, launch_code: str | None = None, template_code: str | None = None) -> InstanceRecord:
    if launch_code:
      existing = self.find_running_instance_by_launch_code(launch_code)
      if existing is not None:
        return existing

    instance_id = uuid.uuid4().hex[:10]
    instance_dir, tmp_dir, sandbox_profile_path = build_instance_paths(instance_id)
    instance_dir.mkdir(parents=True, exist_ok=True)
    tmp_dir.mkdir(parents=True, exist_ok=True)
    notebook_path = instance_dir / "notebook.plnb"
    template_location = get_template_location_for_code(launch_code or "")
    study_code = template_code or launch_code
    prepare_notebook_for_code(notebook_path, template_code or launch_code)
    if INSTANCE_BACKEND in {"docker", "cloud-run"} and not notebook_path.exists():
      write_notebook_json(notebook_path, markdown_text="")

    if launch_code:
      code_stats.record_usage(launch_code)

    if INSTANCE_BACKEND == "docker":
      backend_ref, backend_url, port = self._start_docker_instance(
        instance_id,
        notebook_path,
        template_location=template_location,
        study_code=study_code,
        launch_code=launch_code,
      )
      record = InstanceRecord(
        id=instance_id,
        notebook_path=notebook_path,
        port=port,
        launch_code=launch_code,
          study_code=study_code,
        instance_dir=instance_dir,
        public_url=f"/instance/{instance_id}/",
        status="running",
        backend_kind="docker",
        backend_ref=backend_ref,
        backend_url=backend_url,
      )
      # Set the cached token for container backends
      with self._lock:
        cached_token = self._container_tokens_cache.get(instance_id)
        if cached_token:
          record.token = cached_token
    elif INSTANCE_BACKEND == "cloud-run":
      backend_ref, backend_url = self._start_cloud_run_instance(
        instance_id,
        notebook_path,
        template_location=template_location,
        study_code=study_code,
        launch_code=launch_code,
      )
      record = InstanceRecord(
        id=instance_id,
        notebook_path=notebook_path,
        launch_code=launch_code,
          study_code=study_code,
        instance_dir=instance_dir,
        public_url=backend_url,
        status="running",
        backend_kind="cloud-run",
        backend_ref=backend_ref,
        backend_url=backend_url,
      )
      # Set the cached token for container backends
      with self._lock:
        cached_token = self._container_tokens_cache.get(instance_id)
        if cached_token:
          record.token = cached_token
    else:
      port = find_free_port()
      env = build_instance_env(instance_dir, tmp_dir, study_code=study_code, launch_code=launch_code)
      self._apply_instance_permissions(instance_dir, tmp_dir, notebook_path)

      if ISOLATION_ENABLED and sys.platform == "darwin" and MACOS_SANDBOX_ENABLED and shutil.which("sandbox-exec"):
        sandbox_profile_path.write_text(build_macos_sandbox_profile(instance_dir), encoding="utf-8")

      base_cmd = build_plainbook_command(notebook_path, port, user_study_enabled=bool(study_code))
      cmd, isolation_mode = build_isolated_command(base_cmd, sandbox_profile_path, instance_dir, tmp_dir)

      process = subprocess.Popen(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        bufsize=1,
        env=env,
        cwd=str(instance_dir),
        preexec_fn=build_preexec_fn() if ISOLATION_ENABLED else os.setsid,
      )
      record = InstanceRecord(
        id=instance_id,
        notebook_path=notebook_path,
        port=port,
        process=process,
        launch_code=launch_code,
          study_code=study_code,
        instance_dir=instance_dir,
        isolation_mode=isolation_mode,
        backend_kind="process",
        backend_url=f"http://127.0.0.1:{port}",
      )
      self._spawn_reader(record)

    with self._lock:
      self._instances[instance_id] = record

    if record.backend_kind == "process":
      deadline = time.time() + 10
      while time.time() < deadline:
        with self._lock:
          if record.public_url:
            record.status = "running"
            return record
          if record.process is not None and record.process.poll() is not None:
            break
        time.sleep(0.1)

      with self._lock:
        if record.process is not None and record.process.poll() is None:
          record.status = "starting"
        elif record.status not in {"stopping", "stopped"}:
          record.status = "exited"
      return record

    wait_seconds = 60 if record.backend_kind == "cloud-run" else 20
    if wait_for_backend_ready(record.backend_url or "", wait_seconds):
      with self._lock:
        record.status = "running"
    else:
      with self._lock:
        record.status = "starting"
    return record

  def list_instances(self) -> list[dict]:
    with self._lock:
      records = list(self._instances.values())
    if INSTANCE_BACKEND == "cloud-run":
      records_by_ref = {record.backend_ref: record for record in records if record.backend_ref}
      for remote_record in _list_cloud_run_instance_records():
        if remote_record.backend_ref and remote_record.backend_ref not in records_by_ref:
          records.append(remote_record)
    rows = []
    for record in records:
      if self._record_is_running(record):
        health_target = _build_instance_healthcheck_url(record)
        if record.backend_kind in {"docker", "cloud-run"} and health_target:
          if _request_url_is_ready(health_target, timeout_seconds=2):
            if record.status == "starting":
              record.status = "running"
          else:
            if record.backend_kind == "cloud-run" and record.status in {"running", "starting"}:
              # Cloud Run can briefly fail probes during cold start/revision transitions.
              record.status = "starting"
            elif record.status == "running":
              record.status = "stopped"
              record.public_url = None
      elif record.status in {"running", "starting"}:
        record.status = "stopped"
      rows.append(record.to_dict())
    rows.sort(key=lambda row: row["created_at"], reverse=True)
    return rows

  def find_running_instance_by_token(self, token: str) -> InstanceRecord | None:
    if not token:
      return None
    with self._lock:
      for record in self._instances.values():
        if self._record_is_running(record) and record.token == token:
          return record
    return None

  def find_running_instance_by_id(self, instance_id: str) -> InstanceRecord | None:
    if not instance_id:
      return None
    with self._lock:
      record = self._instances.get(instance_id)
      if record and self._record_is_running(record):
        return record
    return None

  def find_running_instance_by_launch_code(self, launch_code: str) -> InstanceRecord | None:
    code = launch_code.strip()
    if not code:
      return None
    recent_stop_block = False
    with self._lock:
      self._prune_recently_stopped_launch_codes_locked()
      for record in self._instances.values():
        if record.launch_code == code and self._record_is_running(record):
          return record
      recent_stop_block = self._recently_stopped_launch_codes.get(code, 0.0) > time.time()
    if recent_stop_block:
      return None
    if INSTANCE_BACKEND == "cloud-run":
      launch_hash = build_launch_code_hash(code)
      for service in _list_cloud_run_services(*_cloud_run_session_and_project()):
        if not _cloud_run_service_is_ready(service):
          continue
        labels = service.get("labels") if isinstance(service, dict) else {}
        if not isinstance(labels, dict):
          continue
        if labels.get("plainbook-launch-hash") != launch_hash:
          continue
        record = _cloud_run_service_to_record(service)
        if record is not None:
          record.launch_code = code
          return record
    return None

  def get_single_running_instance(self) -> InstanceRecord | None:
    with self._lock:
      running = [record for record in self._instances.values() if self._record_is_running(record)]
    if len(running) == 1:
      return running[0]
    return None

  def get(self, instance_id: str) -> InstanceRecord | None:
    with self._lock:
      return self._instances.get(instance_id)

  def _mark_record_stopped(self, record: InstanceRecord) -> None:
    with self._lock:
      record.exit_code = record.process.returncode if record.process is not None else record.exit_code
      record.status = "stopped"
      record.public_url = None
      self._mark_launch_code_recently_stopped_locked(record.launch_code)

  def _mark_record_stopping(self, record: InstanceRecord) -> None:
    with self._lock:
      record.status = "stopping"

  def mark_cloud_run_record_stopped(self, instance_id: str, backend_ref: str | None = None) -> None:
    with self._lock:
      for record in self._instances.values():
        if record.backend_kind != "cloud-run":
          continue
        id_match = bool(instance_id) and record.id == instance_id
        ref_match = bool(backend_ref) and record.backend_ref == backend_ref
        if not id_match and not ref_match:
          continue
        record.status = "stopped"
        record.public_url = None
        self._mark_launch_code_recently_stopped_locked(record.launch_code)

  def _stop_docker_instance(self, record: InstanceRecord) -> None:
    if not record.backend_ref:
      return
    subprocess.run(["docker", "rm", "-f", record.backend_ref], capture_output=True, text=True, check=False)

  def _stop_cloud_run_instance(self, record: InstanceRecord) -> None:
    if not record.backend_ref:
      return
    self._stop_cloud_run_service(record.backend_ref)

  def _stop_cloud_run_service(self, service_name: str, allow_not_found: bool = False) -> bool:
    session, project_id = _cloud_run_session_and_project()
    api_url = f"https://run.googleapis.com/v2/projects/{project_id}/locations/{CLOUD_RUN_REGION}/services/{service_name}"
    result = session.delete(api_url, timeout=120)
    if result.status_code == 404:
      return allow_not_found
    return result.status_code < 400

  def _stop_cloud_run_instance_by_id(self, instance_id: str) -> bool:
    try:
      service_names = [build_cloud_run_service_name(instance_id)]
      default_name = f"plainbook-instance-{instance_id}".lower()
      if default_name not in service_names:
        service_names.append(default_name)
      for service_name in service_names:
        if self._stop_cloud_run_service(service_name):
          return True

      # Fallback for cross-replica cases: resolve service names by label or suffix pattern.
      session, project_id = _cloud_run_session_and_project()
      for service in _list_cloud_run_services(session, project_id):
        if not isinstance(service, dict):
          continue
        service_resource_name = service.get("name")
        if not isinstance(service_resource_name, str) or not service_resource_name:
          continue
        short_name = service_resource_name.rsplit("/", 1)[-1]
        labels = service.get("labels")
        label_match = isinstance(labels, dict) and labels.get("plainbook-instance") == instance_id
        name_match = short_name == build_cloud_run_service_name(instance_id) or short_name.endswith(f"-{instance_id}")
        if not label_match and not name_match:
          continue
        if self._stop_cloud_run_service(short_name):
          return True

      return False
    except Exception:
      return False

  def stop_cloud_run_by_ref(self, backend_ref: str) -> bool:
    if not backend_ref:
      return False
    try:
      return self._stop_cloud_run_service(backend_ref)
    except Exception:
      return False

  def stop_cloud_run_by_hint(self, hint: str) -> bool:
    if not hint:
      return False
    try:
      session, project_id = _cloud_run_session_and_project()
      for service in _list_cloud_run_services(session, project_id):
        if not isinstance(service, dict):
          continue
        service_resource_name = service.get("name")
        if not isinstance(service_resource_name, str) or not service_resource_name:
          continue
        short_name = service_resource_name.rsplit("/", 1)[-1]
        labels = service.get("labels") if isinstance(service.get("labels"), dict) else {}
        label_instance = labels.get("plainbook-instance") if isinstance(labels, dict) else None
        if (
          short_name == hint
          or short_name.endswith(f"-{hint}")
          or hint in short_name
          or label_instance == hint
        ):
          if self._stop_cloud_run_service(short_name):
            return True
      return False
    except Exception:
      return False

  def _terminate_process(self, process: subprocess.Popen) -> None:
    try:
      os.killpg(process.pid, signal.SIGTERM)
    except OSError:
      process.terminate()
    try:
      process.wait(timeout=5)
    except subprocess.TimeoutExpired:
      try:
        os.killpg(process.pid, signal.SIGKILL)
      except OSError:
        process.kill()
      process.wait()

  def stop(self, instance_id: str) -> bool:
    record = self.get(instance_id)
    if record is None:
      if self._stop_cloud_run_instance_by_id(instance_id):
        return True
      return False

    if not self._record_is_running(record):
      self._mark_record_stopped(record)
      return True

    self._mark_record_stopping(record)
    if record.backend_kind == "process" and record.process is not None:
      self._terminate_process(record.process)
    elif record.backend_kind == "docker":
      self._stop_docker_instance(record)
    elif record.backend_kind == "cloud-run":
      self._stop_cloud_run_instance(record)
    self._mark_record_stopped(record)
    return True

  def stop_all(self) -> int:
    with self._lock:
      instance_ids = list(self._instances.keys())
    stopped_instances = 0
    for instance_id in instance_ids:
      if self.stop(instance_id):
        stopped_instances += 1
    return stopped_instances

  def has_running_instances(self) -> bool:
    with self._lock:
      return any(self._record_is_running(record) for record in self._instances.values())

  def delete_runtime_files(self) -> dict:
    if self.has_running_instances():
      raise RuntimeError("Cannot delete runtime files while instances are running")

    deleted_files = 0
    deleted_bytes = 0
    for path in RUNTIME_DIR.iterdir():
      if path.resolve() == STATS_FILE.resolve():
        continue
      try:
        if path.is_dir():
          deleted_bytes += get_directory_size_bytes(path)
          shutil.rmtree(path, ignore_errors=True)
          deleted_files += 1
        else:
          if path.exists():
            deleted_bytes += path.stat().st_size
          path.unlink(missing_ok=True)
          deleted_files += 1
      except OSError:
        continue

    RUNTIME_DIR.mkdir(parents=True, exist_ok=True)
    return {
      "deleted_files": deleted_files,
      "deleted_bytes": deleted_bytes,
    }


_shutdown_lock = threading.Lock()
_shutdown_complete = False


def shutdown_all_instances() -> None:
  global _shutdown_complete
  with _shutdown_lock:
    if _shutdown_complete:
      return
    _shutdown_complete = True
  try:
    launcher.stop_all()
  except Exception:
    # Do not block process shutdown if cleanup hits a race.
    pass


def install_shutdown_handlers() -> None:
  atexit.register(shutdown_all_instances)

  def _handle_signal(_signum, _frame) -> None:
    shutdown_all_instances()
    raise SystemExit(0)

  for sig in (signal.SIGTERM, signal.SIGINT):
    try:
      signal.signal(sig, _handle_signal)
    except Exception:
      continue


launcher = PlainbookLauncher()
install_shutdown_handlers()
code_stats = CodeStatsManager(STATS_FILE)
app = Bottle()

USER_PAGE_HTML = """<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Launch Plainbook</title>
  <style>
    :root {
      --bg0: #071325;
      --bg1: #0f2745;
      --panel: rgba(11, 24, 46, 0.75);
      --line: rgba(255,255,255,0.14);
      --text: #eef4ff;
      --muted: #bfd0ec;
      --accent: #ffd166;
      --accent2: #f78c6b;
      --shadow: 0 30px 80px rgba(0,0,0,0.35);
    }
    * { box-sizing: border-box; }
    body {
      margin: 0;
      min-height: 100vh;
      color: var(--text);
      font-family: "Avenir Next", "Trebuchet MS", sans-serif;
      background:
        radial-gradient(circle at 12% 10%, rgba(255, 209, 102, 0.15), transparent 30%),
        radial-gradient(circle at 85% 15%, rgba(247, 140, 107, 0.16), transparent 28%),
        linear-gradient(140deg, var(--bg0), var(--bg1));
      display: grid;
      place-items: center;
      padding: 20px;
    }
    .card {
      width: min(680px, 100%);
      border: 1px solid var(--line);
      border-radius: 26px;
      background: var(--panel);
      box-shadow: var(--shadow);
      backdrop-filter: blur(16px);
      padding: 28px;
    }
    h1 {
      margin: 0 0 10px;
      font-size: clamp(2rem, 6vw, 3.8rem);
      letter-spacing: -0.05em;
      line-height: 0.95;
    }
    p {
      margin: 0 0 18px;
      color: var(--muted);
      line-height: 1.6;
    }
    label {
      display: block;
      margin-bottom: 10px;
      font-weight: 600;
      letter-spacing: 0.02em;
    }
    input {
      width: 100%;
      border: 1px solid rgba(255,255,255,0.22);
      background: rgba(255,255,255,0.06);
      color: var(--text);
      border-radius: 14px;
      padding: 14px;
      font: inherit;
      outline: none;
    }
    input:focus {
      border-color: var(--accent);
      box-shadow: 0 0 0 3px rgba(255,209,102,0.2);
    }
    .row {
      margin-top: 14px;
      display: flex;
      gap: 10px;
      flex-wrap: wrap;
    }
    button {
      appearance: none;
      border: 0;
      border-radius: 999px;
      padding: 12px 18px;
      font: inherit;
      cursor: pointer;
      font-weight: 700;
    }
    .primary {
      color: #161008;
      background: linear-gradient(135deg, var(--accent), var(--accent2));
    }
    .status {
      margin-top: 14px;
      border-radius: 12px;
      padding: 10px 12px;
      background: rgba(255,255,255,0.08);
      color: var(--muted);
      min-height: 24px;
    }
  </style>
</head>
<body>
  <main class="card">
    <h1>Plainbook Launch</h1>
    <p>Enter your code and start a new plainbook instance. The code must exist in the access-code list managed by the administrator.</p>
    <label for="launch-code">Access code</label>
    <input id="launch-code" type="text" placeholder="ex: team-alpha" autocomplete="off">
    <div class="row">
      <button class="primary" id="start-btn" type="button" onclick="launchPlainbook()">Start Plainbook</button>
    </div>
    <div class="status" id="status">Ready.</div>
  </main>
  <script>
    const statusBox = document.getElementById('status');
    const startBtn = document.getElementById('start-btn');
    const codeInput = document.getElementById('launch-code');
    let launchInProgress = false;

    function buildLaunchUrl(payload) {
      const rawUrl = payload && payload.public_url ? String(payload.public_url) : '';
      if (!rawUrl) {
        return '';
      }
      const url = new URL(rawUrl, window.location.origin);
      const token = payload && payload.token ? String(payload.token) : '';
      if (token && !url.searchParams.get('token')) {
        url.searchParams.set('token', token);
      }
      return url.toString();
    }

    function setStatus(message) {
      statusBox.textContent = message;
    }

    async function launchPlainbook() {
      if (launchInProgress) {
        return;
      }
      const code = codeInput.value.trim();
      if (!code) {
        setStatus('Please enter a code first.');
        return;
      }
      launchInProgress = true;
      startBtn.disabled = true;
      startBtn.textContent = 'Launching...';
      setStatus('Starting a new plainbook instance...');
      try {
        const response = await fetch('/api/launch', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ code }),
        });
        const contentType = response.headers.get('content-type') || '';
        const payload = contentType.includes('application/json')
          ? await response.json()
          : await response.text();
        if (!response.ok) {
          const message = typeof payload === 'object' && payload !== null
            ? (payload.error || payload.message || 'Launch failed')
            : String(payload || 'Launch failed');
          throw new Error(message);
        }
        if (payload.public_url) {
          const targetUrl = buildLaunchUrl(payload);
          if (!targetUrl) {
            throw new Error('Instance URL unavailable');
          }
          const openedWindow = window.open(targetUrl, '_blank', 'noopener,noreferrer');
          if (openedWindow) {
            setStatus('Instance ready. Opened in a new tab.');
          } else {
            setStatus(`Instance ready. Open it here: ${targetUrl}`);
          }
        } else {
          setStatus('Instance started and is initializing. Please try again shortly.');
        }
      } catch (error) {
        const rawMessage = error && error.message ? String(error.message) : 'Launch failed';
        if (rawMessage.includes('did not match the expected pattern')) {
          setStatus('Access code wrong, please contact the adminitrator');
        } else {
          setStatus(rawMessage);
        }
      } finally {
        startBtn.disabled = false;
        startBtn.textContent = 'Start Plainbook';
        launchInProgress = false;
      }
    }
  </script>
</body>
</html>
"""


ADMIN_LOGIN_HTML = """<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Admin Login</title>
  <style>
    body {
      margin: 0;
      min-height: 100vh;
      display: grid;
      place-items: center;
      font-family: "Avenir Next", "Trebuchet MS", sans-serif;
      background: linear-gradient(140deg, #10131f, #1a2240);
      color: #edf2ff;
      padding: 20px;
    }
    form {
      width: min(430px, 100%);
      background: rgba(8, 12, 26, 0.72);
      border: 1px solid rgba(255,255,255,0.12);
      border-radius: 18px;
      padding: 22px;
    }
    h1 { margin: 0 0 8px; font-size: 1.8rem; }
    p { margin: 0 0 14px; color: #b7c3e6; }
    input {
      width: 100%;
      border: 1px solid rgba(255,255,255,0.24);
      border-radius: 12px;
      padding: 12px;
      font: inherit;
      margin-bottom: 10px;
      background: rgba(255,255,255,0.05);
      color: #edf2ff;
    }
    button {
      border: 0;
      border-radius: 999px;
      padding: 10px 16px;
      font: inherit;
      font-weight: 700;
      cursor: pointer;
      background: linear-gradient(135deg, #8df6d8, #86a8ff);
      color: #0c1224;
    }
    .error {
      color: #ff9aac;
      min-height: 18px;
      margin-bottom: 8px;
      font-size: 0.92rem;
    }
  </style>
</head>
<body>
  <form method="post" action="/admin/login">
    <h1>Admin Login</h1>
    <p>Enter the admin password to access the session dashboard.</p>
    <div class="error">__ERROR__</div>
    <input type="password" name="password" placeholder="Admin password" required autofocus>
    <button type="submit">Sign in</button>
  </form>
</body>
</html>
"""


ADMIN_PAGE_HTML = """<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Plainbook Mux</title>
  <style>
    :root {
      color-scheme: dark;
      --bg0: #070816;
      --bg1: #111833;
      --bg2: #1b2344;
      --panel: rgba(9, 13, 28, 0.78);
      --line: rgba(255, 255, 255, 0.10);
      --text: #f4f6ff;
      --muted: #a8b2d9;
      --accent: #7cf7d4;
      --accent2: #7da7ff;
      --warn: #ffcf5c;
      --danger: #ff7d8d;
      --shadow: 0 26px 72px rgba(0, 0, 0, 0.36);
    }
    * { box-sizing: border-box; }
    body {
      margin: 0;
      min-height: 100vh;
      color: var(--text);
      font-family: "Avenir Next", "Gill Sans", "Trebuchet MS", sans-serif;
      background:
        radial-gradient(circle at top left, rgba(124,247,212,0.16), transparent 28%),
        radial-gradient(circle at 80% 18%, rgba(125,167,255,0.18), transparent 26%),
        linear-gradient(135deg, var(--bg0), var(--bg1) 48%, var(--bg2));
    }
    .wrap {
      width: min(1180px, calc(100vw - 32px));
      margin: 0 auto;
      padding: 28px 0 44px;
    }
    .hero {
      display: grid;
      grid-template-columns: 1.25fr 0.95fr;
      gap: 18px;
      margin-bottom: 18px;
    }
    .panel {
      background: var(--panel);
      border: 1px solid var(--line);
      border-radius: 24px;
      box-shadow: var(--shadow);
      backdrop-filter: blur(18px);
    }
    .hero-copy, .hero-actions, .list-panel {
      padding: 24px;
    }
    .eyebrow {
      display: inline-flex;
      align-items: center;
      gap: 8px;
      color: var(--accent);
      text-transform: uppercase;
      letter-spacing: 0.15em;
      font-size: 0.75rem;
      margin-bottom: 10px;
    }
    .eyebrow::before {
      content: "";
      width: 10px;
      height: 10px;
      border-radius: 999px;
      background: linear-gradient(135deg, var(--accent), var(--accent2));
      box-shadow: 0 0 20px rgba(124,247,212,0.55);
    }
    h1 {
      margin: 0 0 14px;
      font-size: clamp(2.4rem, 5vw, 4.9rem);
      line-height: 0.95;
      letter-spacing: -0.06em;
    }
    .lede {
      margin: 0;
      max-width: 60ch;
      color: var(--muted);
      line-height: 1.65;
      font-size: 1.02rem;
    }
    .stats {
      display: grid;
      grid-template-columns: repeat(3, minmax(0, 1fr));
      gap: 12px;
      margin-top: 20px;
    }
    .stat, .launch-card {
      border-radius: 18px;
      border: 1px solid rgba(255,255,255,0.08);
      background: rgba(255,255,255,0.04);
    }
    .stat {
      padding: 14px 16px;
    }
    .stat strong {
      display: block;
      font-size: 1.2rem;
      margin-bottom: 4px;
    }
    .stat span, .meta, .footnote, .list-header p {
      color: var(--muted);
    }
    .hero-actions {
      display: flex;
      flex-direction: column;
      justify-content: space-between;
      gap: 14px;
    }
    .launch-card {
      padding: 18px;
      background: linear-gradient(180deg, rgba(124,247,212,0.14), rgba(125,167,255,0.09));
      border-color: rgba(124,247,212,0.18);
    }
    .launch-card p {
      margin: 0 0 14px;
      line-height: 1.55;
      color: #dbe4ff;
    }
    .button-row, .actions {
      display: flex;
      flex-wrap: wrap;
      gap: 10px;
    }
    button {
      appearance: none;
      border: 0;
      border-radius: 999px;
      cursor: pointer;
      font: inherit;
      padding: 12px 18px;
      transition: transform 140ms ease, opacity 140ms ease;
    }
    button:hover { transform: translateY(-1px); }
    button:disabled { cursor: wait; opacity: 0.6; transform: none; }
    .primary {
      background: linear-gradient(135deg, var(--accent), var(--accent2));
      color: #081020;
      font-weight: 700;
      box-shadow: 0 14px 34px rgba(125,167,255,0.24);
    }
    .secondary {
      background: rgba(255,255,255,0.08);
      color: var(--text);
      border: 1px solid rgba(255,255,255,0.10);
    }
    .code {
      font-family: "SFMono-Regular", Consolas, "Liberation Mono", monospace;
      background: rgba(0,0,0,0.26);
      border: 1px solid rgba(255,255,255,0.08);
      border-radius: 14px;
      padding: 12px 14px;
      overflow-x: auto;
      color: #dce7ff;
    }
    .list-panel {
      margin-top: 18px;
    }
    .list-header {
      display: flex;
      justify-content: space-between;
      gap: 12px;
      align-items: baseline;
      margin-bottom: 16px;
    }
    .list-header h2 {
      margin: 0;
      font-size: 1.25rem;
    }
    .cards {
      display: grid;
      gap: 12px;
      contain: layout style;
    }
    .card {
      display: grid;
      gap: 12px;
      grid-template-columns: 1.2fr 0.9fr auto;
      align-items: center;
      padding: 16px;
      border-radius: 18px;
      border: 1px solid rgba(255,255,255,0.08);
      background: rgba(255,255,255,0.04);
      animation: rise 220ms ease-out;
    }
    .card h3 {
      margin: 0 0 6px;
      font-size: 1rem;
    }
    .status {
      display: inline-flex;
      align-items: center;
      gap: 8px;
      width: fit-content;
      padding: 8px 12px;
      border-radius: 999px;
      text-transform: uppercase;
      letter-spacing: 0.08em;
      font-size: 0.82rem;
      font-weight: 700;
    }
    .status::before {
      content: "";
      width: 8px;
      height: 8px;
      border-radius: 999px;
      background: currentColor;
      box-shadow: 0 0 14px currentColor;
    }
    .running { color: var(--accent); background: rgba(124,247,212,0.08); }
    .starting { color: var(--warn); background: rgba(255,207,92,0.08); }
    .stopping, .stopped, .exited { color: var(--danger); background: rgba(255,125,141,0.08); }
    .empty {
      padding: 24px;
      border-radius: 18px;
      border: 1px dashed rgba(255,255,255,0.14);
      color: var(--muted);
      text-align: center;
    }
    .toast {
      position: fixed;
      right: 18px;
      bottom: 18px;
      z-index: 50;
      max-width: min(420px, calc(100vw - 36px));
      background: rgba(9, 13, 28, 0.94);
      border: 1px solid rgba(255,255,255,0.12);
      box-shadow: var(--shadow);
      color: var(--text);
      padding: 12px 16px;
      border-radius: 16px;
      opacity: 0;
      transform: translateY(16px);
      transition: opacity 180ms ease, transform 180ms ease;
      pointer-events: none;
    }
    .toast.visible { opacity: 1; transform: translateY(0); }
    .modal-backdrop {
      position: fixed;
      inset: 0;
      background: rgba(2, 6, 16, 0.72);
      display: none;
      align-items: center;
      justify-content: center;
      padding: 16px;
      z-index: 60;
    }
    .modal-backdrop.open {
      display: flex;
    }
    .modal {
      width: min(880px, calc(100vw - 24px));
      max-height: calc(100vh - 24px);
      overflow: auto;
      border-radius: 18px;
      border: 1px solid var(--line);
      background: rgba(9, 13, 28, 0.96);
      box-shadow: var(--shadow);
      padding: 18px;
    }
    .modal-header {
      display: flex;
      justify-content: space-between;
      align-items: center;
      gap: 12px;
      margin-bottom: 12px;
    }
    .modal-header h3 {
      margin: 0;
      font-size: 1.1rem;
    }
    .rows-table {
      width: 100%;
      border-collapse: collapse;
      margin-top: 8px;
    }
    .rows-table th,
    .rows-table td {
      border-bottom: 1px solid rgba(255,255,255,0.08);
      padding: 8px;
      text-align: left;
      vertical-align: middle;
    }
    .rows-table input {
      width: 100%;
      border: 1px solid rgba(255,255,255,0.16);
      border-radius: 10px;
      background: rgba(255,255,255,0.04);
      color: var(--text);
      padding: 8px 10px;
      font: inherit;
    }
    .modal-actions {
      display: flex;
      justify-content: space-between;
      gap: 10px;
      margin-top: 14px;
      flex-wrap: wrap;
    }
    .ghost {
      background: transparent;
      border: 1px solid rgba(255,255,255,0.16);
      color: var(--text);
    }
    .tab-bar {
      display: flex;
      gap: 10px;
      margin: 4px 0 12px;
      flex-wrap: wrap;
    }
    .tab-btn {
      background: rgba(255,255,255,0.06);
      border: 1px solid rgba(255,255,255,0.14);
      color: var(--muted);
      border-radius: 999px;
      padding: 8px 14px;
      cursor: pointer;
      font: inherit;
    }
    .tab-btn.active {
      color: #081020;
      background: linear-gradient(135deg, var(--accent), var(--accent2));
      border-color: transparent;
      font-weight: 700;
    }
    .tab-panel { display: none; }
    .tab-panel.active { display: block; }
    @keyframes rise {
      from { opacity: 0; transform: translateY(8px); }
      to { opacity: 1; transform: translateY(0); }
    }
    @media (max-width: 920px) {
      .hero, .card { grid-template-columns: 1fr; }
      .stats { grid-template-columns: 1fr; }
      .list-header { flex-direction: column; }
    }
  </style>
</head>
<body>
  <div class="wrap">
    <section class="hero">
      <div class="panel hero-copy">
        <div class="eyebrow">Bottle launcher</div>
        <h1>Plainbook Mux</h1>
        <p class="lede">
          Start a fresh plainbook instance every time you click Start. Each launch gets its own notebook file,
          process, and front-end URL.
        </p>
        <div class="stats">
          <div class="stat"><strong id="stat-total">0</strong><span>Total launches</span></div>
          <div class="stat"><strong id="stat-running">0</strong><span>Running now</span></div>
        </div>
      </div>
      <div class="panel hero-actions">
        <div class="launch-card">
          <p>
            This admin dashboard shows all launched sessions and lets you open or stop each process.
          </p>
          <div class="button-row">
            <button class="secondary" onclick="refreshSessions()">Refresh</button>
            <button class="secondary" type="button" onclick="openAccessCodeModal()">Manage access codes</button>
            <a class="secondary" href="/admin/logout" style="text-decoration:none;display:inline-flex;align-items:center;">Logout</a>
          </div>
        </div>
        <div>
          <div class="code" id="launch-command">Latest launch: none</div>
          <div class="code" id="system-usage" style="margin-top:8px;">Mux usage: loading...</div>
          <div class="code" id="total-usage" style="margin-top:8px;">Total usage: loading...</div>
          <div class="code" id="runtime-size" style="margin-top:8px; display:flex; justify-content:space-between; gap:12px; align-items:center; flex-wrap:wrap;">
            <span id="runtime-size-text">Runtime folder size: loading...</span>
            <button class="secondary" id="delete-runtime-btn" onclick="deleteRuntimeFiles()">Delete runtime files</button>
          </div>
          <div class="footnote">Instances are tracked in memory while this launcher process is running.</div>
        </div>
      </div>
    </section>

    <section class="panel" style="margin-top: 20px; padding: 20px; display:flex; justify-content:space-between; gap:12px; align-items:center; flex-wrap:wrap;">
      <div>
        <h2 style="margin:0 0 6px;">Access Codes</h2>
        <p id="access-codes-status" style="margin:0; color: var(--muted);">Manage study templates and generate participant-specific access codes.</p>
      </div>
      <button class="primary" type="button" onclick="openAccessCodeModal()">Open editor</button>
    </section>

    <section class="panel list-panel">
      <div class="list-header">
        <div>
          <h2>Instances</h2>
          <p>Each row points to a separate plainbook process and notebook file.</p>
        </div>
        <div style="display:flex; gap:12px; align-items:center; flex-wrap:wrap;">
          <button class="secondary" id="stop-all-btn" onclick="stopAllInstances()">Stop all</button>
          <p id="last-refresh">Not refreshed yet</p>
        </div>
      </div>
      <div id="cards" class="cards"></div>
    </section>
  </div>
  <div id="access-codes-modal" class="modal-backdrop" role="dialog" aria-modal="true">
    <div class="modal">
      <div class="modal-header">
        <h3>Access Code Management</h3>
        <button class="secondary" type="button" onclick="closeAccessCodeModal()">Close</button>
      </div>
      <div class="tab-bar">
        <button type="button" class="tab-btn active" id="tab-btn-study" onclick="switchAccessModalTab('study')">Study Templates</button>
        <button type="button" class="tab-btn" id="tab-btn-generated" onclick="switchAccessModalTab('generated')">Generated Codes</button>
      </div>

      <div id="tab-panel-study" class="tab-panel active">
        <p class="footnote" style="margin: 0 0 10px;">Manage user-study codes and their template locations.</p>
        <div id="access-codes-error" class="footnote" style="margin: 0 0 10px;"></div>
        <table class="rows-table">
          <thead>
            <tr>
              <th style="width:30%;">Study code</th>
              <th>Template location</th>
              <th style="width:100px;">Action</th>
            </tr>
          </thead>
          <tbody id="access-code-rows"></tbody>
        </table>
        <div class="modal-actions">
          <div style="display:flex; gap:10px; flex-wrap:wrap;">
            <button class="ghost" type="button" onclick="addAccessCodeRow()">Add row</button>
            <button class="secondary" type="button" onclick="reloadAccessCodeRows()">Reload</button>
          </div>
          <div style="display:flex; gap:10px; flex-wrap:wrap;">
            <button class="secondary" type="button" onclick="closeAccessCodeModal()">Cancel</button>
            <button class="primary" type="button" id="save-access-codes-btn" onclick="saveAccessCodes()">Save</button>
          </div>
        </div>
      </div>

      <div id="tab-panel-generated" class="tab-panel">
        <p class="footnote" style="margin: 0 0 10px;">Generate unique participant codes and map each one to a study template.</p>
        <div id="generated-codes-error" class="footnote" style="margin: 0 0 10px;"></div>
        <div style="display:flex; gap:10px; flex-wrap:wrap; align-items:end; margin-bottom: 12px;">
          <label style="margin:0; min-width:200px;">
            Study code
            <select id="generated-study-select" style="width:100%; border:1px solid rgba(255,255,255,0.16); border-radius:10px; background:rgba(255,255,255,0.04); color:var(--text); padding:8px 10px; font:inherit;"></select>
          </label>
          <label style="margin:0; min-width:110px;">
            Count
            <input id="generated-count" type="number" min="1" max="100" value="1" style="width:100%; border:1px solid rgba(255,255,255,0.16); border-radius:10px; background:rgba(255,255,255,0.04); color:var(--text); padding:8px 10px; font:inherit;">
          </label>
          <button class="primary" type="button" id="generate-codes-btn" onclick="generateCodes()">Generate</button>
          <button class="secondary" type="button" onclick="reloadGeneratedCodes()">Reload</button>
          <button class="secondary" type="button" onclick="exportGeneratedCodesCsv()">Export CSV</button>
        </div>
        <div id="generated-study-stats" class="footnote" style="margin: 0 0 12px;"></div>

        <table class="rows-table">
          <thead>
            <tr>
              <th style="width:24%;">Generated code</th>
              <th style="width:24%;">Study code</th>
              <th style="width:10%;">Given</th>
              <th style="width:12%;">Used</th>
              <th>Created</th>
              <th style="width:180px;">Action</th>
            </tr>
          </thead>
          <tbody id="generated-code-rows"></tbody>
        </table>
        <div class="modal-actions">
          <div></div>
          <div style="display:flex; gap:10px; flex-wrap:wrap;">
            <button class="secondary" type="button" onclick="closeAccessCodeModal()">Close</button>
          </div>
        </div>
      </div>
    </div>
  </div>
  <div id="toast" class="toast"></div>

  <script>
    const toast = document.getElementById('toast');
    const cards = document.getElementById('cards');
    const statTotal = document.getElementById('stat-total');
    const statRunning = document.getElementById('stat-running');
    const lastRefresh = document.getElementById('last-refresh');
    const launchCommand = document.getElementById('launch-command');
    const systemUsage = document.getElementById('system-usage');
    const totalUsage = document.getElementById('total-usage');
    const runtimeSizeText = document.getElementById('runtime-size-text');
    const deleteRuntimeBtn = document.getElementById('delete-runtime-btn');
    const stopAllBtn = document.getElementById('stop-all-btn');

    const accessCodesModal = document.getElementById('access-codes-modal');
    const accessCodeRowsBody = document.getElementById('access-code-rows');
    const accessCodesError = document.getElementById('access-codes-error');
    const accessCodesStatus = document.getElementById('access-codes-status');
    const saveAccessCodesBtn = document.getElementById('save-access-codes-btn');
    const tabBtnStudy = document.getElementById('tab-btn-study');
    const tabBtnGenerated = document.getElementById('tab-btn-generated');
    const tabPanelStudy = document.getElementById('tab-panel-study');
    const tabPanelGenerated = document.getElementById('tab-panel-generated');
    const generatedCodesError = document.getElementById('generated-codes-error');
    const generatedStudyStats = document.getElementById('generated-study-stats');
    const generatedRowsBody = document.getElementById('generated-code-rows');
    const generatedStudySelect = document.getElementById('generated-study-select');
    const generatedCountInput = document.getElementById('generated-count');
    const generateCodesBtn = document.getElementById('generate-codes-btn');
    let accessCodeRows = [];
    let studyCodes = [];
    let generatedCodeRows = [];

    function switchAccessModalTab(tabName) {
      const isStudy = tabName === 'study';
      tabBtnStudy.classList.toggle('active', isStudy);
      tabBtnGenerated.classList.toggle('active', !isStudy);
      tabPanelStudy.classList.toggle('active', isStudy);
      tabPanelGenerated.classList.toggle('active', !isStudy);
      if (!isStudy) {
        loadStudyCodes();
      }
    }

    function formatUnixTimestamp(ts) {
      if (!ts) {
        return '-';
      }
      return new Date(ts * 1000).toLocaleString();
    }

    function renderStudyOptions() {
      if (!studyCodes.length) {
        generatedStudySelect.innerHTML = '<option value="">No study codes available</option>';
        generatedStudySelect.disabled = true;
        generateCodesBtn.disabled = true;
        return;
      }
      generatedStudySelect.disabled = false;
      generateCodesBtn.disabled = false;
      generatedStudySelect.innerHTML = studyCodes
        .map((study) => `<option value="${escapeHtml(study.code)}">${escapeHtml(study.code)}</option>`)
        .join('');
    }

    function renderGeneratedCodeRows() {
      renderGeneratedStudyStats();
      if (!generatedCodeRows.length) {
        generatedRowsBody.innerHTML = '<tr><td colspan="6" class="footnote">No generated codes yet.</td></tr>';
        return;
      }

      const studyOptionsHtml = studyCodes
        .map((study) => `<option value="${escapeHtml(study.code)}">${escapeHtml(study.code)}</option>`)
        .join('');

      generatedRowsBody.innerHTML = generatedCodeRows.map((row, index) => `
        <tr>
          <td class="code">${escapeHtml(row.code)}</td>
          <td>
            <select data-generated-index="${index}" data-generated-field="study" style="width:100%; border:1px solid rgba(255,255,255,0.16); border-radius:10px; background:rgba(255,255,255,0.04); color:var(--text); padding:8px 10px; font:inherit;">
              ${studyOptionsHtml}
            </select>
          </td>
          <td>
            <label style="display:flex; align-items:center; justify-content:center; margin:0;">
              <input type="checkbox" data-generated-index="${index}" data-generated-field="given" ${row.given ? 'checked' : ''}>
            </label>
          </td>
          <td>${row.used_count || 0}</td>
          <td>${escapeHtml(formatUnixTimestamp(row.created_at))}</td>
          <td style="display:flex; gap:8px; flex-wrap:wrap;">
            <button class="secondary" type="button" data-generated-copy="${index}">Copy</button>
            <button class="secondary" type="button" data-generated-delete="${index}">Delete</button>
          </td>
        </tr>
      `).join('');

      generatedRowsBody.querySelectorAll('select[data-generated-field="study"]').forEach((select) => {
        const idx = Number(select.getAttribute('data-generated-index'));
        if (!Number.isNaN(idx) && generatedCodeRows[idx]) {
          select.value = generatedCodeRows[idx].study_code || '';
        }
        select.addEventListener('change', async () => {
          const code = generatedCodeRows[idx] ? generatedCodeRows[idx].code : '';
          const studyCode = select.value;
          if (!code || !studyCode) {
            return;
          }
          try {
            await api('/api/admin/generated-codes/update-study', {
              method: 'POST',
              body: JSON.stringify({ code, study_code: studyCode }),
            });
            if (generatedCodeRows[idx]) {
              generatedCodeRows[idx].study_code = studyCode;
            }
            renderGeneratedStudyStats();
            generatedCodesError.textContent = '';
            showToast(`Updated ${code}`);
          } catch (error) {
            generatedCodesError.textContent = error.message;
            showToast(error.message);
          }
        });
      });

      generatedRowsBody.querySelectorAll('input[data-generated-field="given"]').forEach((checkbox) => {
        checkbox.addEventListener('change', async () => {
          const idx = Number(checkbox.getAttribute('data-generated-index'));
          const row = generatedCodeRows[idx];
          if (!row || !row.code) {
            return;
          }
          const nextGiven = checkbox.checked;
          try {
            await api('/api/admin/generated-codes/update-given', {
              method: 'POST',
              body: JSON.stringify({ code: row.code, given: nextGiven }),
            });
            row.given = nextGiven;
            generatedCodesError.textContent = '';
          } catch (error) {
            checkbox.checked = !nextGiven;
            generatedCodesError.textContent = error.message;
            showToast(error.message);
          }
        });
      });

      generatedRowsBody.querySelectorAll('button[data-generated-delete]').forEach((button) => {
        button.addEventListener('click', async () => {
          const idx = Number(button.getAttribute('data-generated-delete'));
          const row = generatedCodeRows[idx];
          if (!row) {
            return;
          }
          try {
            await api('/api/admin/generated-codes/delete', {
              method: 'POST',
              body: JSON.stringify({ code: row.code }),
            });
            generatedCodeRows.splice(idx, 1);
            renderGeneratedCodeRows();
            generatedCodesError.textContent = '';
            showToast(`Deleted ${row.code}`);
          } catch (error) {
            generatedCodesError.textContent = error.message;
            showToast(error.message);
          }
        });
      });

      generatedRowsBody.querySelectorAll('button[data-generated-copy]').forEach((button) => {
        button.addEventListener('click', async () => {
          const idx = Number(button.getAttribute('data-generated-copy'));
          const row = generatedCodeRows[idx];
          if (!row || !row.code) {
            return;
          }
          try {
            await copyTextToClipboard(row.code);
            generatedCodesError.textContent = '';
            showToast(`Copied ${row.code}`);
          } catch (_error) {
            generatedCodesError.textContent = 'Unable to copy automatically. Please copy manually.';
            showToast('Copy failed');
          }
        });
      });
    }

    function renderGeneratedStudyStats() {
      if (!generatedCodeRows.length) {
        generatedStudyStats.textContent = 'Created codes by study: none yet.';
        return;
      }

      const counts = {};
      for (const row of generatedCodeRows) {
        const studyCode = (row.study_code || '').trim() || '(unassigned)';
        counts[studyCode] = (counts[studyCode] || 0) + 1;
      }

      const parts = Object.entries(counts)
        .sort((a, b) => a[0].localeCompare(b[0]))
        .map(([studyCode, count]) => `${studyCode}: ${count}`);
      generatedStudyStats.textContent = `Created codes by study (${generatedCodeRows.length} total): ${parts.join(' | ')}`;
    }

    async function copyTextToClipboard(text) {
      if (navigator.clipboard && navigator.clipboard.writeText) {
        await navigator.clipboard.writeText(text);
        return;
      }

      const input = document.createElement('input');
      input.value = text;
      input.style.position = 'fixed';
      input.style.left = '-9999px';
      document.body.appendChild(input);
      input.select();
      let ok = false;
      try {
        ok = document.execCommand('copy');
      } finally {
        document.body.removeChild(input);
      }
      if (!ok) {
        throw new Error('copy-failed');
      }
    }

    function escapeCsvValue(value) {
      const text = String(value == null ? '' : value);
      return `"${text.replace(/"/g, '""')}"`;
    }

    function exportGeneratedCodesCsv() {
      if (!generatedCodeRows.length) {
        generatedCodesError.textContent = 'No generated codes to export.';
        showToast('Nothing to export');
        return;
      }

      const header = ['code', 'study_code', 'given', 'used_count', 'created_at', 'last_used_at'];
      const lines = [header.join(',')];
      for (const row of generatedCodeRows) {
        const cols = [
          row.code,
          row.study_code,
          row.given ? 'yes' : 'no',
          row.used_count || 0,
          formatUnixTimestamp(row.created_at),
          formatUnixTimestamp(row.last_used_at),
        ];
        lines.push(cols.map(escapeCsvValue).join(','));
      }

      const blob = new Blob([lines.join('\\n')], { type: 'text/csv;charset=utf-8;' });
      const url = URL.createObjectURL(blob);
      const link = document.createElement('a');
      const stamp = new Date().toISOString().replace(/:/g, '-');
      link.href = url;
      link.download = `generated-codes-${stamp}.csv`;
      document.body.appendChild(link);
      link.click();
      document.body.removeChild(link);
      URL.revokeObjectURL(url);
      generatedCodesError.textContent = '';
      showToast('CSV exported');
    }

    function buildInstanceUrl(item) {
      const rawUrl = item && item.public_url ? String(item.public_url) : '';
      if (!rawUrl) {
        return '';
      }
      const url = new URL(rawUrl, window.location.origin);
      const token = item && item.token ? String(item.token) : '';
      if (token && !url.searchParams.get('token')) {
        url.searchParams.set('token', token);
      }
      return url.toString();
    }

    function escapeHtml(value) {
      return String(value)
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#39;');
    }

    function renderAccessCodeRows() {
      if (!accessCodeRows.length) {
        accessCodeRowsBody.innerHTML = '<tr><td colspan="3" class="footnote">No rows yet. Click Add row.</td></tr>';
        return;
      }

      accessCodeRowsBody.innerHTML = accessCodeRows.map((row, index) => `
        <tr>
          <td><input data-index="${index}" data-field="code" value="${escapeHtml(row.code)}" placeholder="Your access code"></td>
          <td><input data-index="${index}" data-field="template" value="${escapeHtml(row.template)}" placeholder="A new file will be created"></td>
          <td><button class="secondary" type="button" data-remove-index="${index}">Remove</button></td>
        </tr>
      `).join('');

      accessCodeRowsBody.querySelectorAll('input[data-index]').forEach((input) => {
        input.addEventListener('input', (event) => {
          const idx = Number(event.target.getAttribute('data-index'));
          const field = event.target.getAttribute('data-field');
          if (!Number.isNaN(idx) && accessCodeRows[idx]) {
            accessCodeRows[idx][field] = event.target.value;
          }
        });
      });

      accessCodeRowsBody.querySelectorAll('button[data-remove-index]').forEach((button) => {
        button.addEventListener('click', () => {
          const idx = Number(button.getAttribute('data-remove-index'));
          if (!Number.isNaN(idx)) {
            accessCodeRows.splice(idx, 1);
            renderAccessCodeRows();
          }
        });
      });
    }

    function normalizeAccessCodeRows(rawJson) {
      let parsed;
      try {
        parsed = JSON.parse(rawJson || '{}');
      } catch (_error) {
        parsed = {};
      }
      if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
        return [];
      }
      return Object.entries(parsed).map(([code, value]) => {
        let template = '';
        if (typeof value === 'string') {
          template = value;
        } else if (value && typeof value === 'object') {
          for (const key of ['template', 'template_uri', 'template_url', 'location', 'source']) {
            if (typeof value[key] === 'string') {
              template = value[key];
              break;
            }
          }
        }
        return { code, template };
      }).sort((a, b) => a.code.localeCompare(b.code));
    }

    function openAccessCodeModal() {
      accessCodesModal.classList.add('open');
      accessCodesError.textContent = '';
      generatedCodesError.textContent = '';
      switchAccessModalTab('study');
      reloadAccessCodeRows();
      loadGeneratedCodes();
    }

    function closeAccessCodeModal() {
      accessCodesModal.classList.remove('open');
    }

    function addAccessCodeRow() {
      accessCodeRows.push({ code: '', template: '' });
      renderAccessCodeRows();
    }

    accessCodesModal.addEventListener('click', (event) => {
      if (event.target === accessCodesModal) {
        closeAccessCodeModal();
      }
    });
    function showToast(message) {
      toast.textContent = message;
      toast.classList.add('visible');
      clearTimeout(showToast.timer);
      showToast.timer = setTimeout(() => toast.classList.remove('visible'), 2400);
    }

    async function api(path, options, timeoutMs = 8000) {
      const controller = new AbortController();
      const timer = setTimeout(() => controller.abort(), timeoutMs);
      try {
        const response = await fetch(path, {
          headers: { 'Content-Type': 'application/json' },
          signal: controller.signal,
          ...options,
        });

        const contentType = response.headers.get('content-type') || '';
        let payload;
        if (contentType.includes('application/json')) {
          payload = await response.json();
        } else {
          payload = await response.text();
        }

        if (!response.ok) {
          const message = typeof payload === 'object' && payload !== null
            ? (payload.error || payload.message || `Request failed (${response.status})`)
            : `Request failed (${response.status})`;
          if (response.status === 401) {
            window.location.href = '/admin/login';
          }
          throw new Error(message);
        }

        return typeof payload === 'object' && payload !== null ? payload : {};
      } catch (error) {
        if (error.name === 'AbortError') {
          throw new Error(`Request timed out: ${path}`);
        }
        throw error;
      } finally {
        clearTimeout(timer);
      }
    }

    async function loadAccessCodes() {
      accessCodesStatus.textContent = 'Loading access code document...';
      try {
        const payload = await api('/api/admin/access-codes');
        accessCodeRows = normalizeAccessCodeRows(payload.raw_json || '{}\\n');
        renderAccessCodeRows();
        accessCodesStatus.textContent = 'Access code document loaded.';
      } catch (error) {
        accessCodesStatus.textContent = `Access code document unavailable: ${error.message}`;
        showToast(error.message);
      }
    }

    async function loadStudyCodes() {
      const payload = await api('/api/admin/study-codes');
      studyCodes = Array.isArray(payload.studies) ? payload.studies : [];
      renderStudyOptions();
    }

    async function loadGeneratedCodes() {
      generatedCodesError.textContent = '';
      try {
        const payload = await api('/api/admin/generated-codes');
        generatedCodeRows = Array.isArray(payload.items) ? payload.items : [];
        renderGeneratedCodeRows();
      } catch (error) {
        generatedCodeRows = [];
        renderGeneratedCodeRows();
        generatedCodesError.textContent = error.message;
        showToast(error.message);
      }
    }

    async function reloadGeneratedCodes() {
      await Promise.all([loadStudyCodes(), loadGeneratedCodes()]);
    }

    async function generateCodes() {
      const studyCode = generatedStudySelect.value;
      const count = Number(generatedCountInput.value || '1');
      if (!studyCode) {
        generatedCodesError.textContent = 'Choose a study code first.';
        return;
      }
      if (!Number.isInteger(count) || count < 1 || count > 100) {
        generatedCodesError.textContent = 'Count must be between 1 and 100.';
        return;
      }

      generateCodesBtn.disabled = true;
      const prevText = generateCodesBtn.textContent;
      generateCodesBtn.textContent = 'Generating...';
      try {
        const payload = await api('/api/admin/generated-codes/generate', {
          method: 'POST',
          body: JSON.stringify({ study_code: studyCode, count }),
        });
        generatedCodesError.textContent = '';
        const createdCount = Array.isArray(payload.created_codes) ? payload.created_codes.length : 0;
        showToast(`Generated ${createdCount} code(s)`);
        await loadGeneratedCodes();
      } catch (error) {
        generatedCodesError.textContent = error.message;
        showToast(error.message);
      } finally {
        generateCodesBtn.disabled = false;
        generateCodesBtn.textContent = prevText;
      }
    }

    async function reloadAccessCodeRows() {
      await Promise.all([loadAccessCodes(), loadStudyCodes()]);
    }

    async function saveAccessCodes() {
      const configObject = {};
      const seenCodes = new Set();
      for (const row of accessCodeRows) {
        const code = row.code.trim();
        const template = row.template.trim();
        if (!code) {
          continue;
        }
        if (seenCodes.has(code)) {
          const message = `Duplicate access code: ${code}`;
          accessCodesError.textContent = message;
          showToast(message);
          return;
        }
        seenCodes.add(code);
        configObject[code] = { template: template || null };
      }

      if (!Object.keys(configObject).length) {
        const message = 'Add at least one access code before saving.';
        accessCodesError.textContent = message;
        showToast(message);
        return;
      }

      accessCodesError.textContent = '';
      saveAccessCodesBtn.disabled = true;
      saveAccessCodesBtn.textContent = 'Saving…';
      try {
        const payload = await api('/api/admin/access-codes', {
          method: 'POST',
          body: JSON.stringify({ raw_json: JSON.stringify(configObject, null, 2) }),
        });
        accessCodeRows = normalizeAccessCodeRows(payload.raw_json || '{}\\n');
        renderAccessCodeRows();
        accessCodesStatus.textContent = `Saved ${payload.count} access code(s).`;
        showToast('Access codes saved');
      } catch (error) {
        accessCodesError.textContent = error.message;
        showToast(error.message);
      } finally {
        saveAccessCodesBtn.disabled = false;
        saveAccessCodesBtn.textContent = 'Save';
      }
    }

    function statusClass(status) {
      if (status === 'running') return 'running';
      if (status === 'starting') return 'starting';
      return 'exited';
    }

    function renderCards(items) {
      cards.innerHTML = '';
      if (!items.length) {
        cards.innerHTML = '<div class="empty">No plainbook instances yet. Start one to create its own session and UI.</div>';
        return;
      }

      for (const item of items) {
        const displayUrl = buildInstanceUrl(item);
        const card = document.createElement('article');
        card.className = 'card';
        card.innerHTML = `
          <div>
            <h3>${item.id}</h3>
            <div class="meta">Notebook: ${item.notebook_path}</div>
            <div class="meta">Port: ${item.port} · Started: ${item.created_at_label}</div>
            <div class="meta">Code: ${item.launch_code || '-'}</div>
              <div class="meta">Study: ${item.study_code || '-'}</div>
            <div class="meta">PID: ${item.pid || '-'} · CPU: ${item.usage ? item.usage.cpu_percent + '%' : 'n/a'} · RAM: ${item.usage ? item.usage.memory_mb + ' MB' : 'n/a'}</div>
            ${item.exit_code !== null ? `<div class="meta">Exit code: ${item.exit_code}</div>` : ''}
          </div>
          <div>
            <div class="status ${statusClass(item.status || 'starting')}">${item.status || 'starting'}</div>
            <div class="meta" style="margin-top: 8px;">${displayUrl || 'Waiting for plainbook to print its URL…'}</div>
          </div>
          <div class="actions">
            <button class="secondary" ${item.public_url ? '' : 'disabled'} data-open="${item.id}">Open</button>
            <button class="secondary" data-stop="${item.id}" data-backend-ref="${item.backend_ref || ''}">Stop</button>
          </div>
        `;
        cards.appendChild(card);
      }

      cards.querySelectorAll('[data-open]').forEach((button) => {
        button.addEventListener('click', () => {
          const item = items.find((row) => row.id === button.getAttribute('data-open'));
          if (item && item.public_url) {
            const targetUrl = buildInstanceUrl(item);
            if (targetUrl) {
              window.location.replace(targetUrl);
            }
          }
        });
      });

      cards.querySelectorAll('[data-stop]').forEach((button) => {
        button.addEventListener('click', async () => {
          try {
            const backendRef = button.getAttribute('data-backend-ref') || '';
            await api(`/api/sessions/${button.getAttribute('data-stop')}/stop`, {
              method: 'POST',
              body: JSON.stringify({ backend_ref: backendRef }),
            });
            showToast('Stopped instance');
            await refreshSessions();
          } catch (error) {
            showToast(error.message);
          }
        });
      });
    }

    async function refreshSessions() {
      try {
        const [payload, usagePayload] = await Promise.all([
          api('/api/sessions'),
          api('/api/admin/usage'),
        ]);
        const items = payload.sessions || [];
        renderCards(items);
        statTotal.textContent = String(items.length);
        statRunning.textContent = String(items.filter((item) => item.status === 'running' || item.status === 'starting').length);
        lastRefresh.textContent = `Updated ${new Date().toLocaleTimeString()}`;
        if (usagePayload && usagePayload.mux) {
          systemUsage.textContent = `Mux usage: PID ${usagePayload.mux.pid} · CPU ${usagePayload.mux.cpu_percent}% · RAM ${usagePayload.mux.memory_mb} MB`;
        } else {
          systemUsage.textContent = 'Mux usage: unavailable';
        }
        if (usagePayload && usagePayload.total) {
          totalUsage.textContent = `Total usage: CPU ${usagePayload.total.cpu_percent}% · RAM ${usagePayload.total.memory_mb} MB`;
        } else {
          totalUsage.textContent = 'Total usage: unavailable';
        }
        if (usagePayload && usagePayload.runtime) {
          runtimeSizeText.textContent = `Runtime folder size: ${usagePayload.runtime.megabytes} MB (${usagePayload.runtime.bytes} bytes)`;
          deleteRuntimeBtn.disabled = !usagePayload.can_delete_runtime;
          deleteRuntimeBtn.title = usagePayload.can_delete_runtime ? 'Delete all files in runtime/' : 'Stop all running instances before deleting runtime files';
        } else {
          runtimeSizeText.textContent = 'Runtime folder size: unavailable';
          deleteRuntimeBtn.disabled = true;
          deleteRuntimeBtn.title = 'Runtime status unavailable';
        }
        stopAllBtn.disabled = items.length === 0;
        if (items.length) {
          launchCommand.textContent = `Latest launch: ${buildInstanceUrl(items[0]) || 'starting…'}`;
        } else {
          launchCommand.textContent = 'Latest launch: none';
        }
      } catch (error) {
        lastRefresh.textContent = 'Update failed';
        systemUsage.textContent = 'Mux usage: unavailable';
        totalUsage.textContent = 'Total usage: unavailable';
        runtimeSizeText.textContent = 'Runtime folder size: unavailable';
        showToast(error.message);
      }
    }

    async function stopAllInstances() {
      const confirmed = window.confirm('Stop all will stop every current plainbook instance. Continue?');
      if (!confirmed) {
        return;
      }
      stopAllBtn.disabled = true;
      stopAllBtn.textContent = 'Stopping…';
      try {
        const payload = await api('/api/admin/stop-all', { method: 'POST', body: '{}' });
        showToast(`Stopped ${payload.stopped_instances} instance(s)`);
        await refreshSessions();
      } catch (error) {
        showToast(error.message);
      } finally {
        stopAllBtn.disabled = false;
        stopAllBtn.textContent = 'Stop all';
      }
    }

    async function deleteRuntimeFiles() {
      const confirmed = window.confirm('Delete all files inside runtime/? This only works when no instances are running. Continue?');
      if (!confirmed) {
        return;
      }
      deleteRuntimeBtn.disabled = true;
      deleteRuntimeBtn.textContent = 'Deleting…';
      try {
        const payload = await api('/api/admin/delete-runtime-files', { method: 'POST', body: '{}' });
        showToast(`Deleted ${payload.deleted_files} file(s)`);
        await refreshSessions();
      } catch (error) {
        showToast(error.message);
      } finally {
        deleteRuntimeBtn.disabled = false;
        deleteRuntimeBtn.textContent = 'Delete runtime files';
      }
    }

    loadAccessCodes();
    loadStudyCodes();
    refreshSessions();
    setInterval(refreshSessions, 3000);
  </script>
</body>
</html>
"""


def create_admin_session() -> str:
    token = secrets.token_urlsafe(32)
    expires = time.time() + ADMIN_SESSION_TTL_SECONDS
    with admin_sessions_lock:
        admin_sessions[token] = expires
    return token


def is_admin_authenticated() -> bool:
    token = request.get_cookie(ADMIN_COOKIE_NAME)
    if not token:
        return False
    now = time.time()
    with admin_sessions_lock:
        expiry = admin_sessions.get(token)
        if expiry is None:
            return False
        if expiry < now:
            admin_sessions.pop(token, None)
            return False
    return True


def require_admin(handler):
    @wraps(handler)
    def wrapped(*args, **kwargs):
        if not is_admin_authenticated():
            raise HTTPError(401, "Admin authentication required")
        return handler(*args, **kwargs)

    return wrapped


def admin_login_page(error_message: str = "") -> str:
    return ADMIN_LOGIN_HTML.replace("__ERROR__", error_message)


@app.get("/")
def index():
  set_no_cache_headers()
  response.content_type = HTML_CONTENT_TYPE
  return USER_PAGE_HTML


def launch_instance_from_request() -> dict:
  payload = request.json or {}
  code = str(payload.get("code", request.query.get("code", ""))).strip()
  if not code:
    response.status = 400
    response.content_type = JSON_CONTENT_TYPE
    return {"error": "Code is required"}

  existing = launcher.find_running_instance_by_launch_code(code)
  if existing is not None:
    response.content_type = JSON_CONTENT_TYPE
    return existing.to_dict()

  resolved_study_code = resolve_study_code_for_launch(code)
  if not resolved_study_code:
    response.status = 400
    response.content_type = JSON_CONTENT_TYPE
    return {"error": "Access code wrong, please contact the administrator"}

  if resolved_study_code != code:
    mark_generated_code_used(code)

  try:
    record = launcher.start(launch_code=code, template_code=resolved_study_code)
  except FileNotFoundError as exc:
    if "template" in str(exc).lower():
      response.status = 400
      response.content_type = JSON_CONTENT_TYPE
      return {"error": TEMPLATE_EXPIRED_MESSAGE}
    response.status = 400
    response.content_type = JSON_CONTENT_TYPE
    return {"error": str(exc)}
  response.content_type = JSON_CONTENT_TYPE
  return record.to_dict()


@app.get("/api/launch")
@app.post("/api/launch")
def public_launch():
  return launch_instance_from_request()


@app.get("/api/admin/access-codes")
@require_admin
def admin_access_codes_get():
  response.content_type = JSON_CONTENT_TYPE
  return {"raw_json": read_access_code_config_text()}


@app.post("/api/admin/access-codes")
@require_admin
def admin_access_codes_post():
  payload = request.json or {}
  raw_json = payload.get("raw_json")
  if not isinstance(raw_json, str):
    raise HTTPError(400, "raw_json must be a string")

  try:
    parsed = json.loads(raw_json)
  except json.JSONDecodeError as exc:
    raise HTTPError(400, f"Invalid JSON: {exc.msg}") from exc

  if not isinstance(parsed, dict):
    raise HTTPError(400, "Access code config must be a JSON object")

  save_access_code_config(parsed)
  response.content_type = JSON_CONTENT_TYPE
  return {"status": "ok", "count": len(parsed), "raw_json": read_access_code_config_text()}


@app.get("/api/admin/study-codes")
@require_admin
def admin_study_codes_get():
  config = load_access_code_config()
  studies = []
  for code in sorted(config.keys()):
    studies.append({
      "code": code,
      "template": get_template_location_for_code(code),
    })
  response.content_type = JSON_CONTENT_TYPE
  return {"studies": studies}


@app.get("/api/admin/generated-codes")
@require_admin
def admin_generated_codes_get():
  generated = load_generated_access_codes()
  items = []
  for code, value in generated.items():
    if isinstance(value, str):
      study_code = value
      created_at = None
      used_count = 0
      last_used_at = None
      given = False
    elif isinstance(value, dict):
      study_code = value.get("study_code") if isinstance(value.get("study_code"), str) else ""
      created_at = value.get("created_at") if isinstance(value.get("created_at"), int) else None
      used_count = value.get("used_count") if isinstance(value.get("used_count"), int) else 0
      last_used_at = value.get("last_used_at") if isinstance(value.get("last_used_at"), int) else None
      given = value.get("given") if isinstance(value.get("given"), bool) else False
    else:
      continue

    items.append({
      "code": code,
      "study_code": study_code,
      "created_at": created_at,
      "given": given,
      "used_count": used_count,
      "last_used_at": last_used_at,
    })

  items.sort(key=lambda item: (item["created_at"] or 0, item["code"]), reverse=True)
  response.content_type = JSON_CONTENT_TYPE
  return {"items": items}


@app.post("/api/admin/generated-codes/generate")
@require_admin
def admin_generated_codes_generate():
  payload = request.json or {}
  study_code = str(payload.get("study_code", "")).strip()
  count = payload.get("count", 1)

  if study_code not in load_access_code_config():
    raise HTTPError(400, "Unknown study code")
  if not isinstance(count, int):
    raise HTTPError(400, "count must be an integer")
  if count < 1 or count > 100:
    raise HTTPError(400, "count must be between 1 and 100")

  generated = load_generated_access_codes()
  created_codes = []
  now = int(time.time())
  for _ in range(count):
    code = generate_unique_access_code()
    generated[code] = {
      "study_code": study_code,
      "created_at": now,
      "given": False,
      "used_count": 0,
    }
    created_codes.append(code)

  save_generated_access_codes(generated)
  response.content_type = JSON_CONTENT_TYPE
  return {"status": "ok", "created_codes": created_codes}


@app.post("/api/admin/generated-codes/update-study")
@require_admin
def admin_generated_codes_update_study():
  payload = request.json or {}
  code = str(payload.get("code", "")).strip()
  study_code = str(payload.get("study_code", "")).strip()
  if not code:
    raise HTTPError(400, "code is required")
  if study_code not in load_access_code_config():
    raise HTTPError(400, "Unknown study code")

  generated = load_generated_access_codes()
  entry = generated.get(code)
  if entry is None:
    raise HTTPError(404, "Generated code not found")
  if isinstance(entry, str):
    entry = {"study_code": entry, "used_count": 0}
  if not isinstance(entry, dict):
    raise HTTPError(400, "Generated code entry is invalid")
  entry["study_code"] = study_code
  generated[code] = entry
  save_generated_access_codes(generated)
  response.content_type = JSON_CONTENT_TYPE
  return {"status": "ok"}


@app.post("/api/admin/generated-codes/update-given")
@require_admin
def admin_generated_codes_update_given():
  payload = request.json or {}
  code = str(payload.get("code", "")).strip()
  given = payload.get("given")
  if not code:
    raise HTTPError(400, "code is required")
  if not isinstance(given, bool):
    raise HTTPError(400, "given must be a boolean")

  generated = load_generated_access_codes()
  entry = generated.get(code)
  if entry is None:
    raise HTTPError(404, "Generated code not found")
  if isinstance(entry, str):
    entry = {"study_code": entry, "used_count": 0}
  if not isinstance(entry, dict):
    raise HTTPError(400, "Generated code entry is invalid")
  entry["given"] = given
  generated[code] = entry
  save_generated_access_codes(generated)
  response.content_type = JSON_CONTENT_TYPE
  return {"status": "ok"}


@app.post("/api/admin/generated-codes/delete")
@require_admin
def admin_generated_codes_delete():
  payload = request.json or {}
  code = str(payload.get("code", "")).strip()
  if not code:
    raise HTTPError(400, "code is required")

  generated = load_generated_access_codes()
  if code not in generated:
    raise HTTPError(404, "Generated code not found")
  generated.pop(code, None)
  save_generated_access_codes(generated)
  response.content_type = JSON_CONTENT_TYPE
  return {"status": "ok"}


@app.get("/admin")
def admin_page():
  if not is_admin_authenticated():
    redirect("/admin/login")
  set_no_cache_headers()
  response.content_type = HTML_CONTENT_TYPE
  return ADMIN_PAGE_HTML


@app.get("/admin/login")
def admin_login_get():
  set_no_cache_headers()
  response.content_type = HTML_CONTENT_TYPE
  return admin_login_page()


@app.post("/admin/login")
def admin_login_post():
  password = (request.forms.get("password") or "").strip()
  if password != ADMIN_PASSWORD:
    response.content_type = HTML_CONTENT_TYPE
    return admin_login_page("Invalid password")

  token = create_admin_session()
  response.set_cookie(
    ADMIN_COOKIE_NAME,
    token,
    path="/",
    httponly=True,
    secure=False,
    samesite="Lax",
    max_age=ADMIN_SESSION_TTL_SECONDS,
  )
  redirect("/admin")


@app.get("/admin/logout")
def admin_logout():
  token = request.get_cookie(ADMIN_COOKIE_NAME)
  if token:
    with admin_sessions_lock:
      admin_sessions.pop(token, None)
  response.delete_cookie(ADMIN_COOKIE_NAME, path="/")
  redirect("/admin/login")


def build_instance_proxy_target(record: InstanceRecord, subpath: str, raw_query: str) -> str:
  clean_subpath = subpath.lstrip("/")
  path = f"/{clean_subpath}" if clean_subpath else "/"
  backend_url = record.backend_url or f"http://127.0.0.1:{record.port}"
  target = f"{backend_url.rstrip('/')}{path}"
  if raw_query:
    target = f"{target}?{raw_query}"
  return target


def _is_within_root(path: Path, root: Path) -> bool:
  try:
    path.resolve().relative_to(root.resolve())
    return True
  except Exception:
    return False


def _secure_file_list(record: InstanceRecord) -> dict:
  if record.instance_dir is None:
    raise HTTPError(500, "Instance directory unavailable")

  root_dir = record.instance_dir.resolve()
  data = request.json or {}
  requested = data.get("path")

  if not requested:
    target_dir = root_dir
  else:
    candidate = Path(str(requested))
    if not candidate.is_absolute():
      candidate = (root_dir / candidate)
    target_dir = candidate.resolve()

  if not _is_within_root(target_dir, root_dir):
    raise HTTPError(403, "Access outside instance directory is not allowed")
  if not target_dir.exists():
    raise HTTPError(404, "Path does not exist")
  if not target_dir.is_dir():
    raise HTTPError(400, "Path is not a directory")

  entries: list[dict[str, str]] = []
  for entry in target_dir.iterdir():
    if entry.name.startswith("."):
      continue
    entries.append(
      {
        "name": entry.name,
        "path": str(entry.resolve()),
        "type": "directory" if entry.is_dir() else "file",
      }
    )
  entries.sort(key=lambda item: (item["type"] != "directory", item["name"].lower()))
  return {"files": entries}


def handle_secure_instance_endpoint(record: InstanceRecord, subpath: str):
  normalized = subpath.strip("/")
  
  # For process backend, use local filesystem
  if record.backend_kind == "process":
    if record.instance_dir is None:
      return None

    if normalized == "current_dir" and request.method.upper() == "GET":
      response.content_type = JSON_CONTENT_TYPE
      return {"path": str(record.instance_dir.resolve())}

    if normalized == "home_dir" and request.method.upper() == "GET":
      response.content_type = JSON_CONTENT_TYPE
      return {"path": str(record.instance_dir.resolve())}

    if normalized == "file_list" and request.method.upper() == "POST":
      response.content_type = JSON_CONTENT_TYPE
      return _secure_file_list(record)
  
  # For container backends, proxy file operations to plainbook instance
  elif record.backend_kind in {"docker", "cloud-run"}:
    # These endpoints are proxied to the plainbook instance, which implements them
    # Return None to let the normal proxy handler take over
    pass

  return None


def proxy_to_instance(instance_id: str, subpath: str = ""):
  record = launcher.get(instance_id)
  if record is None:
    raise HTTPError(404, "Instance not found")
  if not launcher._record_is_running(record):
    raise HTTPError(410, "Instance is no longer running")

  secured_response = handle_secure_instance_endpoint(record, subpath)
  if secured_response is not None:
    return secured_response

  target_url = build_instance_proxy_target(record, subpath, request.query_string or "")
  method = (request.method or "GET").upper()
  body_bytes = request.body.read() if method in {"POST", "PUT", "PATCH", "DELETE"} else None

  upstream_headers: dict[str, str] = {}
  for key, value in request.headers.items():
    if key.lower() in HOP_BY_HOP_HEADERS:
      continue
    upstream_headers[key] = value

  req = Request(target_url, data=body_bytes, headers=upstream_headers, method=method)
  try:
    with urlopen(req, timeout=30) as upstream:
      response.status = upstream.getcode()
      for key, value in upstream.headers.items():
        if key.lower() in HOP_BY_HOP_HEADERS:
          continue
        response.set_header(key, value)
      return upstream.read()
  except URLLibHTTPError as exc:
    response.status = exc.code
    for key, value in exc.headers.items():
      if key.lower() in HOP_BY_HOP_HEADERS:
        continue
      response.set_header(key, value)
    return exc.read()
  except URLError as exc:
    raise HTTPError(502, f"Unable to reach instance backend: {exc.reason}")


def proxy_to_record(record: InstanceRecord, subpath: str = ""):
  if not launcher._record_is_running(record):
    raise HTTPError(410, "Instance is no longer running")

  secured_response = handle_secure_instance_endpoint(record, subpath)
  if secured_response is not None:
    return secured_response

  target_url = build_instance_proxy_target(record, subpath, request.query_string or "")
  method = (request.method or "GET").upper()
  body_bytes = request.body.read() if method in {"POST", "PUT", "PATCH", "DELETE"} else None

  upstream_headers: dict[str, str] = {}
  for key, value in request.headers.items():
    if key.lower() in HOP_BY_HOP_HEADERS:
      continue
    upstream_headers[key] = value

  req = Request(target_url, data=body_bytes, headers=upstream_headers, method=method)
  try:
    with urlopen(req, timeout=30) as upstream:
      response.status = upstream.getcode()
      for key, value in upstream.headers.items():
        if key.lower() in HOP_BY_HOP_HEADERS:
          continue
        response.set_header(key, value)
      return upstream.read()
  except URLLibHTTPError as exc:
    response.status = exc.code
    for key, value in exc.headers.items():
      if key.lower() in HOP_BY_HOP_HEADERS:
        continue
      response.set_header(key, value)
    return exc.read()
  except URLError as exc:
    raise HTTPError(502, f"Unable to reach instance backend: {exc.reason}")


def resolve_instance_from_request_context() -> InstanceRecord | None:
  token = (request.query.get("token") or "").strip()
  if token:
    by_token = launcher.find_running_instance_by_token(token)
    if by_token is not None:
      return by_token

  referer = request.headers.get("Referer") or ""
  if referer:
    try:
      parsed = urlsplit(referer)
      match = INSTANCE_PATH_RE.search(parsed.path or "")
      if match:
        by_id = launcher.find_running_instance_by_id(match.group(1))
        if by_id is not None:
          return by_id
    except Exception:
      pass

  return launcher.get_single_running_instance()


@app.route("/instance/<instance_id>", method=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD"])
def instance_proxy_root(instance_id: str):
  return proxy_to_instance(instance_id, "")


@app.route("/instance/<instance_id>/", method=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD"])
def instance_proxy_root_slash(instance_id: str):
  return proxy_to_instance(instance_id, "")


@app.route("/instance/<instance_id>/<subpath:path>", method=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD"])
def instance_proxy_subpath(instance_id: str, subpath: str):
  return proxy_to_instance(instance_id, subpath)


@app.route("/<subpath:re:(?!api(?:/|$)).+>", method=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD"])
def root_fallback_instance_proxy(subpath: str):
  record = resolve_instance_from_request_context()
  if record is None:
    raise HTTPError(404, f"Not found: '/{subpath}'")
  return proxy_to_record(record, subpath)


@app.get("/api/sessions")
@require_admin
def list_sessions():
    response.content_type = JSON_CONTENT_TYPE
    return {"sessions": launcher.list_instances()}


@app.get("/api/admin/usage")
@require_admin
def admin_usage():
  usage = get_process_usage(os.getpid())
  sessions = launcher.list_instances()
  runtime_size_bytes = get_directory_size_bytes(RUNTIME_DIR)
  running_instances = sum(1 for session in sessions if session.get("status") == "running")

  total_cpu = 0.0
  total_memory = 0.0
  instance_count_with_usage = 0

  if usage is not None:
    total_cpu += float(usage.get("cpu_percent", 0.0))
    total_memory += float(usage.get("memory_mb", 0.0))

  for session in sessions:
    proc_usage = session.get("usage")
    if not proc_usage:
      continue
    instance_count_with_usage += 1
    total_cpu += float(proc_usage.get("cpu_percent", 0.0))
    total_memory += float(proc_usage.get("memory_mb", 0.0))

  response.content_type = JSON_CONTENT_TYPE
  total = {
    "cpu_percent": round(total_cpu, 1),
    "memory_mb": round(total_memory, 1),
    "instance_count": instance_count_with_usage,
  }
  runtime = {
    "bytes": runtime_size_bytes,
    "megabytes": round(runtime_size_bytes / (1024.0 * 1024.0), 2),
  }

  if usage is None:
    return {"mux": None, "total": total, "runtime": runtime, "can_delete_runtime": running_instances == 0}

  return {
    "mux": {
      "pid": os.getpid(),
      **usage,
    },
    "total": total,
    "runtime": runtime,
    "can_delete_runtime": running_instances == 0,
  }


@app.get("/api/admin/code-stats")
@require_admin
def admin_code_stats():
  response.content_type = JSON_CONTENT_TYPE
  return {"code_stats": code_stats.get_stats()}


@app.post("/api/admin/stop-all")
@require_admin
def stop_all_instances():
    stopped_instances = launcher.stop_all()
    response.content_type = JSON_CONTENT_TYPE
    return {"stopped_instances": stopped_instances}


@app.post("/api/admin/delete-runtime-files")
@require_admin
def delete_runtime_files():
    if launcher.has_running_instances():
        raise HTTPError(409, "Stop all running instances before deleting runtime files")
    result = launcher.delete_runtime_files()
    response.content_type = JSON_CONTENT_TYPE
    return result


@app.post("/api/sessions/<instance_id>/stop")
@require_admin
def stop_session(instance_id: str):
  payload = request.json if isinstance(request.json, dict) else {}
  backend_ref = str(payload.get("backend_ref") or "").strip()
  normalized_ref = backend_ref.rsplit("/", 1)[-1] if backend_ref else ""
  stopped = False

  if backend_ref:
    stopped = launcher.stop_cloud_run_by_ref(normalized_ref)

  if not stopped:
    stopped = launcher.stop(instance_id)

  if not stopped and backend_ref and backend_ref != instance_id:
    stopped = launcher.stop(backend_ref)

  if not stopped:
    stopped = launcher._stop_cloud_run_instance_by_id(instance_id)

  if not stopped:
    stopped = launcher.stop_cloud_run_by_hint(instance_id)

  if not stopped:
    for session in launcher.list_instances():
      if str(session.get("id") or "") != instance_id:
        continue
      resolved_ref = str(session.get("backend_ref") or "").strip()
      if not resolved_ref:
        continue
      if launcher.stop_cloud_run_by_ref(resolved_ref):
        normalized_ref = resolved_ref
        stopped = True
        break

  if stopped:
    launcher.mark_cloud_run_record_stopped(instance_id, normalized_ref or None)

  if not stopped:
    if INSTANCE_BACKEND == "cloud-run":
      response.content_type = JSON_CONTENT_TYPE
      return {"status": "ok", "noop": True}
    raise HTTPError(404, "Instance not found")
  response.content_type = JSON_CONTENT_TYPE
  return {"status": "ok"}


if __name__ == "__main__":
    host = os.environ.get("MUX_HOST")
    if not host:
      host = "0.0.0.0" if (os.environ.get("PORT") or os.environ.get("K_SERVICE")) else "127.0.0.1"
    port = int(os.environ.get("PORT") or os.environ.get("MUX_PORT", "5050"))
    app.run(host=host, port=port, debug=False, reloader=False)