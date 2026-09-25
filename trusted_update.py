"""Narrow, signed Agent/Updater artifact validation for the update bootstrap."""

import hashlib
import base64
import binascii
import json
import os
import re
import subprocess
import sys
import uuid
from urllib.parse import urlparse

import requests


VERSION_RE = re.compile(r"^[0-9]+(?:\.[0-9]+){1,3}$")
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")


def version_parts(value):
    if not isinstance(value, str) or not VERSION_RE.fullmatch(value):
        raise ValueError("invalid release version")
    return tuple(int(part) for part in value.split("."))


def is_newer(candidate, installed):
    left, right = version_parts(candidate), version_parts(installed)
    width = max(len(left), len(right))
    return left + (0,) * (width - len(left)) > right + (0,) * (width - len(right))


def validate_artifact(release, kind):
    """Accept only the two fixed artifact routes and canonical R2 object keys."""
    if kind not in ("agent", "updater") or not isinstance(release, dict):
        raise ValueError("unsupported artifact type")
    version = release.get("version")
    version_parts(version)
    sha256 = release.get("sha256")
    if not isinstance(sha256, str) or not SHA256_RE.fullmatch(sha256):
        raise ValueError("invalid artifact SHA-256")
    filename = "GivovaMonitorAgent.exe" if kind == "agent" else "GivovaMonitorUpdater.exe"
    expected_key = f"agents/{version}/{filename}" if kind == "agent" else f"updaters/{version}/{filename}"
    expected_url = f"/api/agent/download/{version}" if kind == "agent" else f"/api/agent/updater/download/{version}"
    if release.get("object_key") != expected_key or release.get("download_url") != expected_url:
        raise ValueError("artifact route or key is not canonical")
    return version, sha256


def verify_sha256(path, expected):
    if not isinstance(expected, str) or not SHA256_RE.fullmatch(expected):
        raise ValueError("invalid expected SHA-256")
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(65536), b""):
            digest.update(chunk)
    if digest.hexdigest() != expected:
        raise ValueError("artifact SHA-256 mismatch")


def authenticode_publisher(path):
    """Use Windows' Authenticode verification only; never relax OS execution policy."""
    if sys.platform != "win32":
        raise RuntimeError("Authenticode is available only on Windows")
    script = (
        "$s=Get-AuthenticodeSignature -LiteralPath $env:GIVOVA_VERIFY_PATH; "
        "if($s.Status -eq 'Valid' -and $s.SignerCertificate)"
        "{[Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($s.SignerCertificate.Subject))}else{exit 1}"
    )
    env = dict(os.environ, GIVOVA_VERIFY_PATH=os.path.abspath(path))
    result = subprocess.run(
        ["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", script],
        env=env, capture_output=True, text=True, timeout=20, check=False,
    )
    try:
        publisher = base64.b64decode(result.stdout.strip(), validate=True).decode("utf-8")
    except (ValueError, UnicodeError, binascii.Error):
        publisher = ""
    if result.returncode or not publisher:
        raise ValueError("Authenticode signature is not valid")
    return publisher


def verify_same_signer(path, trusted_bootstrap):
    if authenticode_publisher(path) != authenticode_publisher(trusted_bootstrap):
        raise ValueError("artifact publisher differs from trusted updater")


def approved_url(base_url, release, kind):
    validate_artifact(release, kind)
    parsed = urlparse(base_url)
    if parsed.scheme != "https" or not parsed.netloc or parsed.username or parsed.password:
        raise ValueError("update server must use HTTPS")
    return f"{parsed.scheme}://{parsed.netloc}{release['download_url']}"


def load_update_identity(target_dir):
    override = os.environ.get("GIVOVA_CONFIG_PATH")
    if override:
        config_path = os.path.expandvars(override.strip())
    else:
        candidates = ([r"C:\ProgramData\GivovaMonitor\agent_config.json"]
                      if sys.platform == "win32" else [])
        candidates.append(os.path.join(target_dir, "agent_config.json"))
        config_path = next((path for path in candidates if os.path.isfile(path)), None)
    if not config_path or not os.path.isfile(config_path):
        raise ValueError("Agent configuration is missing")
    with open(config_path, encoding="utf-8") as handle:
        config = json.load(handle)
    parsed = urlparse(config.get("server_url", ""))
    if parsed.scheme != "https" or not parsed.netloc or parsed.username or parsed.password:
        raise ValueError("Agent update server must use HTTPS")
    token = config.get("agent_token")
    if not isinstance(token, str) or not token:
        raise ValueError("Agent update token is missing")
    headers = {"X-Agent-Token": token, "X-Device-UUID": f"node-{hex(uuid.getnode())[2:]}"}
    if config.get("device_token"):
        headers["X-Device-Token"] = config["device_token"]
    return f"{parsed.scheme}://{parsed.netloc}", headers


def fetch_updater_plan(base_url, headers, agent_version):
    version_parts(agent_version)
    response = requests.get(
        f"{base_url}/api/agent/updater/check",
        headers=headers, params={"agent_version": agent_version}, timeout=15,
    )
    response.raise_for_status()
    plan = response.json()
    if not isinstance(plan, dict):
        raise ValueError("invalid updater plan")
    version_parts(plan.get("min_updater_version"))
    release = plan.get("updater_release")
    if release is not None:
        validate_artifact(release, "updater")
    return plan


def stage_updater(base_url, headers, release, target_dir, trusted_bootstrap, agent_version):
    version, sha256 = validate_artifact(release, "updater")
    version_parts(agent_version)
    destination_dir = os.path.join(target_dir, "updaters")
    os.makedirs(destination_dir, exist_ok=True)
    for existing in os.listdir(destination_dir):
        match = re.fullmatch(r"GivovaMonitorUpdater-v([0-9]+(?:\.[0-9]+){1,3})\.exe", existing)
        if match and is_newer(match.group(1), version):
            raise ValueError("Updater downgrade is not allowed")
    destination = os.path.join(destination_dir, f"GivovaMonitorUpdater-v{version}.exe")
    if os.path.isfile(destination):
        try:
            verify_sha256(destination, sha256)
            verify_same_signer(destination, trusted_bootstrap)
            return destination
        except (OSError, ValueError):
            pass

    staged = destination + ".tmp"
    try:
        url = approved_url(base_url, release, "updater")
        response = requests.get(url, headers=headers, params={"agent_version": agent_version},
                                stream=True, timeout=60, allow_redirects=False)
        if response.status_code == 302:
            location = response.headers.get("Location", "")
            redirect = urlparse(location)
            if redirect.scheme != "https" or not redirect.hostname or not redirect.hostname.endswith(".r2.cloudflarestorage.com"):
                raise ValueError("updater download redirected outside approved R2")
            response.close()
            response = requests.get(location, stream=True, timeout=60, headers={})
        response.raise_for_status()
        with response, open(staged, "wb") as handle:
            for chunk in response.iter_content(chunk_size=65536):
                if chunk:
                    handle.write(chunk)
        verify_sha256(staged, sha256)
        verify_same_signer(staged, trusted_bootstrap)
        os.replace(staged, destination)
        return destination
    finally:
        if os.path.exists(staged):
            os.remove(staged)
