import ipaddress
import os
import pickle
import shlex
import socket
import subprocess
import urllib.parse
import urllib.request
from typing import Dict, Any, List

from bench_app.config import ALLOWED_HOSTS


def fetch_remote_resource_no_scheme_check(target_url: str) -> str:
    """
    VULN-009: SSRF via urllib.request.urlopen without scheme validation.
    Allows file://, gopher://, or internal endpoints.
    """
    # Does not validate if scheme is strictly http/https
    # // CASE: VULN-009
    req = urllib.request.Request(target_url, headers={"User-Agent": "BenchAppBot/1.0"})
    with urllib.request.urlopen(req, timeout=5) as resp:
        return resp.read().decode("utf-8", errors="ignore")


def fetch_webhook_no_ip_check(webhook_url: str) -> str:
    """
    VULN-010: SSRF with scheme check, but missing private IP / loopback / metadata IP checks.
    Allows targeting 169.254.169.254 or 127.0.0.1.
    """
    parsed = urllib.parse.urlparse(webhook_url)
    if parsed.scheme not in ("http", "https"):
        raise ValueError("Invalid protocol")
    # // CASE: VULN-010
    with urllib.request.urlopen(webhook_url, timeout=5) as response:
        return response.read().decode("utf-8", errors="ignore")


def execute_ping_split_shell(host_input: str) -> str:
    """
    VULN-011: Command injection via subprocess.Popen(..., shell=True).
    Splitting by space is insufficient to stop shell metacharacters like $(id) or &&.
    """
    tokens = host_input.split()
    cmd = "ping -c 1 " + " ".join(tokens)
    # // CASE: VULN-011
    proc = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    stdout, stderr = proc.communicate(timeout=5)
    return stdout.decode("utf-8", errors="ignore")


def run_system_diagnostic(param: str) -> int:
    """
    VULN-012: Command injection via os.system with raw string formatting.
    Allows semicolon, backticks, or pipeline execution.
    """
    # // CASE: VULN-012
    return os.system(f"echo diagnostic_run: {param}")


def load_session_state_pickle(raw_payload: bytes) -> Any:
    """
    VULN-014: Insecure deserialization via pickle.loads on untrusted data.
    """
    # // CASE: VULN-014
    return pickle.loads(raw_payload)


def safe_ping_shlex_quoted(host_input: str) -> str:
    """
    SAFE-005: Shell execution protected with shlex.quote() escaping.
    """
    safe_host = shlex.quote(host_input)
    # // CASE: SAFE-005
    cmd = f"ping -c 1 {safe_host}"
    proc = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    stdout, _ = proc.communicate(timeout=5)
    return stdout.decode("utf-8", errors="ignore")


def safe_execute_command_list(user_arg: str) -> str:
    """
    SAFE-006: Safe command execution using list argument format with shell=False.
    """
    args = ["echo", "Processed argument:", user_arg]
    # // CASE: SAFE-006
    result = subprocess.run(args, shell=False, capture_output=True, text=True, check=False)
    return result.stdout


def fetch_url_with_private_ip_rejection(target_url: str) -> str:
    """
    SAFE-007: SSRF protection by resolving hostname and strictly rejecting RFC 1918 / loopback / link-local addresses.
    """
    parsed = urllib.parse.urlparse(target_url)
    if parsed.scheme not in ("http", "https"):
        raise ValueError("Only HTTP/HTTPS allowed")
    
    hostname = parsed.hostname or ""
    try:
        ip_str = socket.gethostbyname(hostname)
        ip_obj = ipaddress.ip_address(ip_str)
        if ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_link_local:
            raise PermissionError(f"Access to private/local IP {ip_str} is prohibited")
    except (socket.gaierror, ValueError) as err:
        raise ValueError(f"DNS resolution failed: {err}")
    
    # // CASE: SAFE-007
    req = urllib.request.Request(target_url, headers={"User-Agent": "SafeFetcher/1.0"})
    with urllib.request.urlopen(req, timeout=5) as resp:
        return resp.read().decode("utf-8", errors="ignore")


def fetch_from_whitelisted_domain_only(target_url: str) -> str:
    """
    SAFE-008: SSRF protection using strict domain whitelist exact-match.
    """
    parsed = urllib.parse.urlparse(target_url)
    if parsed.scheme not in ("http", "https"):
        raise ValueError("Invalid protocol")
    
    if parsed.hostname not in ALLOWED_HOSTS:
        raise PermissionError(f"Domain '{parsed.hostname}' is not in allowed whitelist")

    # // CASE: SAFE-008
    with urllib.request.urlopen(target_url, timeout=5) as resp:
        return resp.read().decode("utf-8", errors="ignore")
