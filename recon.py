#!/usr/bin/env python3
"""
reconkit - a combined external + internal reconnaissance orchestrator.

It implements the workflow of two pentest cheat sheets in one tool:

  * External / public-target recon  (domain & IP)   -> passive, scope, active
  * Internal network discovery      (post-foothold)  -> internal
  * Content / directory discovery    (ffuf/gobuster)  -> content
  * Lead triage + report note                         -> analyze, report

Design principles (taken straight from the cheat sheets):

  * Authorization first. Active phases refuse to run unless an explicit scope
    allowlist exists and you confirm authorization.  A resolving subdomain or a
    shared IP is NOT automatically in scope.
  * Evidence by default. Every external command is recorded in
    evidence/commands.log with the UTC time, exact argv, output file and exit
    code, so another tester can reproduce it.
  * Leads, not verdicts. A banner or version string is a *lead* to validate,
    never a confirmed vulnerability.  No exploit checks, credential attempts or
    `vuln` NSE categories are ever run.

Everything here uses only the Python standard library.  External binaries
(dig, nmap, nc, curl, openssl, whois, ffuf, gobuster, subfinder, ...) are
invoked when present and degraded gracefully when absent.

USE ONLY AGAINST SYSTEMS YOU ARE EXPLICITLY AUTHORIZED TO TEST.

Copyright (C) 2026 Elchin Guliyev
SPDX-License-Identifier: GPL-3.0-or-later
This program is free software under the GNU GPL v3 or later; see the LICENSE file.
"""

from __future__ import annotations

import argparse
import concurrent.futures
import datetime
import hashlib
import ipaddress
import json
import os
import random
import re
import shlex
import shutil
import ssl
import string
import subprocess
import sys
import urllib.error
import urllib.request
import xml.etree.ElementTree as ET

# ---------------------------------------------------------------------------
# small helpers
# ---------------------------------------------------------------------------

RECON_ROOT = "recon"
CURRENT_PTR = os.path.join(RECON_ROOT, ".current")
DOMAIN_RE = re.compile(r"^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?:\.[A-Za-z0-9-]{1,63})+$")
SUBDIRS = ("passive", "active", "content", "internal", "evidence", "report")

C_RED = "\033[31m"; C_YEL = "\033[33m"; C_GRN = "\033[32m"; C_CYN = "\033[36m"; C_DIM = "\033[2m"; C_RST = "\033[0m"

BANNER = r"""
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣠⣤⡀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣤⡀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢰⢁⣿⣿⣷⡄⠀⠀⠀⠀⠀⣴⣿⣿⣷⡀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣾⢸⡿⠿⣿⣿⣦⣤⣤⣤⣤⣬⣉⣻⣿⣧
⠀⠀⠀⠀⠀⠀⠀⠀⠀⢰⣿⠀⣶⣶⣬⣿⣿⣿⣿⣿⣿⣿⣿⣿⣦⡝⠆
⠀⠀⠀⠀⠀⠀⠀⠀⠀⢸⣿⣸⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣆
⠀⠀⠀⠀⠀⠀⠀⠀⠀⢸⣿⣿⣿⣿⣿⣿⣿⣿⠿⠿⣿⣿⣿⣿⡏⠉⢻
⠀⠀⠀⠀⠀⠀⠀⠀⠀⢸⣿⣿⣿⣿⣿⣿⣿⡏⠀⠀⣿⣿⣿⣿⣷⣄⣼⣷⡒
⠀⢀⣠⣤⣤ ⠀⠀⠀⠸⣿⣿⣿⣿⣿⣿⠖⣻⣶⣾⣿⣿⣿⣧⣿⣿⣿⣿⠉
⣿⣿⣿⣿⣿⣷⣄⠀ ⠹⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡿⠏      ⠀⠀⠀⢀⡴⢲⡄⠀⠀⠀⢀⣀
⠈⢿⣿⣿⣿⣿⣿⣿⡄   ⠙⠛⠿⠿⣿⣿⣿⣿⣿⣿⣿⣿⡋⠁       ⠀⠀⢀⡞⠀⠀⡇⠀⢀⡴⠋⠁⢸
⠀⠀⠉⢻⣿⣿⣿⣿⣧   ⣠⣶⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡀       ⠀⠀⣸⠁⠀⠀⡇⣠⠟⠀⠀⠀⣼⣠⣤⣤⣀
⠀⠀⠀⠘⣿⣿⣿⣿⡟ ⢀⣼⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣇       ⠀⠀⣿⠀⢠⢤⡿⠃⣀⠀⢀⡞⠉⠁⠀⠀⠈⠙⠶⡄
⠀⠀⠀⢰⣿⣿⣿⣿⠇⢀⣾⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿       ⠀⠀⣻⣰⡏⣼⢁⡴⠋⣰⠋⠀⠀⠀⠀⠀⠀⠀⠀⠹⡄⣀⡀
⠀⠀⠀⣾⣿⣿⣿⡟⠀⣾⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⢿⡿       ⢀⡾⠋⠉⠁⠀⠙⠁⠞⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢹⡈⢷
⠀⠀⢰⣿⣿⣿⣿⠀⢸⣿⣿⣿⣿⣿⣿⠿⣿⣿⣿⣿⣿⣿⣿⡇⣼⡇       ⣼⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠄⠀⠀⠀⠀⠀⠀⠀⢀⣧⡾⠁
⠀⠀⢸⣿⣿⣿⣇⠀⣿⣿⣿⣿⣿⣿⣿⣷⣌⢻⣿⣿⣿⣿⣿⣴⣿⡇       ⡏⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠄⠀⠀⠀⠀⠀⠀⠀⣾⠃
⠀⠀⠸⣿⣿⣿⣿⣤⣿⣿⣿⣿⣿⣿⣿⣿⣿⠄⣿⣿⣿⣿⡏⢸⣿⡇       ⣹⡄⠀⠀⠀⠀⠀⠀⠀⠀⠀⠘⠁⠀⠀⡀⠀⠀⢰⡾⠋
⠀⠀⠀⠙⢿⣿⣿⡇⢿⣿⣿⣿⣿⣿⣿⣿⡿⠀⣿⣿⣿⣿⡇⣿⣿        ⢻⡇⣀⡀⠀⠺⣿⠇⠀⣀⣤⣄⣀⣠⣬⣥⣤⠾⠛⠁
⠀⠀⠀⠀⠀⠉⠙⠛⠂⠙⠛⠛⠛⠛⠛⠛⠐⠓⠈⠙⠋⠋⠃⠉⠉        ⠀⠉⠛⠓⠂⠤⠤⠖⠊⠉⠉⠉⠉⠁
"""

# "reconkit" rendered in the figlet "small" font, shown beside the art.
WORDMARK = r"""                     _   _ _
 _ _ ___ __ ___ _ _ | |_(_) |_
| '_/ -_) _/ _ \ ' \| / / |  _|
|_| \___\__\___/_||_|_\_\_|\__|"""

# which art row the wordmark's top line sits on, and the column it starts at.
_WORDMARK_ROW = 2
_WORDMARK_COL = 30


def _color(s: str, c: str) -> str:
    return s if not sys.stdout.isatty() else f"{c}{s}{C_RST}"


def _compose_banner() -> str:
    """Overlay the `reconkit` wordmark into the empty top-right of the art."""
    art = BANNER.strip("\n").split("\n")
    word = WORDMARK.split("\n")
    out = []
    for i, line in enumerate(art):
        w = i - _WORDMARK_ROW
        if 0 <= w < len(word) and word[w].strip():
            left = _color(line.ljust(_WORDMARK_COL), C_CYN)
            out.append(left + _color(word[w], C_GRN))
        else:
            out.append(_color(line, C_CYN))
    return "\n".join(out)


def print_banner() -> None:
    print()
    print(_compose_banner())
    print()
    tagline = "reconkit — combined external + internal recon orchestrator"
    print("  " + _color(tagline, C_GRN))
    print("  " + _color("authorized testing only · leads, not verdicts · every command logged", C_DIM))
    print()


def utcnow() -> str:
    return datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def utcstamp() -> str:
    return datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%dT%H%M%SZ")


def info(msg: str) -> None:
    print(_color("[*] ", C_CYN) + msg)


def good(msg: str) -> None:
    print(_color("[+] ", C_GRN) + msg)


def warn(msg: str) -> None:
    print(_color("[!] ", C_YEL) + msg)


def err(msg: str) -> None:
    print(_color("[x] ", C_RED) + msg, file=sys.stderr)


def have(tool: str) -> bool:
    return shutil.which(tool) is not None


def classify_target(t: str) -> str:
    try:
        ipaddress.ip_address(t)
        return "ip"
    except ValueError:
        if DOMAIN_RE.match(t):
            return "domain"
    return "unknown"


def safe_name(t: str) -> str:
    return re.sub(r"[^A-Za-z0-9._-]", "_", t)


# ---------------------------------------------------------------------------
# case / scope
# ---------------------------------------------------------------------------

class Case:
    def __init__(self, path: str):
        self.path = os.path.abspath(path)
        self.meta = self._load_json("case.json", {})
        self.scope = self._load_json("scope.json", {"domains": [], "ips": [], "cidrs": [], "hosts": [], "authorized": False})

    def _load_json(self, name, default):
        p = os.path.join(self.path, name)
        if os.path.exists(p):
            try:
                with open(p) as f:
                    return json.load(f)
            except Exception:
                return default
        return default

    def save_json(self, name, obj):
        with open(os.path.join(self.path, name), "w") as f:
            json.dump(obj, f, indent=2)

    def d(self, sub: str) -> str:
        p = os.path.join(self.path, sub)
        os.makedirs(p, exist_ok=True)
        return p

    def f(self, sub: str, name: str) -> str:
        return os.path.join(self.d(sub), name)

    # ---- evidence logging ----
    def log_cmd(self, argv, outfile, exit_code, note=""):
        line = {
            "utc": utcnow(),
            "argv": argv if isinstance(argv, list) else [argv],
            "output": os.path.relpath(outfile, self.path) if outfile else None,
            "exit": exit_code,
            "note": note,
        }
        with open(os.path.join(self.d("evidence"), "commands.log"), "a") as f:
            f.write(json.dumps(line) + "\n")

    # ---- scope checks ----
    def host_in_scope(self, host: str) -> bool:
        host = host.lower().rstrip(".")
        if host in [h.lower() for h in self.scope.get("hosts", [])]:
            return True
        for dom in self.scope.get("domains", []):
            dom = dom.lower().lstrip("*.").lstrip(".")
            if host == dom or host.endswith("." + dom):
                return True
        return False

    def ip_in_scope(self, ip: str) -> bool:
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return False
        if ip in self.scope.get("ips", []):
            return True
        for cidr in self.scope.get("cidrs", []):
            try:
                if addr in ipaddress.ip_network(cidr, strict=False):
                    return True
            except ValueError:
                continue
        return False

    def in_scope(self, target: str) -> bool:
        return self.ip_in_scope(target) if classify_target(target) == "ip" else self.host_in_scope(target)


def resolve_case(args) -> Case:
    path = getattr(args, "case", None)
    if not path and os.path.exists(CURRENT_PTR):
        with open(CURRENT_PTR) as f:
            path = f.read().strip()
    if not path or not os.path.isdir(path):
        err("No case found. Run `recon.py init <target>` first (or pass --case <dir>).")
        sys.exit(2)
    return Case(path)


# ---------------------------------------------------------------------------
# subprocess wrapper (logs everything)
# ---------------------------------------------------------------------------

def run(case: Case, argv, outfile=None, timeout=600, note="", quiet=False, use_sudo=False):
    """Run an external command, capture stdout to outfile, log to evidence."""
    if use_sudo:
        argv = ["sudo", "-n"] + argv
    tool = argv[1] if use_sudo else argv[0]
    if not have(tool):
        warn(f"'{tool}' not installed - skipping: {' '.join(argv)}")
        case.log_cmd(argv, outfile, -127, note="tool-missing:" + tool)
        return -127, "", "tool-missing"
    if not quiet:
        print(_color("    $ " + " ".join(argv), C_DIM))
    try:
        proc = subprocess.run(argv, capture_output=True, text=True, timeout=timeout)
        out, errout, code = proc.stdout, proc.stderr, proc.returncode
    except subprocess.TimeoutExpired:
        out, errout, code = "", f"timeout after {timeout}s", -9
    except Exception as e:  # noqa: BLE001
        out, errout, code = "", str(e), -1
    if outfile and out:
        with open(outfile, "w") as f:
            f.write(out)
    case.log_cmd(argv, outfile, code, note=note)
    return code, out, errout


# ---------------------------------------------------------------------------
# lightweight HTTP (stdlib) for crt.sh / wayback / content fuzzing
# ---------------------------------------------------------------------------

UA = "reconkit/1.0 (authorized-recon)"


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: D401
        return None


MAX_BODY = 512 * 1024  # never pull a whole backup.tar.gz onto a worker thread


def http_get(url, timeout=12, method="GET", follow=True, insecure=False):
    """Return (status, headers_dict, body_bytes, error_str). Body is capped."""
    ctx = ssl.create_default_context()
    if insecure:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    handlers = [urllib.request.HTTPSHandler(context=ctx)]
    if not follow:
        handlers.append(_NoRedirect())
    opener = urllib.request.build_opener(*handlers)
    req = urllib.request.Request(url, method=method, headers={"User-Agent": UA})
    try:
        resp = opener.open(req, timeout=timeout)
        return resp.status, dict(resp.headers), resp.read(MAX_BODY), None
    except urllib.error.HTTPError as e:
        try:
            body = e.read(MAX_BODY)
        except Exception:
            body = b""
        return e.code, dict(e.headers or {}), body, None
    except Exception as e:  # noqa: BLE001
        return None, {}, b"", str(e)


# ---------------------------------------------------------------------------
# dependency check / install  (cross-platform, consent-based)
# ---------------------------------------------------------------------------

# Tools the core recon workflow needs, and the optional enhancers.
REQUIRED_TOOLS = ["dig", "nmap", "nc", "curl", "openssl", "whois", "ip", "ss"]
OPTIONAL_TOOLS = ["ffuf", "gobuster", "subfinder", "theHarvester", "seclists"]

# Per-family package plan. Each tool maps to (installer, package); "go"/"manual"
# entries carry a command/note. Arch is verified on this machine; the apt/dnf/
# brew maps are BEST-EFFORT and not tested -- verify names before trusting them.
PKG_PLAN = {
    "arch": {
        "label": "Arch/Omarchy (pacman + yay)",
        "repo": {"dig": "bind", "nmap": "nmap", "nc": "openbsd-netcat", "curl": "curl",
                 "openssl": "openssl", "ip": "iproute2", "ss": "iproute2",
                 "whois": "whois", "gobuster": "gobuster"},
        "aur": {"ffuf": "ffuf-bin", "subfinder": "subfinder-bin", "seclists": "seclists-git"},
        "manual": {"theHarvester": "sudo pacman -S python-pipx && pipx install theHarvester"},
    },
    "debian": {
        # Kali is the intended runtime: its repos carry ffuf/gobuster/seclists/
        # theharvester. Plain Debian/Ubuntu may lack some; subfinder usually
        # needs `go install` outside Kali.
        "label": "Debian/Ubuntu/Kali (apt)",
        "repo": {"dig": "dnsutils", "nmap": "nmap", "nc": "netcat-openbsd", "curl": "curl",
                 "openssl": "openssl", "ip": "iproute2", "ss": "iproute2", "whois": "whois",
                 "gobuster": "gobuster", "ffuf": "ffuf", "seclists": "seclists",
                 "theHarvester": "theharvester"},
        "go": {"subfinder": "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"},
    },
    "fedora": {
        "label": "Fedora/RHEL (dnf) [best-effort, untested]",
        "repo": {"dig": "bind-utils", "nmap": "nmap", "nc": "nmap-ncat", "curl": "curl",
                 "openssl": "openssl", "ip": "iproute", "ss": "iproute", "whois": "whois"},
        "go": {"ffuf": "github.com/ffuf/ffuf/v2@latest",
               "gobuster": "github.com/OJ/gobuster/v3@latest",
               "subfinder": "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"},
        "manual": {"theHarvester": "pipx install theHarvester"},
    },
    "darwin": {
        "label": "macOS (Homebrew) [best-effort, untested]",
        "repo": {"dig": "bind", "nmap": "nmap", "whois": "whois", "curl": "curl",
                 "openssl": "openssl", "ffuf": "ffuf", "gobuster": "gobuster",
                 "subfinder": "subfinder", "seclists": "seclists"},
        "manual": {"theHarvester": "pipx install theHarvester", "nc": "built-in on macOS",
                   "ip": "use `ifconfig`/`route` on macOS", "ss": "use `netstat` on macOS"},
    },
}


def detect_platform(os_release_path="/etc/os-release"):
    """Return (family, label). Matches ID and ID_LIKE so arch derivatives
    (omarchy, manjaro, endeavouros) are recognised, then falls back to which
    package manager is actually installed."""
    if sys.platform == "darwin":
        return "darwin", PKG_PLAN["darwin"]["label"]
    ids = ""
    try:
        with open(os_release_path) as f:
            ids = f.read().lower()
    except OSError:
        pass
    fields = dict(re.findall(r'^(\w+)=["\']?([^"\'\n]*)', ids, re.M))
    tokens = (fields.get("id", "") + " " + fields.get("id_like", "")).split()
    if any(t in tokens for t in ("arch", "archlinux", "omarchy", "manjaro", "endeavouros")):
        return "arch", PKG_PLAN["arch"]["label"]
    if any(t in tokens for t in ("debian", "ubuntu", "kali")):
        return "debian", PKG_PLAN["debian"]["label"]
    if any(t in tokens for t in ("fedora", "rhel", "centos")):
        return "fedora", PKG_PLAN["fedora"]["label"]
    # fallback by package manager binary
    for fam, binname in (("arch", "pacman"), ("debian", "apt-get"), ("fedora", "dnf")):
        if have(binname):
            return fam, PKG_PLAN[fam]["label"] + " (detected by package manager)"
    return "unknown", "unknown platform"


def _tool_installed(tool):
    if tool == "seclists":
        return any(os.path.exists(c) for c in SECLISTS_CANDIDATES) or os.path.isdir(
            "/usr/share/seclists") or os.path.isdir("/usr/share/wordlists/seclists")
    if tool == "theHarvester":
        return have("theHarvester") or have("theharvester")
    return have(tool)


def _build_install_plan(family, tools):
    """Group missing tools into (sudo repo cmd, user aur cmd, go cmds, manual notes)."""
    plan = PKG_PLAN.get(family, {})
    repo_pkgs, aur_pkgs, go_cmds, manual = [], [], [], []
    for t in tools:
        if t in plan.get("repo", {}):
            repo_pkgs.append(plan["repo"][t])
        elif t in plan.get("aur", {}):
            aur_pkgs.append(plan["aur"][t])
        elif t in plan.get("go", {}):
            go_cmds.append((t, plan["go"][t]))
        elif t in plan.get("manual", {}):
            manual.append((t, plan["manual"][t]))
        else:
            manual.append((t, "no known package for this platform; install manually"))
    cmds = []
    if repo_pkgs:
        if family == "arch":
            cmds.append(["sudo", "pacman", "-S", "--needed"] + sorted(set(repo_pkgs)))
        elif family == "debian":
            cmds.append(["sudo", "apt-get", "install", "-y"] + sorted(set(repo_pkgs)))
        elif family == "fedora":
            cmds.append(["sudo", "dnf", "install", "-y"] + sorted(set(repo_pkgs)))
        elif family == "darwin":
            cmds.append(["brew", "install"] + sorted(set(repo_pkgs)))
    if aur_pkgs:  # Arch AUR: run as the user (makepkg refuses root), no --noconfirm
        cmds.append(["yay", "-S", "--needed"] + sorted(set(aur_pkgs)))
    for t, mod in go_cmds:
        cmds.append(["go", "install", mod])
    return cmds, go_cmds, manual


def _run_installer(argv):
    """Run with the terminal ATTACHED so sudo/yay prompts are visible (no capture)."""
    print(_color("    $ " + " ".join(argv), C_DIM))
    try:
        return subprocess.run(argv).returncode
    except FileNotFoundError:
        err(f"'{argv[0]}' not found; install it first or use --print.")
        return -127
    except KeyboardInterrupt:
        err("install interrupted")
        return 130


def cmd_deps(args):
    family, label = detect_platform(args.os_release or "/etc/os-release")
    info(f"Platform: {label}")
    missing_req = [t for t in REQUIRED_TOOLS if not _tool_installed(t)]
    missing_opt = [t for t in OPTIONAL_TOOLS if not _tool_installed(t)]

    print()
    print("  Required tools:")
    for t in REQUIRED_TOOLS:
        ok = _tool_installed(t)
        print(f"    [{'x' if ok else ' '}] {t}" + ("" if ok else "  MISSING"))
    print("  Optional tools:")
    for t in OPTIONAL_TOOLS:
        ok = _tool_installed(t)
        print(f"    [{'x' if ok else ' '}] {t}" + ("" if ok else "  (enhances recon)"))
    print()

    missing = (missing_req if args.required_only else missing_req + missing_opt)
    if not missing:
        good("All dependencies present. Nothing to install.")
        return
    if family == "unknown":
        err("Could not identify the platform/package manager; install these manually: "
            + ", ".join(missing))
        return

    cmds, go_cmds, manual = _build_install_plan(family, missing)
    warn(f"Missing: {', '.join(missing)}")
    if cmds:
        print("  Install command(s):")
        for c in cmds:
            print("    " + " ".join(c))
    for t, note in manual:
        print(f"  {t}: {note}")
    if family != "arch":
        warn("Non-Arch package names are best-effort and untested; verify before running.")
    print()

    if args.check:
        return
    # choose action
    if args.yes:
        choice = "i"
    elif args.print_only or args.dry_run or not sys.stdin.isatty():
        if not args.dry_run:
            info("Non-interactive (or --print): showing commands only; run them yourself.")
        return
    else:
        try:
            ans = input("  [I]nstall them for me / [P]rint commands, I'll do it / [S]kip? ")
        except EOFError:
            ans = "s"
        choice = (ans.strip().lower() or "s")[0]

    if choice == "p":
        info("Printed above; run them when ready.")
        return
    if choice != "i":
        info("Skipped. Re-run `recon.py deps` anytime.")
        return

    for c in cmds:
        rc = _run_installer(c)
        if rc != 0:
            warn(f"'{' '.join(c[:3])} ...' exited {rc}; continuing with the rest.")
    for t, note in manual:
        warn(f"{t} needs a manual step (not automated): {note}")
    # re-check
    still = [t for t in missing if not _tool_installed(t)]
    if still:
        warn(f"Still missing after install attempt: {', '.join(still)}")
    else:
        good("All requested dependencies are now present.")


# ---------------------------------------------------------------------------
# init
# ---------------------------------------------------------------------------

def cmd_init(args):
    target = args.target.strip()
    kind = classify_target(target)
    if kind == "unknown":
        err(f"'{target}' is not a valid domain or IP address.")
        sys.exit(2)
    case_dir = os.path.join(RECON_ROOT, safe_name(target), utcstamp())
    os.makedirs(case_dir, exist_ok=True)
    case = Case(case_dir)
    for sub in SUBDIRS:
        case.d(sub)

    with open(case.f("evidence", "start-utc.txt"), "w") as f:
        f.write(utcnow() + "\n")

    case.meta = {
        "target": target,
        "type": kind,
        "host": args.host or (target if kind == "domain" else None),
        "created_utc": utcnow(),
    }
    case.save_json("case.json", case.meta)

    # Seed scope CONSERVATIVELY. A bare domain target authorizes only that exact
    # host (+ --host), never *.domain -- discovering a subdomain does not
    # authorize scanning it. Suffix-wide authority comes only from --scope-domain.
    raw_hosts = list(args.scope_host or [])
    if args.host:
        raw_hosts.append(args.host)
    if kind == "domain":
        raw_hosts.append(target)
    ips = list(args.scope_ip or ([target] if kind == "ip" else []))
    hosts = []
    for h in raw_hosts:  # an IP-valued host belongs in the IP allowlist, not hosts
        (ips if classify_target(h.split(":")[0]) == "ip" else hosts).append(h.split(":")[0])
    scope = {
        "domains": list(args.scope_domain or []),
        "ips": sorted(set(ips)),
        "cidrs": list(args.scope_cidr or []),
        "hosts": sorted(set(hosts)),
        "authorized": bool(args.authorized),
        "note": "Edit this file to match the engagement's written authorization. "
                "Active phases refuse to run until 'authorized' is true and the "
                "target is listed here. 'domains' is a SUFFIX allowlist (*.dom); "
                "'hosts' authorizes exact names only. Add discovered subdomains "
                "explicitly once they are confirmed in scope.",
    }
    case.save_json("scope.json", scope)

    with open(CURRENT_PTR, "w") as f:
        f.write(case.path)

    good(f"Case created: {case.path}")
    info(f"Target: {target}  ({kind})")
    for sub in SUBDIRS:
        print(f"      {os.path.join(case.path, sub)}/")
    print()
    info("Scope file: " + os.path.join(case.path, "scope.json"))
    if not scope["authorized"]:
        warn("Authorization NOT confirmed. Edit scope.json (set \"authorized\": true) "
             "or pass --authorized once you have written approval before active phases.")


# ---------------------------------------------------------------------------
# passive (domain + ip)
# ---------------------------------------------------------------------------

def _clean_subdomains(names, suffixes):
    cleaned = set()
    for raw in names:
        for n in re.split(r"[\s,]+", raw.strip()):
            n = n.lower().strip().rstrip(".")
            if not n:
                continue
            n = n.lstrip("*.").lstrip(".")
            if "*" in n or " " in n:
                continue
            if not DOMAIN_RE.match(n):
                continue
            if suffixes and not any(n == s or n.endswith("." + s) for s in suffixes):
                continue
            cleaned.add(n)
    return sorted(cleaned)


def _crtsh(domain, case):
    url = f"https://crt.sh/?q=%25.{domain}&output=json"
    info(f"crt.sh certificate transparency: {url}")
    status, _, body, error = http_get(url, timeout=30)
    case.log_cmd(["http_get", url], case.f("passive", "crtsh.json"), status or -1,
                 note="third-party-index")
    if error or not body:
        warn(f"crt.sh query failed ({error or status}); record the manual URL instead.")
        return []
    with open(case.f("passive", "crtsh.json"), "wb") as f:
        f.write(body)
    names = []
    try:
        for row in json.loads(body.decode("utf-8", "replace")):
            for key in ("name_value", "common_name"):
                if row.get(key):
                    names.append(row[key])
    except Exception as e:  # noqa: BLE001
        warn(f"could not parse crt.sh JSON: {e}")
    return names


def _wayback(domain, case):
    url = (f"https://web.archive.org/cdx/search/cdx?url=*.{domain}"
           f"&output=text&fl=original&collapse=urlkey&limit=2000")
    info("Wayback Machine (historical URLs)")
    status, _, body, error = http_get(url, timeout=30)
    case.log_cmd(["http_get", url], case.f("passive", "wayback.txt"), status or -1,
                 note="third-party-index")
    if error or not body:
        warn(f"wayback query failed ({error or status}); record the manual URL instead.")
        return []
    with open(case.f("passive", "wayback.txt"), "wb") as f:
        f.write(body)
    hosts = []
    for line in body.decode("utf-8", "replace").splitlines():
        m = re.search(r"https?://([^/\s:]+)", line)
        if m:
            hosts.append(m.group(1))
    return hosts


DIG_RECORDS = ("A", "AAAA", "MX", "NS", "TXT", "SOA", "CAA")


def _dig(case, name, rtype, outname=None):
    argv = ["dig", "+short", rtype, name]
    outfile = case.f("passive", outname or f"dns_{rtype}_{safe_name(name)}.txt")
    code, out, _ = run(case, argv, outfile=outfile, timeout=30, quiet=True)
    if code != 0:  # dig prints ';; ... error' to STDOUT and exits nonzero on failure
        return ""
    # drop any ';;' diagnostic lines so a resolver error isn't read as data
    return "\n".join(l for l in out.splitlines() if l.strip() and not l.lstrip().startswith(";"))


def cmd_passive(args):
    case = resolve_case(args)
    target = case.meta["target"]
    kind = case.meta["type"]
    info(f"Passive discovery for {target} ({kind}) - {utcnow()}")

    summary = {"utc": utcnow(), "target": target, "type": kind}

    # whois (registry query; privacy masking is common)
    run(case, ["whois", target], outfile=case.f("passive", "whois.txt"), timeout=30,
        note="registration")

    if kind == "ip":
        code, out, _ = run(case, ["dig", "+short", "-x", target],
                           outfile=case.f("passive", "ptr.txt"), timeout=30, quiet=True)
        summary["ptr"] = out.strip().splitlines()
        good(f"PTR: {out.strip() or '(none)'}")
        _shodan_note(case, target)
        case.save_json("passive_summary.json", summary)
        _passive_done(case, kind)
        return

    # ---- domain ----
    host = case.meta.get("host") or target
    dns = {}
    for rtype in DIG_RECORDS:
        dns[rtype] = _dig(case, target, rtype).splitlines()
    dns["CNAME@host"] = _dig(case, host, "CNAME").splitlines()
    dns["_dmarc TXT"] = _dig(case, "_dmarc." + target, "TXT").splitlines()
    summary["dns"] = dns
    for rtype, vals in dns.items():
        if vals:
            good(f"{rtype}: {', '.join(vals[:4])}" + (" ..." if len(vals) > 4 else ""))

    # third-party subdomain sources
    candidates = []
    candidates += _crtsh(target, case)
    candidates += [h for h in _wayback(target, case) if h.endswith(target)]
    if have("subfinder"):
        code, out, _ = run(case, ["subfinder", "-d", target, "-silent"],
                           outfile=case.f("passive", "subfinder.txt"), timeout=300)
        candidates += out.splitlines()
    else:
        warn("subfinder not installed; using crt.sh + wayback as native substitutes.")

    cleaned = _clean_subdomains(candidates, [target])
    with open(case.f("passive", "subdomains.txt"), "w") as f:
        f.write("\n".join(cleaned) + ("\n" if cleaned else ""))

    # resolve candidates (DNS is low-touch but not zero-touch; documented)
    resolved = {}
    info(f"Resolving {len(cleaned)} candidate names (A records)...")
    for name in cleaned:
        a = _dig(case, name, "A")
        ips = [x for x in a.splitlines() if classify_target(x) == "ip"]
        if ips:
            resolved[name] = ips
    with open(case.f("passive", "resolved.txt"), "w") as f:
        for name, ips in sorted(resolved.items()):
            f.write(f"{name} {' '.join(ips)}\n")

    summary["counts"] = {
        "candidates": len(cleaned),
        "resolved": len(resolved),
        "tested": 0,
    }
    summary["resolved"] = resolved
    _shodan_note(case, target)
    case.save_json("passive_summary.json", summary)

    good(f"Candidates: {len(cleaned)}   Currently resolving: {len(resolved)}   Tested: 0")
    _passive_done(case, kind)


def _shodan_note(case, target):
    note = {
        "shodan_key": bool(os.environ.get("SHODAN_API_KEY")),
        "manual_urls": {
            "shodan": f"https://www.shodan.io/search?query={target}",
            "censys": f"https://search.censys.io/search?resource=hosts&q={target}",
            "crtsh": f"https://crt.sh/?q=%25.{target}",
        },
    }
    with open(case.f("passive", "indexes.json"), "w") as f:
        json.dump(note, f, indent=2)
    info("Shodan/Censys: no API key wired in; manual search URLs saved to passive/indexes.json")


def _passive_done(case, kind):
    good("Passive phase complete. Next: `recon.py scope` to triage, then `recon.py active`.")


# ---------------------------------------------------------------------------
# harvest (theHarvester: emails / names / hosts from public sources)
# ---------------------------------------------------------------------------

EMAIL_RE = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")


def _harvest_native(domain, case, host):
    """Stdlib substitute for theHarvester: hosts from crt.sh, emails from the
    live site + wayback. OSINT only; no credential or search-engine scraping
    that would violate a provider's terms."""
    emails = set()
    hosts = set()

    # hosts: reuse CT logs (third-party index, already low-touch)
    for n in _clean_subdomains(_crtsh(domain, case), [domain]):
        hosts.add(n)

    # emails: fetch the site's own pages and scan for addresses.
    # This is TARGET traffic, so it is gated on authorization + scope.
    scrape_host = host.split(":")[0] if host else None
    may_scrape = bool(host) and case.scope.get("authorized") and case.in_scope(scrape_host)
    if host and not may_scrape:
        warn(f"Skipping site e-mail scrape of {scrape_host}: not authorized/in-scope. "
             "crt.sh hosts still collected (third-party index).")
    if may_scrape:
        for base in (f"https://{host}/", f"http://{host}/"):
            for path in ("", "contact", "about", "team", "contact-us"):
                url = base + path
                # follow=False so a redirect can't carry us to an out-of-scope host
                st, _, body, e = http_get(url, timeout=12, follow=False, insecure=True)
                case.log_cmd(["http_get", url], None, st or -1, note="harvest-scrape")
                if st and body:
                    for m in EMAIL_RE.findall(body.decode("utf-8", "replace")):
                        emails.add(m.lower())
            if emails:
                break

    # keep only emails on the target domain (others are leads, not confirmed)
    on_domain = sorted(e for e in emails if e.endswith("@" + domain) or e.endswith("." + domain))
    off_domain = sorted(e for e in emails if e not in on_domain)
    return {"source": "native", "hosts": sorted(hosts),
            "emails_on_domain": on_domain, "emails_other": off_domain}


def _harvest_binary(domain, case, sources="crtsh,bing,duckduckgo,otx"):
    out_prefix = case.f("passive", "theharvester")
    binname = "theHarvester" if have("theHarvester") else "theharvester"
    # -b sources can be slow/rate-limited; the set is configurable via --sources.
    # NOTE: theHarvester flags vary by version; verify with `theHarvester -h` on first run.
    run(case, [binname, "-d", domain, "-b", sources, "-f", out_prefix],
        outfile=case.f("passive", "theharvester.stdout.txt"), timeout=900, note="harvest")
    data = {"source": binname, "hosts": [], "emails_on_domain": [], "emails_other": []}
    jpath = out_prefix + ".json"
    if os.path.exists(jpath):
        try:
            with open(jpath) as f:
                j = json.load(f)
            data["hosts"] = sorted(set(j.get("hosts", []) or []))
            emails = [e.lower() for e in (j.get("emails", []) or [])]
            data["emails_on_domain"] = sorted(e for e in emails if e.endswith("@" + domain))
            data["emails_other"] = sorted(e for e in emails if not e.endswith("@" + domain))
        except Exception as e:  # noqa: BLE001
            warn(f"could not parse theHarvester JSON: {e}")
    return data


def cmd_harvest(args):
    case = resolve_case(args)
    if case.meta["type"] != "domain":
        err("harvest works on a domain target.")
        sys.exit(2)
    domain = case.meta["target"]
    host = case.meta.get("host") or domain
    info(f"OSINT harvest for {domain} - {utcnow()}")

    if (have("theHarvester") or have("theharvester")) and not args.native:
        data = _harvest_binary(domain, case, getattr(args, "sources", "crtsh,bing,duckduckgo,otx"))
    else:
        if not args.native:
            warn("theHarvester not installed; using native stdlib OSINT (crt.sh + site emails).")
        data = _harvest_native(domain, case, host)

    data["utc"] = utcnow()
    data["domain"] = domain
    case.save_json("harvest_summary.json", data)
    with open(case.f("passive", "emails.txt"), "w") as f:
        f.write("\n".join(data["emails_on_domain"] + data["emails_other"]) + "\n")

    good(f"Hosts: {len(data['hosts'])}   "
         f"Emails (on-domain): {len(data['emails_on_domain'])}   "
         f"Emails (other): {len(data['emails_other'])}")
    for e in data["emails_on_domain"][:20]:
        print(f"      {e}")
    if data["emails_on_domain"]:
        warn("Harvested addresses are a phishing / password-spray surface "
             "(note as OSINT exposure; do NOT attempt logins from recon).")
    good("Harvest saved to passive/harvest_summary.json + passive/emails.txt. "
         "Feeds `analyze` and `report`.")


# ---------------------------------------------------------------------------
# scope triage table
# ---------------------------------------------------------------------------

def cmd_scope(args):
    case = resolve_case(args)
    summ = case._load_json("passive_summary.json", {})
    rows = []
    if case.meta["type"] == "ip":
        # IP case: the IP itself is the candidate; PTR names are a clue, not scope.
        ip = case.meta["target"]
        ptr = ", ".join(summ.get("ptr", [])) or "(no PTR)"
        rows.append({"candidate": f"{ip}  (PTR: {ptr})", "ip": ip,
                     "in_scope": case.ip_in_scope(ip)})
    else:
        for name, ips in sorted(summ.get("resolved", {}).items()):
            display_ips = ips if isinstance(ips, list) else [ips]
            for ip in (display_ips or ["?"]):
                rows.append({
                    "candidate": name,
                    "ip": ip,
                    "in_scope": case.host_in_scope(name) or case.ip_in_scope(ip),
                })
    lines = ["| Candidate | Resolved IP | In scope? | Next action |",
             "| --- | --- | --- | --- |"]
    for r in rows:
        status = "YES" if r["in_scope"] else "PENDING - confirm scope first"
        nxt = "Active checks" if r["in_scope"] else "Do NOT touch until authorized"
        lines.append(f"| {r['candidate']} | {r['ip']} | {status} | {nxt} |")
    table = "\n".join(lines)
    with open(case.f("report", "scope-table.md"), "w") as f:
        f.write(f"# Scope triage - {utcnow()}\n\n{table}\n")
    print(table)
    print()
    if not case.scope.get("authorized"):
        warn("scope.json authorized=false. Active phases will refuse to run.")
    pend = [r["candidate"] for r in rows if not r["in_scope"]]
    if pend:
        warn(f"{len(pend)} candidate(s) are out of the current allowlist: {', '.join(pend[:8])}"
             + (" ..." if len(pend) > 8 else ""))
    good("Scope table written to report/scope-table.md")


# ---------------------------------------------------------------------------
# active (one approved host/ip at a time)
# ---------------------------------------------------------------------------

def _require_authorized(case, target):
    if not case.scope.get("authorized"):
        err("Active phase refused: scope.json \"authorized\" is false. "
            "Obtain written approval, then set it true (or re-run init --authorized).")
        sys.exit(3)
    if not case.in_scope(target):
        err(f"Active phase refused: {target} is not in the scope allowlist "
            f"(scope.json). Add it explicitly only if it is authorized.")
        sys.exit(3)


def _parse_nmap_open_ports(xml_path):
    ports = []
    try:
        tree = ET.parse(xml_path)
    except Exception:
        return ports
    for port in tree.getroot().iter("port"):
        state = port.find("state")
        if state is not None and state.get("state") == "open":
            svc = port.find("service")
            ports.append({
                "port": int(port.get("portid")),
                "proto": port.get("protocol"),
                "service": (svc.get("name") if svc is not None else "") or "",
                "product": (svc.get("product") if svc is not None else "") or "",
                "version": (svc.get("version") if svc is not None else "") or "",
            })
    return ports


def _parse_nmap_address(xml_path):
    """The actual IP nmap contacted (so the report can state it)."""
    try:
        tree = ET.parse(xml_path)
    except Exception:
        return ""
    for host in tree.getroot().iter("host"):
        for addr in host.iter("address"):
            if addr.get("addrtype") in ("ipv4", "ipv6"):
                return addr.get("addr", "")
    return ""


def cmd_active(args):
    case = resolve_case(args)
    target = args.target or case.meta.get("host") or case.meta["target"]
    _require_authorized(case, target)
    info(f"Active checks against approved target {target} - {utcnow()}")
    warn("These probes create connections and can be logged. One target at a time.")

    # per-target evidence dir so a second target never overwrites the first
    sub = os.path.join("active", safe_name(target))
    adir = case.d(sub)

    def af(name):
        return os.path.join(adir, name)

    # 1. reachability / top ports
    top = af("top100")
    first = ["nmap", "-n", "-sT", "--top-ports", "100", "--open"]
    if args.pn:
        first.append("-Pn")
        info("-Pn set: skipping host discovery (not stealth; treats host as up).")
    run(case, first + [target, "-oA", top],
        outfile=af("top100.stdout.txt"), timeout=900, note="first-pass")
    open_ports = _parse_nmap_open_ports(top + ".xml")
    address = _parse_nmap_address(top + ".xml")

    if args.all_ports:
        warn("Full TCP port scan (-p-) requested - this is broad and slow.")
        allt = af("all-tcp")
        run(case, ["nmap", "-n", "-sT", "-p-", "--open", target, "-oA", allt],
            outfile=af("all-tcp.stdout.txt"), timeout=3600, note="all-tcp-opt")
        open_ports = _parse_nmap_open_ports(allt + ".xml") or open_ports

    if not open_ports:
        warn("No open TCP ports parsed from first pass. "
             "Try `--pn` (skip discovery) if you know a host is up, or widen ports.")
    else:
        good(f"Open ports on {address or target}: "
             + ", ".join(f"{p['port']}/{p['proto']}" for p in open_ports))

    ports_csv = ",".join(str(p["port"]) for p in open_ports) or "22,80,443"

    # 2. service version + banners on found ports only
    if open_ports:
        run(case, ["nmap", "-n", "-Pn", "-sV", "--version-light", "-p", ports_csv, target,
                   "-oA", af("versions")],
            outfile=af("versions.stdout.txt"), timeout=900, note="version-light")
        run(case, ["nmap", "-n", "-Pn", "--script", "banner", "-p", ports_csv, target,
                   "-oA", af("banners")],
            outfile=af("banners.stdout.txt"), timeout=900, note="banner")
        open_ports = _parse_nmap_open_ports(af("versions.xml")) or open_ports

    # 3. HTTP/HTTPS/TLS. Contact the TARGET; use the case host only as the
    #    SNI/vhost name when the target is a bare IP.
    if classify_target(target) == "domain":
        web_host, web_ip = target, None
    else:
        web_host, web_ip = case.meta.get("host"), target
    if web_host:
        _web_checks(case, af, web_host, ip=web_ip)
    else:
        info("No hostname known for this IP; skipping HTTP/TLS-by-name checks "
             "(HTTPS uses SNI/vhost, so a bare IP may not reach the app).")

    if args.os_detect:
        warn("OS detection (-O) and UDP need raw sockets; running via sudo -n.")
        run(case, ["nmap", "-n", "-Pn", "-O", "-p", ports_csv, target, "-oA", af("os")],
            outfile=af("os.stdout.txt"), timeout=900, note="os-opt", use_sudo=True)
        run(case, ["nmap", "-n", "-sU", "-p", "53,123,161", target, "-oA", af("udp-selected")],
            outfile=af("udp.stdout.txt"), timeout=1200, note="udp-opt", use_sudo=True)

    doc = case._load_json("active_summary.json", {"targets": {}})
    doc.setdefault("targets", {})[target] = {
        "utc": utcnow(), "open_ports": open_ports, "address": address, "evdir": sub,
    }
    doc["utc"] = utcnow()
    case.save_json("active_summary.json", doc)
    good(f"Active phase complete. {len(open_ports)} open port(s) recorded in {sub}/. "
         "Next: `recon.py content --url ...` and `recon.py analyze`.")


def _web_checks(case, af, host, ip=None):
    base_https = f"https://{host}/"
    base_http = f"http://{host}/"
    run(case, ["curl", "-sSIk", "--max-time", "10", base_https],
        outfile=af("https-head.txt"), timeout=30, note="tls-head")
    run(case, ["curl", "-sSI", "--max-time", "10", base_http],
        outfile=af("http-head.txt"), timeout=30, note="http-head")
    run(case, ["curl", "-sS", "--max-time", "10", "-D", af("headers.txt"),
               "-o", os.devnull, base_https],
        outfile=af("https-get.txt"), timeout=30, note="https-get")
    if ip:
        run(case, ["curl", "-sSIk", "--resolve", f"{host}:443:{ip}", base_https],
            outfile=af("https-head-pinned.txt"), timeout=30, note="pinned-sni")
    # TLS certificate + verification result via openssl
    if have("openssl"):
        cert_out = af("tls-cert.txt")
        try:
            p1 = subprocess.run(
                ["openssl", "s_client", "-connect", f"{host}:443", "-servername", host],
                input="", capture_output=True, text=True, timeout=20)
            p2 = subprocess.run(
                ["openssl", "x509", "-noout", "-subject", "-issuer", "-dates"],
                input=p1.stdout, capture_output=True, text=True, timeout=20)
            verify = "\n".join(l for l in p1.stdout.splitlines()
                               if "Verify return code" in l or "verify error" in l)
            with open(cert_out, "w") as f:
                f.write((p2.stdout or p2.stderr) + ("\n" + verify if verify else ""))
            case.log_cmd(["openssl", "s_client", "-connect", f"{host}:443", "|",
                          "openssl", "x509", "-subject", "-issuer", "-dates"], cert_out,
                         p2.returncode, note="tls-cert")
            if p2.stdout.strip():
                good("TLS cert: " + p2.stdout.strip().replace("\n", " | "))
        except Exception as e:  # noqa: BLE001
            warn(f"openssl cert check failed: {e}")


# ---------------------------------------------------------------------------
# content / directory discovery  (native ffuf/gobuster replacement)
# ---------------------------------------------------------------------------

BUILTIN_WORDS = [
    "admin", "administrator", "login", "wp-admin", "wp-login.php", "user", "users",
    "dashboard", "config", "config.php", "configuration", "setup", "install",
    "backup", "backups", "backup.zip", "backup.tar.gz", "db.sql", "dump.sql",
    ".git/HEAD", ".git/config", ".svn/entries", ".env", ".env.bak", ".DS_Store",
    "server-status", "server-info", "phpinfo.php", "info.php", "test.php",
    "robots.txt", "sitemap.xml", ".well-known/security.txt", "crossdomain.xml",
    "api", "api/v1", "swagger", "swagger.json", "openapi.json", "graphql",
    "actuator", "actuator/health", "actuator/env", "metrics",
    "uploads", "upload", "files", "tmp", "temp", "old", "bak", "dev", "staging",
    "console", "manager", "manager/html", "jenkins", "phpmyadmin", "pma",
    "cgi-bin", "cgi-bin/test.cgi", "web.config", "WEB-INF/web.xml", ".htaccess",
    "readme.txt", "README.md", "CHANGELOG", "license.txt", "VERSION",
]

SECLISTS_CANDIDATES = [
    "/usr/share/seclists/Discovery/Web-Content/common.txt",
    "/usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt",
    "/usr/share/wordlists/dirb/common.txt",
    "/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt",
]


def _load_wordlist(path):
    if path:
        with open(path, errors="replace") as f:
            return [w.strip().lstrip("/") for w in f if w.strip() and not w.startswith("#")]
    for cand in SECLISTS_CANDIDATES:
        if os.path.exists(cand):
            info(f"Using wordlist: {cand}")
            with open(cand, errors="replace") as f:
                return [w.strip().lstrip("/") for w in f if w.strip() and not w.startswith("#")]
    info("No SecLists/dirb wordlist found; using built-in high-value path list.")
    return list(BUILTIN_WORDS)


def _rand_path():
    return "".join(random.choices(string.ascii_lowercase + string.digits, k=18))


def _store_content_run(case, base, mode, findings, extra=None):
    """Accumulate runs keyed by base URL so multiple vhosts/ports don't clobber."""
    doc = case._load_json("content_summary.json", {"runs": []})
    # key by (base, mode) so an ffuf run doesn't clobber a native/gobuster run on the same URL
    runs = [r for r in doc.get("runs", []) if not (r.get("base") == base and r.get("mode") == mode)]
    runs.append({"utc": utcnow(), "base": base, "mode": mode,
                 "count": len(findings), "findings": findings, **(extra or {})})
    doc["runs"] = runs
    doc["utc"] = utcnow()
    case.save_json("content_summary.json", doc)
    # rewrite the combined human-readable file from ALL runs
    with open(case.f("content", "dirscan.txt"), "w") as f:
        for r in runs:
            f.write(f"# {r['base']}  ({r['mode']}, {r['count']} hits)\n")
            for h in r["findings"]:
                f.write(f"{h['status']:>3}  {h['length']:>8}  /{h['path']}"
                        + (f"  -> {h['location']}" if h.get("location") else "") + "\n")
            f.write("\n")
    case.log_cmd([mode + "-fuzzer", base], case.f("content", "dirscan.txt"), 0, note="content")


def _print_content(findings):
    if findings:
        good(f"{len(findings)} interesting path(s):")
        for r in findings[:40]:
            print(f"      {r['status']}  /{r['path']}"
                  + (f"  -> {r['location']}" if r.get('location') else ""))
        if len(findings) > 40:
            print(f"      ... and {len(findings) - 40} more (see content/dirscan.txt)")
    else:
        info("No paths stood out against the baseline.")


def cmd_content(args):
    case = resolve_case(args)
    base = args.url.rstrip("/") + "/"
    host = re.sub(r"^https?://", "", base).split("/")[0].split(":")[0]
    _require_authorized(case, host)

    # external-tool path (declared untested here, since neither binary is installed)
    if args.engine in ("ffuf", "gobuster") and have(args.engine):
        _content_external(case, base, args)
        return
    if args.engine in ("ffuf", "gobuster"):
        warn(f"{args.engine} not installed; falling back to the native fuzzer.")

    words = _load_wordlist(args.wordlist)
    _run_native_content(case, base, words, args.threads, args.delay, args.timeout, args.ext)
    good("Content phase complete. Next: `recon.py analyze`.")


def _run_native_content(case, base, words, threads=10, delay=0.0, timeout=8.0, ext=None):
    exts = [e if e.startswith(".") else "." + e for e in (ext.split(",") if ext else [])]
    paths, seen = [], set()
    for w in words:
        for cand in [w] + [w + e for e in exts if not w.endswith(e)]:
            if cand not in seen:
                seen.add(cand)
                paths.append(cand)

    # ---- soft-404 calibration: baseline SIGNATURES (status, length, location) ----
    # Handles a 200 catch-all, "redirect everything to /login", and "403 for all".
    # Also calibrate per-extension and a trailing slash, since a PHP front
    # controller can 200 every *.php even when the root path 404s.
    info("Calibrating against random paths (soft-404 / catch-all detection)...")
    baseline = []  # (status, length, location_normalized)
    cal_suffixes = [""] + exts + ["/"]
    for suf in cal_suffixes:
        tok = _rand_path() + suf
        st, headers, body, e = http_get(base + tok, timeout=timeout, follow=False, insecure=True)
        if st is not None:
            loc = headers.get("Location", "").replace(tok, "RAND")
            baseline.append((st, len(body), loc))
    bstatuses = sorted({b[0] for b in baseline})
    if baseline and all(b[0] in (301, 302, 307, 308) for b in baseline):
        warn(f"Server redirects ALL unknown paths ({bstatuses}); filtering that signature.")
    elif baseline and all(b[0] == 403 for b in baseline):
        warn("Server returns 403 for ALL unknown paths; filtering that signature.")
    elif baseline and all(b[0] == 200 for b in baseline):
        warn("Server returns 200 for ALL unknown paths (catch-all); filtering that signature.")
    elif baseline:
        info(f"Baseline statuses for missing paths: {bstatuses}")

    def matches_baseline(st, blen, loc_norm):
        for bs, bl, bloc in baseline:
            if st == bs and abs(blen - bl) <= 32 and loc_norm == bloc:
                return True
        return False

    interesting_codes = (200, 204, 301, 302, 307, 308, 401, 403, 405, 500, 503)
    findings = []
    lock = __import__("threading").Lock()

    def probe(p):
        url = base + p
        st, headers, body, e = http_get(url, timeout=timeout, follow=False, insecure=True)
        if delay:
            import time
            time.sleep(delay)
        if st is None or st not in interesting_codes:
            return
        blen = len(body)
        loc = headers.get("Location", "")
        loc_norm = loc.replace(p, "RAND")
        if matches_baseline(st, blen, loc_norm):
            return
        with lock:
            findings.append({
                "path": p, "url": url, "status": st, "length": blen,
                "location": loc, "server": headers.get("Server", ""),
            })

    info(f"Fuzzing {len(paths)} paths with {threads} threads (no redirect following)...")
    with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as ex:
        list(ex.map(probe, paths))

    findings.sort(key=lambda f: (f["status"], f["path"]))
    _store_content_run(case, base, "native", findings, {"baseline": baseline, "words": len(paths)})
    _print_content(findings)
    return findings


def _content_external(case, base, args):
    wl = args.wordlist
    if not wl:
        for c in SECLISTS_CANDIDATES:
            if os.path.exists(c):
                wl = c
                break
    if not wl:
        # no SecLists on this box: materialize the built-in list to a file so
        # ffuf/gobuster (which require -w) still have something to run with.
        wl = case.f("content", "builtin-wordlist.txt")
        with open(wl, "w") as f:
            f.write("\n".join(BUILTIN_WORDS) + "\n")
        info(f"No SecLists found; wrote built-in list to {wl}")
    findings = []
    if args.engine == "ffuf":
        out = case.f("content", "ffuf.json")
        code, _, _ = run(case, ["ffuf", "-u", base + "FUZZ", "-w", wl, "-t", str(args.threads), "-ac",
                   "-mc", "200,204,301,302,307,401,403,500", "-of", "json", "-o", out],
            outfile=case.f("content", "ffuf.stdout.txt"), timeout=1800, note="ffuf")
        if code != 0:
            warn(f"ffuf exited {code}; results may be incomplete (see content/ffuf.stdout.txt).")
        if os.path.exists(out):
            try:
                with open(out) as f:
                    j = json.load(f)
                for r in j.get("results", []):
                    path = (r.get("input", {}) or {}).get("FUZZ", "")
                    findings.append({
                        "path": path, "url": r.get("url", base + path),
                        "status": r.get("status", 0), "length": r.get("length", 0),
                        "location": r.get("redirectlocation", ""), "server": "",
                    })
            except Exception as e:  # noqa: BLE001
                warn(f"could not parse ffuf JSON: {e}")
    else:
        gout = case.f("content", "gobuster.txt")
        code, _, _ = run(case, ["gobuster", "dir", "-u", base, "-w", wl, "-t", str(args.threads), "-q",
                   "-o", gout],
            outfile=case.f("content", "gobuster.stdout.txt"), timeout=1800, note="gobuster")
        if code != 0:
            warn(f"gobuster exited {code} (often a wildcard/catch-all server); "
                 "results may be incomplete. Try the native engine, which calibrates for that.")
        if os.path.exists(gout):
            with open(gout, errors="replace") as f:
                for line in f:
                    m = re.match(r"\s*/?(\S+)\s+\(Status:\s*(\d+)\)\s*\[Size:\s*(\d+)\]", line)
                    if m:
                        findings.append({
                            "path": m.group(1).lstrip("/"), "url": base + m.group(1).lstrip("/"),
                            "status": int(m.group(2)), "length": int(m.group(3)),
                            "location": "", "server": "",
                        })
    findings.sort(key=lambda f: (f["status"], f["path"]))
    _store_content_run(case, base, args.engine, findings)
    _print_content(findings)
    good("External content scan complete; results folded into analyze/report.")


# ---------------------------------------------------------------------------
# internal network discovery (second cheat sheet)
# ---------------------------------------------------------------------------

INTERNAL_ROLES = {
    "linux": [22, 80, 443],
    "web": [80, 443, 8080, 8443],
    "windows": [135, 139, 445, 3389, 5985],
    "dc": [53, 88, 389, 445, 636, 3268],
    "db": [1433, 3306, 5432, 6379],
}


def cmd_internal(args):
    case = resolve_case(args) if (getattr(args, "case", None) or os.path.exists(CURRENT_PTR)) else None
    if case is None:
        # internal mode can run standalone; make an ad-hoc case
        case_dir = os.path.join(RECON_ROOT, "internal", utcstamp())
        os.makedirs(case_dir, exist_ok=True)
        case = Case(case_dir)
        case.meta = {"target": "internal", "type": "internal", "created_utc": utcnow()}
        case.save_json("case.json", case.meta)
        with open(CURRENT_PTR, "w") as f:
            f.write(case.path)
        info(f"Standalone internal case: {case.path}")

    info(f"Internal discovery - {utcnow()}")
    info("Section 1: local clues (LOCAL - reads this host only)")
    local_cmds = [
        (["hostname", "-f"], "hostname.txt"),
        (["ip", "-br", "addr"], "ip-addr.txt"),
        (["ip", "route"], "ip-route.txt"),
        (["ip", "neigh"], "ip-neigh.txt"),
        (["resolvectl", "status"], "resolvectl.txt"),
        (["cat", "/etc/hosts"], "etc-hosts.txt"),
        (["ss", "-tnp"], "ss-established.txt"),
        (["ss", "-lntp"], "ss-listening.txt"),
    ]
    for argv, name in local_cmds:
        code, out, _ = run(case, argv, outfile=case.f("internal", name), timeout=30, quiet=True)
        if out.strip():
            print(_color(f"  --- {' '.join(argv)} ---", C_DIM))
            print("  " + out.strip().replace("\n", "\n  "))

    if args.ip and args.role:
        _require_internal_probe_ok(args)
        ports = INTERNAL_ROLES.get(args.role, INTERNAL_ROLES["linux"])
        ports_csv = ",".join(str(p) for p in ports)
        info(f"Section 3/6: role '{args.role}' first-pass TCP check on {args.ip} (PROBE)")
        run(case, ["nmap", "-Pn", "-n", "-sT", "--reason", "-p", ports_csv, args.ip,
                   "-oN", case.f("internal", f"nmap-{safe_name(args.ip)}.txt")],
            outfile=case.f("internal", f"nmap-{safe_name(args.ip)}.stdout.txt"),
            timeout=600, note="internal-probe")
        run(case, ["nmap", "-Pn", "-n", "-sT", "-sV", "--version-light", "-p", ports_csv, args.ip,
                   "-oN", case.f("internal", f"nmap-ver-{safe_name(args.ip)}.txt")],
            outfile=case.f("internal", f"nmap-ver-{safe_name(args.ip)}.stdout.txt"),
            timeout=600, note="internal-version")

    if args.domain and args.dns:
        info("Section 2: AD domain controller SRV lookup (DNS)")
        run(case, ["dig", f"@{args.dns}", f"_ldap._tcp.dc._msdcs.{args.domain}", "SRV", "+short"],
            outfile=case.f("internal", "dc-srv.txt"), timeout=30)

    if args.sweep:
        _require_internal_probe_ok(args)
        warn(f"Subnet sweep requested for {args.sweep}. Listing exact targets first (LOCAL).")
        code, out, _ = run(case, ["nmap", "-sL", "-n", args.sweep],
                           outfile=case.f("internal", "sweep-targets.txt"), timeout=60)
        n = len(re.findall(r"Nmap scan report", out))
        warn(f"Sweep would touch ~{n} host(s). Discovery only (-sn), never -Pn on a CIDR.")
        if args.confirm_sweep:
            run(case, ["nmap", "-sn", "-n", args.sweep],
                outfile=case.f("internal", "sweep-live.txt"), timeout=1800, note="sweep")
        else:
            warn("Re-run with --confirm-sweep to actually run `nmap -sn` on the range.")

    good(f"Internal discovery written to {case.d('internal')}")


def _require_internal_probe_ok(args):
    if not args.authorized:
        err("Internal PROBE/SWEEP refused: pass --authorized once the target(s) are "
            "confirmed in scope for this foothold.")
        sys.exit(3)


# ---------------------------------------------------------------------------
# analyze -> ranked leads
# ---------------------------------------------------------------------------

RISKY_PORTS = {
    21: ("FTP", "Cleartext auth; check for anonymous login and known FTPd CVEs.", "high"),
    23: ("Telnet", "Cleartext remote admin; should not be exposed.", "high"),
    445: ("SMB", "SMB exposed; enumerate shares/signing, check for known SMB CVEs.", "high"),
    3389: ("RDP", "RDP exposed; check NLA and known RDP CVEs (RCE-adjacent).", "high"),
    135: ("MSRPC", "Windows RPC exposed to the probe source.", "medium"),
    139: ("NetBIOS", "Legacy SMB/NetBIOS exposed.", "medium"),
    1433: ("MSSQL", "Database port reachable; should be network-restricted.", "high"),
    3306: ("MySQL", "Database port reachable; should be network-restricted.", "high"),
    5432: ("PostgreSQL", "Database port reachable; should be network-restricted.", "high"),
    6379: ("Redis", "Redis often unauthenticated -> RCE-adjacent; verify AUTH/bind.", "high"),
    27017: ("MongoDB", "Database port reachable; check auth.", "high"),
    5900: ("VNC", "Remote desktop; check auth strength.", "high"),
}

SEVERITY_RANK = {"high": 0, "medium": 1, "low": 2, "info": 3}


def _lead(title, severity, confidence, evidence, repro, nxt, rce=False):
    return {"title": title, "severity": severity, "confidence": confidence,
            "evidence": evidence, "repro": repro, "next": nxt, "rce_adjacent": rce}


def _read(case, sub, name):
    p = case.f(sub, name)
    if os.path.exists(p):
        with open(p, errors="replace") as f:
            return f.read()
    return ""


def _readp(case, rel):
    """Read a file by its path relative to the case root (e.g. 'active/<t>/headers.txt')."""
    p = os.path.join(case.path, rel)
    if os.path.exists(p):
        with open(p, errors="replace") as f:
            return f.read()
    return ""


def cmd_analyze(args):
    case = resolve_case(args)
    leads = []
    target = case.meta.get("host") or case.meta.get("target", "")

    passive = case._load_json("passive_summary.json", {})
    active = case._load_json("active_summary.json", {})
    content = case._load_json("content_summary.json", {})
    content_findings = []
    for r in content.get("runs", []):
        content_findings += r.get("findings", [])

    # --- DNS / mail auth hygiene ---
    dns = passive.get("dns", {})
    txt = " ".join(dns.get("TXT", [])).lower()
    dmarc = " ".join(dns.get("_dmarc TXT", [])).lower()
    # Only trust "record is absent" if DNS actually answered something, otherwise
    # a SERVFAIL/timeout would manufacture false high-confidence findings.
    dns_ok = any(dns.get(k) for k in ("A", "AAAA", "NS", "SOA", "MX"))
    if dns and not dns_ok:
        warn("DNS lookups returned nothing (resolver failure?); "
             "suppressing absence-based SPF/DMARC/CAA leads.")
    if dns_ok:
        if "v=spf1" not in txt:
            leads.append(_lead("No SPF record", "medium", "high", "passive/dns_TXT_*.txt",
                               f"dig +short TXT {case.meta['target']}",
                               "Publish an SPF record to limit mail spoofing."))
        if not dmarc:
            leads.append(_lead("No DMARC record", "medium", "high", "passive/dns__dmarc*",
                               f"dig +short TXT _dmarc.{case.meta['target']}",
                               "Publish a DMARC policy (start p=none for monitoring, then enforce)."))
        elif "p=none" in dmarc:
            leads.append(_lead("DMARC policy is p=none (monitor only)", "low", "high",
                               "passive/dns__dmarc*",
                               f"dig +short TXT _dmarc.{case.meta['target']}",
                               "Move to p=quarantine/reject once monitoring is clean."))
        if not dns.get("CAA"):
            leads.append(_lead("No CAA record", "low", "medium", "passive/dns_CAA_*",
                               f"dig +short CAA {case.meta['target']}",
                               "Add CAA to restrict which CAs may issue certs."))

    # --- subdomain takeover candidate: CNAME to 3rd party ---
    cname = " ".join(dns.get("CNAME@host", []))
    if cname and any(s in cname for s in ("github.io", "herokuapp", "azurewebsites",
                                          "cloudfront", "s3-website", "amazonaws",
                                          "pages.dev", "netlify", "fastly")):
        leads.append(_lead("CNAME to third-party service (takeover worth checking)",
                           "medium", "low", "passive/dns_CNAME_*",
                           f"dig CNAME {target}; then confirm the target resource still exists",
                           "Verify the referenced resource is claimed; dangling CNAME => takeover.",
                           rce=False))

    # --- active findings, per target (evidence lives under each target's dir) ---
    for tgt, tinfo in active.get("targets", {}).items():
        ev = tinfo.get("evdir", "active")
        for p in tinfo.get("open_ports", []):
            pn = p["port"]
            if pn in RISKY_PORTS:
                label, why, sev = RISKY_PORTS[pn]
                leads.append(_lead(f"Exposed {label} ({pn}/{p['proto']}) on {tgt}", sev, "high",
                                   f"{ev}/top100.nmap", f"nmap -n -Pn -sV -p {pn} {tgt}",
                                   why, rce=(sev == "high" and pn in (3389, 6379, 445, 5900))))
            if p.get("product") or p.get("version"):
                vs = (p["product"] + " " + p["version"]).strip()
                hint = f"  (try: searchsploit {p['product']} {p['version']})" if have("searchsploit") else ""
                leads.append(_lead(f"Service version disclosed on {tgt}:{pn}: {vs}",
                                   "low", "medium", f"{ev}/versions.nmap",
                                   f"nmap -n -Pn -sV -p {pn} {tgt}",
                                   "POSSIBLE / NEEDS VALIDATION: match the exact build against the "
                                   "vendor advisory; a banner alone is not a vulnerability." + hint))

        # HTTP headers / TLS for this target
        headers = _readp(case, f"{ev}/headers.txt") + _readp(case, f"{ev}/https-head.txt")
        if headers:
            hl = headers.lower()
            m = re.search(r"server:\s*(.+)", headers, re.I)
            if m and re.search(r"\d", m.group(1)):
                leads.append(_lead(f"Server header leaks version on {tgt}: {m.group(1).strip()}",
                                   "low", "medium", f"{ev}/headers.txt",
                                   f"curl -sSIk https://{tgt}/",
                                   "POSSIBLE / NEEDS VALIDATION: confirm exact build vs advisory; "
                                   "suppress version banners."))
            xp = re.search(r"x-powered-by:\s*(.+)", headers, re.I)
            if xp:
                leads.append(_lead(f"X-Powered-By disclosure on {tgt}: {xp.group(1).strip()}",
                                   "low", "medium", f"{ev}/headers.txt",
                                   f"curl -sSIk https://{tgt}/",
                                   "Remove X-Powered-By; confirm framework version separately."))
            missing = [h for h in ("strict-transport-security", "content-security-policy",
                                   "x-frame-options", "x-content-type-options") if h not in hl]
            if missing:
                leads.append(_lead(f"Missing security headers on {tgt}: " + ", ".join(missing),
                                   "low", "high", f"{ev}/headers.txt",
                                   f"curl -sSIk https://{tgt}/",
                                   "Add HSTS, CSP, X-Frame-Options, X-Content-Type-Options as applicable."))

        http_head = _readp(case, f"{ev}/http-head.txt")
        if http_head and "200" in http_head.split("\n")[0] and "location:" not in http_head.lower():
            leads.append(_lead(f"HTTP served without redirect to HTTPS on {tgt}", "low", "medium",
                               f"{ev}/http-head.txt", f"curl -sSI http://{tgt}/",
                               "Redirect all HTTP to HTTPS (301) and set HSTS."))

        cert = _readp(case, f"{ev}/tls-cert.txt")
        if cert:
            subj = re.search(r"subject=(.+)", cert)
            issu = re.search(r"issuer=(.+)", cert)
            vcode = re.search(r"Verify return code:\s*(\d+)", cert)
            self_signed = (subj and issu and subj.group(1).strip() == issu.group(1).strip()) \
                or (vcode and vcode.group(1) in ("18", "19"))
            if self_signed:
                leads.append(_lead(f"Self-signed / untrusted TLS certificate on {tgt}",
                                   "medium", "medium", f"{ev}/tls-cert.txt",
                                   f"openssl s_client -connect {tgt}:443 -servername {tgt}",
                                   "Install a CA-trusted certificate."))
            mnot = re.search(r"notAfter=(.+)", cert)
            if mnot:
                try:
                    exp = datetime.datetime.strptime(mnot.group(1).strip(), "%b %d %H:%M:%S %Y %Z")
                    now_naive = datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None)
                    if exp < now_naive or (vcode and vcode.group(1) == "10"):
                        leads.append(_lead(f"TLS certificate expired on {tgt} ({mnot.group(1).strip()})",
                                           "medium", "high", f"{ev}/tls-cert.txt",
                                           f"openssl s_client -connect {tgt}:443",
                                           "Renew the certificate."))
                except Exception:
                    pass

    # --- content findings ---
    HIGH_PATHS = {
        ".git/HEAD": ("Exposed .git repository", "high", True),
        ".git/config": ("Exposed .git repository", "high", True),
        ".env": ("Exposed .env (likely secrets/credentials)", "high", True),
        ".env.bak": ("Exposed .env backup", "high", True),
        "server-status": ("Apache server-status exposed", "medium", False),
        "phpinfo.php": ("phpinfo() exposed (info disclosure)", "medium", False),
        "info.php": ("phpinfo() exposed (info disclosure)", "medium", False),
        ".DS_Store": (".DS_Store exposed (path disclosure)", "low", False),
        "actuator/env": ("Spring actuator/env exposed (secrets)", "high", True),
        "web.config": ("web.config exposed", "medium", False),
    }
    for r in content_findings:
        path = r["path"]
        if r.get("status") in (200,):
            for key, (title, sev, rce) in HIGH_PATHS.items():
                if path == key or path.startswith(key):
                    leads.append(_lead(f"{title}  (/{path})", sev, "medium",
                                       "content/dirscan.txt", f"curl -sSi {r['url']}",
                                       "Validate contents; restrict/remove the exposed resource.",
                                       rce=rce))
                    break
            else:
                if re.search(r"backup|\.zip$|\.tar|\.sql$|dump", path):
                    leads.append(_lead(f"Possible backup/dump exposed (/{path})", "high", "low",
                                       "content/dirscan.txt", f"curl -sSi {r['url']}",
                                       "Confirm it is a real backup, then remove it.", rce=False))
        if r.get("status") in (401, 403) and re.search(r"admin|manager|console|jenkins|phpmyadmin", path):
            leads.append(_lead(f"Protected admin surface found (/{path}) [{r['status']}]",
                               "info", "medium", "content/dirscan.txt", f"curl -sSi {r['url']}",
                               "Admin panel exists; note it as attack surface (do not brute-force)."))

    # --- harvested OSINT (theHarvester / native) ---
    harvest = case._load_json("harvest_summary.json", {})
    on_dom = harvest.get("emails_on_domain", [])
    if on_dom:
        leads.append(_lead(f"{len(on_dom)} corporate email address(es) exposed via OSINT",
                           "info", "high", "passive/emails.txt",
                           f"recon.py harvest  (source: {harvest.get('source','native')})",
                           "Phishing / password-spray surface. Note the naming scheme; "
                           "do not attempt authentication during recon."))

    # rank: RCE-adjacent first, then severity, then confidence
    conf_rank = {"high": 0, "medium": 1, "low": 2}
    leads.sort(key=lambda l: (not l["rce_adjacent"], SEVERITY_RANK.get(l["severity"], 9),
                              conf_rank.get(l["confidence"], 9)))
    case.save_json("leads.json", {"utc": utcnow(), "target": target, "leads": leads})

    if not leads:
        info("No leads surfaced yet. Run passive/active/content first, or results were clean.")
    else:
        good(f"{len(leads)} lead(s) - ranked (high-impact and high severity first):\n")
        for i, l in enumerate(leads, 1):
            tag = _color("[HIGH-IMPACT]", C_RED) + " " if l["rce_adjacent"] else ""
            sev = {"high": C_RED, "medium": C_YEL, "low": C_GRN, "info": C_CYN}.get(l["severity"], C_RST)
            print(f"{i:>2}. {tag}{_color(l['severity'].upper(), sev)} "
                  f"(confidence {l['confidence']}) - {l['title']}")
            print(f"    evidence : {l['evidence']}")
            print(f"    repro    : {l['repro']}")
            print(f"    next     : {l['next']}\n")

    # Highlight THE lead to elaborate on
    if leads:
        top = leads[0]
        print(_color("==> PRIMARY POINT TO ELABORATE IN THE REPORT:", C_RED))
        print(f"    {top['title']}  [{top['severity']} / confidence {top['confidence']}]")
        print(f"    Start here: {top['next']}")
    good("Leads saved to leads.json. Next: `recon.py report`.")


# ---------------------------------------------------------------------------
# report (section 8 template + leads)
# ---------------------------------------------------------------------------

REPORT_TMPL = """# Recon note - {target}

- UTC date / tester / source IP: {utc} / <tester> / <source-ip>
- Scope and authorization: {authorized}
- Target-to-IP mapping at test time: {mapping}
- Shared infrastructure / CDN / third-party boundaries: <describe edge vs origin>

## Passive findings
| Question | Finding | Method/source | Observed at | Confidence |
| --- | --- | --- | --- | --- |
| Hostnames / IPs | {hostcount} candidates, {resolvedcount} resolving | crt.sh + wayback + dig | {utc} | medium |
| DNS / ownership / ASN | {dnsline} | dig + whois | {utc} | medium |
| History / technology clues | see passive/ | wayback / headers | {utc} | low |
| OSINT emails / names | {emailcount} on-domain address(es) | theHarvester/native | {utc} | medium |

## Active findings
| IP / hostname | Port / protocol | State | Service / version | Method | Evidence file |
| --- | --- | --- | --- | --- | --- |
{portrows}

OS: {osline}
Possible issue: {primary}
Recommended follow-up / remediation: {remediation}
Limits: {limits}
Summary: {summary}

## Leads to elaborate (ranked)
{leadblock}

---
Generated by reconkit {utc}. Every command is logged in evidence/commands.log.
A version/banner match is "possible / needs validation" until the exact build and
conditions are confirmed against the vendor advisory. No exploit checks were run.
"""


def cmd_report(args):
    case = resolve_case(args)
    passive = case._load_json("passive_summary.json", {})
    active = case._load_json("active_summary.json", {})
    harvest = case._load_json("harvest_summary.json", {})
    leads_doc = case._load_json("leads.json", {})
    leads = leads_doc.get("leads", [])
    target = case.meta.get("host") or case.meta.get("target", "")

    counts = passive.get("counts", {})
    dns = passive.get("dns", {})
    dnsline = "; ".join(f"{k}={','.join(v[:2])}" for k, v in dns.items() if v)[:200] or "n/a"

    atargets = active.get("targets", {})
    note_targets = list(atargets.keys()) or [target]

    # classify each lead to a target (by evidence dir or title mention); the rest
    # are "global" (DNS/OSINT/content) and appear in every target's note.
    def lead_target(l):
        for t in note_targets:
            ev = (atargets.get(t, {}) or {}).get("evdir", "")
            if (ev and str(l.get("evidence", "")).startswith(ev)) or (t and t in l.get("title", "")):
                return t
        return None

    common_limits = []
    if not atargets:
        common_limits.append("no active phase run")
    if not case._load_json("content_summary.json", {}).get("runs"):
        common_limits.append("no content/dir discovery run")
    if not have("subfinder"):
        common_limits.append("subfinder absent (crt.sh/wayback only)")
    common_limits.append("CDN/WAF may hide the origin; IPv6/UDP not covered unless flagged")

    written = []
    for tgt in note_targets:
        tinfo = atargets.get(tgt, {})
        address = tinfo.get("address", "")
        ev = tinfo.get("evdir", "active")
        mapping = (f"{tgt} -> {address}" if address
                   else ", ".join(f"{k}->{','.join(v if isinstance(v,list) else [v])}"
                                   for k, v in list(passive.get("resolved", {}).items())[:6]) or tgt)

        portrows, total_ports = "", 0
        for p in tinfo.get("open_ports", []):
            total_ports += 1
            vs = (p.get("product", "") + " " + p.get("version", "")).strip() or p.get("service", "")
            portrows += (f"| {tgt} | {p['port']}/{p['proto']} | open | "
                         f"{vs} | nmap -sV | {ev}/versions.nmap |\n")
        if not portrows:
            portrows = "| | | | | | |\n"

        os_line = "not determined"
        if os.path.exists(os.path.join(case.path, ev, "os.nmap")):
            os_line = f"see {ev}/os.nmap (guess only; corroborate before claiming)"

        tleads = [l for l in leads if lead_target(l) in (tgt, None)]
        primary, remediation = "none confirmed", "See per-lead remediation below."
        if tleads:
            t0 = tleads[0]
            primary = (f"{t0['title']} - {t0['severity'].upper()} / confidence {t0['confidence']} "
                       f"(POSSIBLE / NEEDS VALIDATION). Evidence: {t0['evidence']}.")
            remediation = t0["next"]

        leadblock = ""
        for i, l in enumerate(tleads, 1):
            rce = " [high-impact]" if l.get("rce_adjacent") else ""
            leadblock += (f"{i}. **{l['title']}**{rce} - {l['severity'].upper()} "
                          f"(confidence {l['confidence']})\n"
                          f"   - Evidence: `{l['evidence']}`\n"
                          f"   - Reproduce: `{l['repro']}`\n"
                          f"   - Next / fix: {l['next']}\n")
        if not leadblock:
            leadblock = "_No leads surfaced. Re-run analyze after active/content phases._\n"

        text = REPORT_TMPL.format(
            target=tgt, utc=utcnow(),
            authorized=("confirmed" if case.scope.get("authorized") else "NOT confirmed"),
            mapping=mapping,
            hostcount=counts.get("candidates", 0), resolvedcount=counts.get("resolved", 0),
            emailcount=len(harvest.get("emails_on_domain", [])),
            dnsline=dnsline, portrows=portrows.rstrip(), osline=os_line,
            primary=primary, remediation=remediation,
            limits="; ".join(common_limits),
            summary=(f"Recon of {tgt}: {counts.get('resolved',0)} resolving names, "
                     f"{total_ports} open port(s), {len(tleads)} lead(s). "
                     f"Top item to validate: {tleads[0]['title'] if tleads else 'none'}."),
            leadblock=leadblock.rstrip(),
        )
        out = case.f("report", f"recon-note-{safe_name(tgt)}.md")
        with open(out, "w") as f:
            f.write(text)
        written.append(out)

    good(f"Report note(s) written: {', '.join(os.path.relpath(w, case.path) for w in written)}")
    print()
    print(_readp(case, os.path.relpath(written[0], case.path)))


# ---------------------------------------------------------------------------
# all (chain)
# ---------------------------------------------------------------------------

def cmd_all(args):
    # init
    cmd_init(args)
    args.case = None  # use .current
    cmd_passive(args)
    args.native = getattr(args, "native", False)
    if resolve_case(args).meta.get("type") == "domain":
        cmd_harvest(args)
    cmd_scope(args)
    case = resolve_case(args)
    if not case.scope.get("authorized"):
        warn("Stopping before active phases: scope.json authorized=false. "
             "Set it true (with written approval) and run `active`/`content`/`analyze`/`report`.")
        return
    args.target = None
    try:
        cmd_active(args)
    except SystemExit:
        pass
    # content discovery on each open web port of the scanned target (the core
    # "find a vulnerable point" step), through the same authorization gate.
    active = case._load_json("active_summary.json", {})
    words = _load_wordlist(None)
    for tgt, tinfo in active.get("targets", {}).items():
        web_host = tgt if classify_target(tgt) == "domain" else (case.meta.get("host") or tgt)
        for p in tinfo.get("open_ports", []):
            svc = (p.get("service", "") or "").lower()
            pn = p["port"]
            if pn in (80, 8080, 8000) or svc == "http":
                _run_native_content(case, f"http://{web_host}:{pn}/".replace(":80/", "/"), words)
            elif pn in (443, 8443) or "https" in svc or "ssl" in svc:
                _run_native_content(case, f"https://{web_host}:{pn}/".replace(":443/", "/"), words)
    cmd_analyze(args)
    cmd_report(args)


# ---------------------------------------------------------------------------
# interactive shell
# ---------------------------------------------------------------------------

# commands exposed at the interactive prompt (name -> one-line hint).
SHELL_COMMANDS = {
    "init":     "init <target> [--host H] [--scope-* ...] [--authorized]  create a case",
    "passive":  "passive discovery (crt.sh, wayback, dig, whois)",
    "harvest":  "OSINT harvest: emails/hosts (theHarvester or native)",
    "scope":    "print/triage the scope table from passive results",
    "active":   "active --target HOST  nmap/curl/openssl on one approved target",
    "content":  "content --url https://HOST/ [--engine ffuf|gobuster] [--ext php,bak]",
    "internal": "internal network discovery (local + optional probe)",
    "analyze":  "turn results into ranked leads",
    "report":   "write the report note (section 8 template + leads)",
    "all":      "all <target> [--host H] [--authorized]  run the whole chain",
    "deps":     "check OS + install required/optional tools (with consent)",
}

# meta-commands handled by the REPL itself, not by argparse.
SHELL_META = {
    "help":   "show this help, or `help <command>` for a command's options",
    "banner": "redraw the ASCII banner",
    "clear":  "clear the screen",
    "status": "show the current case directory",
    "exit":   "leave the interactive shell (also: quit, q, Ctrl-D)",
}


def _shell_help(parser, topic=None):
    """`help` lists commands; `help <cmd>` defers to argparse's own -h."""
    if topic:
        topic = topic.lower()
        if topic in SHELL_COMMANDS:
            try:
                parser.parse_args([topic, "-h"])
            except SystemExit:
                pass
            return
        if topic in SHELL_META:
            print(f"  {topic:9} {SHELL_META[topic]}")
            return
        warn(f"unknown command: {topic}")
        return
    print(_color("Commands", C_GRN) + " (type `help <command>` for options):")
    for name, hint in SHELL_COMMANDS.items():
        print(f"  {_color(name.ljust(9), C_CYN)} {hint}")
    print()
    print(_color("Shell", C_GRN) + ":")
    for name, hint in SHELL_META.items():
        print(f"  {_color(name.ljust(9), C_CYN)} {hint}")


def _shell_status():
    path = None
    if os.path.exists(CURRENT_PTR):
        try:
            with open(CURRENT_PTR) as f:
                path = f.read().strip()
        except OSError:
            path = None
    if path and os.path.isdir(path):
        good(f"current case: {path}")
    else:
        info("no case yet — run `init <target>` to create one.")


def interactive_shell(parser):
    """A small REPL over the existing subcommands.

    State is shared across commands through the on-disk `recon/.current`
    pointer exactly as the non-interactive CLI does, so `init` then `passive`
    then `scope` ... behave identically to separate invocations.
    """
    try:
        import readline  # noqa: F401  (enables line editing + history if present)
    except Exception:
        pass

    print_banner()
    # one-time, non-prompting tool hint so the banner isn't noisy per command.
    missing_req = [t for t in REQUIRED_TOOLS if not _tool_installed(t)]
    if missing_req:
        warn(f"Missing required tool(s): {', '.join(missing_req)} — run `deps` to install.")
    info("Interactive mode. Type `help` for commands, `exit` to quit.")
    _shell_status()

    prompt = _color("reconkit> ", C_CYN)
    while True:
        try:
            line = input(prompt)
        except EOFError:
            print()
            break
        except KeyboardInterrupt:
            print()
            continue

        line = line.strip()
        if not line:
            continue

        try:
            tokens = shlex.split(line)
        except ValueError as e:
            err(f"parse error: {e}")
            continue
        if not tokens:
            continue

        name = tokens[0].lower()
        if name in ("exit", "quit", "q"):
            break
        if name in ("help", "?", "h"):
            _shell_help(parser, tokens[1] if len(tokens) > 1 else None)
            continue
        if name == "banner":
            print_banner()
            continue
        if name in ("clear", "cls"):
            if sys.stdout.isatty():
                print("\033[2J\033[H", end="")
            continue
        if name == "status":
            _shell_status()
            continue
        if name in ("shell", "interactive"):
            warn("already in interactive mode.")
            continue
        if name not in SHELL_COMMANDS:
            warn(f"unknown command: {name} (type `help`)")
            continue

        # argparse exits the process on error/-h; trap that so the REPL lives.
        try:
            args = parser.parse_args(tokens)
        except SystemExit:
            continue
        try:
            args.func(args)
        except KeyboardInterrupt:
            err("interrupted")
        except SystemExit:
            # a command signalled a non-fatal error (e.g. no case yet); stay up.
            pass
        except Exception as e:  # keep the shell alive on unexpected failures
            err(f"{type(e).__name__}: {e}")


def cmd_shell(args):
    interactive_shell(build_parser())


# ---------------------------------------------------------------------------
# cli
# ---------------------------------------------------------------------------

def build_parser():
    p = argparse.ArgumentParser(
        prog="recon.py",
        description="Combined external + internal reconnaissance orchestrator "
                    "(authorized testing only).",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""Typical flow:
  recon.py init example.com --host www.example.com
  recon.py passive
  recon.py scope
  # confirm authorization, edit recon/.../scope.json: "authorized": true
  recon.py active --target www.example.com
  recon.py content --url https://www.example.com/
  recon.py analyze
  recon.py report

Internal (post-foothold):
  recon.py internal
  recon.py internal --ip 10.0.0.5 --role windows --authorized
""")
    sub = p.add_subparsers(dest="cmd", required=False)

    def add_case(sp):
        sp.add_argument("--case", help="case directory (default: last created)")

    sh = sub.add_parser("shell", help="interactive mode: banner + prompt (default with no args)")
    sh.set_defaults(func=cmd_shell)

    i = sub.add_parser("init", help="create a case + folder structure + scope file")
    i.add_argument("target", help="domain or IP to assess")
    i.add_argument("--host", help="exact approved hostname for web checks")
    i.add_argument("--scope-domain", action="append", help="authorized domain suffix (repeatable)")
    i.add_argument("--scope-ip", action="append", help="authorized IP (repeatable)")
    i.add_argument("--scope-cidr", action="append", help="authorized CIDR (repeatable)")
    i.add_argument("--scope-host", action="append", help="authorized exact hostname (repeatable)")
    i.add_argument("--authorized", action="store_true", help="mark scope as authorized now")
    i.set_defaults(func=cmd_init)

    pa = sub.add_parser("passive", help="passive discovery (crt.sh, wayback, dig, whois)")
    add_case(pa); pa.set_defaults(func=cmd_passive)

    hv = sub.add_parser("harvest", help="OSINT harvest: emails/hosts (theHarvester or native)")
    add_case(hv)
    hv.add_argument("--native", action="store_true", help="force native stdlib OSINT (skip binary)")
    hv.add_argument("--sources", default="crtsh,bing,duckduckgo,otx",
                    help="theHarvester -b sources (comma-separated)")
    hv.set_defaults(func=cmd_harvest)

    dp = sub.add_parser("deps", help="check OS + install required/optional tools (with consent)")
    dp.add_argument("--check", action="store_true", help="report only; never install")
    dp.add_argument("--print", dest="print_only", action="store_true",
                    help="print install commands, don't run them")
    dp.add_argument("--dry-run", action="store_true", help="show the plan; execute nothing")
    dp.add_argument("--yes", action="store_true", help="install without prompting (non-interactive)")
    dp.add_argument("--required-only", action="store_true", help="ignore optional tools")
    dp.add_argument("--os-release", help="path to an os-release file (for testing)")
    dp.set_defaults(func=cmd_deps)

    sc = sub.add_parser("scope", help="print/triage the scope table from passive results")
    add_case(sc); sc.set_defaults(func=cmd_scope)

    ac = sub.add_parser("active", help="active checks on one approved target (nmap/curl/openssl)")
    add_case(ac)
    ac.add_argument("--target", help="approved host or IP (default: case host/target)")
    ac.add_argument("--all-ports", action="store_true", help="scan all TCP ports (-p-), slow")
    ac.add_argument("--pn", action="store_true", help="skip host discovery (-Pn)")
    ac.add_argument("--os-detect", action="store_true", help="OS + UDP probes (needs sudo)")
    ac.set_defaults(func=cmd_active)

    co = sub.add_parser("content", help="directory/content discovery (native, or ffuf/gobuster)")
    add_case(co)
    co.add_argument("--url", required=True, help="base URL, e.g. https://host/")
    co.add_argument("--wordlist", help="wordlist path (default: SecLists if found, else built-in)")
    co.add_argument("--engine", choices=["native", "ffuf", "gobuster"], default="native")
    co.add_argument("--threads", type=int, default=10)
    co.add_argument("--delay", type=float, default=0.0, help="seconds between requests")
    co.add_argument("--timeout", type=float, default=8.0)
    co.add_argument("--ext", help="comma-separated extensions to append, e.g. php,bak,zip")
    co.set_defaults(func=cmd_content)

    it = sub.add_parser("internal", help="internal network discovery (local + optional probe)")
    add_case(it)
    it.add_argument("--ip", help="single host to probe")
    it.add_argument("--role", choices=list(INTERNAL_ROLES), help="role preset for port set")
    it.add_argument("--domain", help="AD domain for SRV lookup")
    it.add_argument("--dns", help="DNS server IP for @server queries")
    it.add_argument("--sweep", help="CIDR to list/sweep (discovery only)")
    it.add_argument("--confirm-sweep", action="store_true", help="actually run nmap -sn on the CIDR")
    it.add_argument("--authorized", action="store_true", help="confirm probe/sweep authorization")
    it.set_defaults(func=cmd_internal)

    an = sub.add_parser("analyze", help="turn results into ranked leads")
    add_case(an); an.set_defaults(func=cmd_analyze)

    rp = sub.add_parser("report", help="write the report note (section 8 template + leads)")
    add_case(rp); rp.set_defaults(func=cmd_report)

    al = sub.add_parser("all", help="init+passive+scope (+active/analyze/report if authorized)")
    al.add_argument("target"); al.add_argument("--host")
    al.add_argument("--scope-domain", action="append"); al.add_argument("--scope-ip", action="append")
    al.add_argument("--scope-cidr", action="append"); al.add_argument("--scope-host", action="append")
    al.add_argument("--authorized", action="store_true")
    al.add_argument("--all-ports", action="store_true"); al.add_argument("--pn", action="store_true")
    al.add_argument("--os-detect", action="store_true")
    al.set_defaults(func=cmd_all)

    return p


def _preflight(args):
    """Trigger: if a REQUIRED tool is missing, offer to run deps (TTY only);
    for missing OPTIONAL tools just print a one-line hint."""
    if getattr(args, "cmd", None) == "deps":
        return
    missing_req = [t for t in REQUIRED_TOOLS if not _tool_installed(t)]
    missing_opt = [t for t in OPTIONAL_TOOLS if not _tool_installed(t)]
    if missing_req:
        warn(f"Missing required tool(s): {', '.join(missing_req)}.")
        if sys.stdin.isatty():
            try:
                if (input("  Run `deps` to install them now? [y/N] ").strip().lower() or "n")[0] == "y":
                    ns = argparse.Namespace(check=False, print_only=False, dry_run=False,
                                            yes=False, required_only=False, os_release=None, cmd="deps")
                    cmd_deps(ns)
            except EOFError:
                pass
        else:
            info("Run `recon.py deps` to install them.")
    elif missing_opt:
        info(f"Optional tools not installed: {', '.join(missing_opt)} "
             "(run `recon.py deps` to add them; native fallbacks are used meanwhile).")


def main(argv=None):
    parser = build_parser()
    args = parser.parse_args(argv)
    # no subcommand -> drop into the interactive shell on a TTY, else show help.
    if getattr(args, "cmd", None) is None:
        if sys.stdin.isatty() and sys.stdout.isatty():
            interactive_shell(parser)
        else:
            parser.print_help()
        return
    if args.cmd != "shell":
        _preflight(args)
    try:
        args.func(args)
    except KeyboardInterrupt:
        err("interrupted")
        sys.exit(130)


if __name__ == "__main__":
    main()
