<p align="center">
  <br>
  <a href="https://github.com/elcnqlyv/reconkit" target="_blank"><img src="reconkit-banner.svg" alt="reconkit" width="72%"/></a>
  <br>
  <br>
  <span>Combined <b>external + internal</b> reconnaissance in one evidence-driven CLI &mdash; passive &rarr; scope &rarr; active, <b>leads, not verdicts</b>.</span>
  <br>
</p>

<p align="center">
  <a href="#install">Install</a>
  &nbsp;&nbsp;&nbsp;•&nbsp;&nbsp;&nbsp;
  <a href="#workflow">Workflow</a>
  &nbsp;&nbsp;&nbsp;•&nbsp;&nbsp;&nbsp;
  <a href="#internal-mode-post-foothold">Internal mode</a>
  &nbsp;&nbsp;&nbsp;•&nbsp;&nbsp;&nbsp;
  <a href="#output-layout">Output</a>
  &nbsp;&nbsp;&nbsp;•&nbsp;&nbsp;&nbsp;
  <a href="#license">License</a>
</p>

```console
$ python3 recon.py
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣠⣤⡀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣤⡀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢰⢁⣿⣿⣷⡄⠀⠀⠀⠀⠀⣴⣿⣿⣷⡀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣾⢸⡿⠿⣿⣿⣦⣤⣤⣤⣤⣬⣉⣻⣿⣧
⠀⠀⠀⠀⠀⠀⠀⠀⠀⢰⣿⠀⣶⣶⣬⣿⣿⣿⣿⣿⣿⣿⣿⣿⣦⡝⠆
⠀⠀⠀⠀⠀⠀⠀⠀⠀⢸⣿⣸⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣆
⠀⠀⠀⠀⠀⠀⠀⠀⠀⢸⣿⣿⣿⣿⣿⣿⣿⣿⠿⠿⣿⣿⣿⣿⡏⠉⢻
⠀⠀⠀⠀⠀⠀⠀⠀⠀⢸⣿⣿⣿⣿⣿⣿⣿⡏⠀⠀⣿⣿⣿⣿⣷⣄⣼⣷⡒
⠀⢀⣠⣤⣤⠀⠀⠀⠀⠸⣿⣿⣿⣿⣿⣿⠖⣻⣶⣾⣿⣿⣿⣧⣿⣿⣿⣿⠉
⣿⣿⣿⣿⣿⣷⣄⠀⠀⠹⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡿⠏⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⡴⢲⡄⠀⠀⠀⢀⣀
⠈⢿⣿⣿⣿⣿⣿⣿⡄⠀⠀⠀⠙⠛⠿⠿⣿⣿⣿⣿⣿⣿⣿⣿⡋⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⡞⠀⠀⡇⠀⢀⡴⠋⠁⢸
⠀⠀⠉⢻⣿⣿⣿⣿⣧⠀⠀⠀⣠⣶⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣸⠁⠀⠀⡇⣠⠟⠀⠀⠀⣼⣠⣤⣤⣀
⠀⠀⠀⠘⣿⣿⣿⣿⡟⠀⢀⣼⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣇⠀⠀⠀⠀⠀⠀⠀⠀⠀⣿⠀⢠⢤⡿⠃⣀⠀⢀⡞⠉⠁⠀⠀⠈⠙⠶⡄
⠀⠀⠀⢰⣿⣿⣿⣿⠇⢀⣾⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⠀⠀⠀⠀⠀⠀⠀⠀⠀⣻⣰⡏⣼⢁⡴⠋⣰⠋⠀⠀⠀⠀⠀⠀⠀⠀⠹⡄⣀⡀
⠀⠀⠀⣾⣿⣿⣿⡟⠀⣾⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⢿⡿⠀⠀⠀⠀⠀⠀⠀⢀⡾⠋⠉⠁⠀⠙⠁⠞⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢹⡈⢷
⠀⠀⢰⣿⣿⣿⣿⠀⢸⣿⣿⣿⣿⣿⣿⠿⣿⣿⣿⣿⣿⣿⣿⡇⣼⡇⠀⠀⠀⠀⠀⠀⠀⣼⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠄⠀⠀⠀⠀⠀⠀⠀⢀⣧⡾⠁
⠀⠀⢸⣿⣿⣿⣇⠀⣿⣿⣿⣿⣿⣿⣿⣷⣌⢻⣿⣿⣿⣿⣿⣴⣿⡇⠀⠀⠀⠀⠀⠀⠀⡏⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠄⠀⠀⠀⠀⠀⠀⠀⣾⠃
⠀⠀⠸⣿⣿⣿⣿⣤⣿⣿⣿⣿⣿⣿⣿⣿⣿⠄⣿⣿⣿⣿⡏⢸⣿⡇⠀⠀⠀⠀⠀⠀⠀⣹⡄⠀⠀⠀⠀⠀⠀⠀⠀⠀⠘⠁⠀⠀⡀⠀⠀⢰⡾⠋
⠀⠀⠀⠙⢿⣿⣿⡇⢿⣿⣿⣿⣿⣿⣿⣿⡿⠀⣿⣿⣿⣿⡇⣿⣿⠀⠀⠀⠀⠀⠀⠀⠀⢻⡇⣀⡀⠀⠺⣿⠇⠀⣀⣤⣄⣀⣠⣬⣥⣤⠾⠛⠁
⠀⠀⠀⠀⠀⠉⠙⠛⠂⠙⠛⠛⠛⠛⠛⠛⠐⠓⠈⠙⠋⠋⠃⠉⠉⠀⠀⠀⠀⠀⠀⠀⠀⠀⠉⠛⠓⠂⠤⠤⠖⠊⠉⠉⠉⠉⠁

                     _   _ _
 _ _ ___ __ ___ _ _ | |_(_) |_
| '_/ -_) _/ _ \ ' \| / / |  _|
|_| \___\__\___/_||_|_\_\_|\__|

  reconkit — combined external + internal recon orchestrator
  authorized testing only · leads, not verdicts · every command logged
```

One command-line tool that combines two pentest cheat sheets into a single,
evidence-driven workflow:

- **External / public-target recon** (domain & IP) — passive → scope → active
- **Internal network discovery** (post-foothold)
- **Content / directory discovery** (native fuzzer, or `ffuf` / `gobuster`)
- **OSINT harvest** (`theHarvester`, or a native stdlib fallback)
- **Lead triage + report note** — surfaces the point(s) to elaborate on

Pure Python 3 standard library. External binaries (`dig`, `nmap`, `nc`, `curl`,
`openssl`, `whois`, `ffuf`, `gobuster`, `subfinder`, `theHarvester`) are used
when present and degrade gracefully when absent.

> [!WARNING]
> **Authorized testing only.** Active phases refuse to run unless a scope
> allowlist exists and you have confirmed authorization. A resolving subdomain
> or a shared IP is **not** automatically in scope. Every external command is
> logged to `evidence/commands.log` (UTC time, exact argv, output file, exit).

## Install

```bash
git clone https://github.com/elcnqlyv/reconkit.git
cd reconkit
./install.sh          # = python3 recon.py deps : checks your OS and offers to install tools
```

`deps` detects the platform (Arch/Omarchy, Debian/Ubuntu/**Kali**, Fedora, macOS),
lists which required/optional tools are missing, and asks:
**[I]nstall for me / [P]rint commands, I'll do it / [S]kip**. It never installs
without consent, runs repo installs with the terminal attached (so sudo/yay
prompts are visible), and runs AUR installs as your user (never `sudo yay`).

```bash
python3 recon.py deps              # interactive check + install
python3 recon.py deps --check      # report only, never install
python3 recon.py deps --print      # print the commands for you to run
```

Only Python 3 and the core CLI tools (`dig nmap nc curl openssl whois ip ss`)
are required. `ffuf`/`gobuster`/`subfinder`/`theHarvester`/SecLists are optional
— native fallbacks run without them.

| Platform | Install |
| --- | --- |
| **Kali** (intended runtime) | `sudo apt-get install -y nmap ffuf gobuster seclists theharvester dnsutils netcat-openbsd whois` |
| **Arch / Omarchy** | `gobuster` from the repo; `ffuf-bin` / `subfinder-bin` / `seclists-git` from the AUR |
| **subfinder** (any) | `go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest` |
| **theHarvester on Arch** | AUR build currently fails against `flit_core` 4 — use `sudo pacman -S python-pipx && pipx install theHarvester` |

## Commands

```console
$ python3 recon.py --help
usage: recon.py [-h]
                {shell,init,passive,harvest,deps,scope,active,content,internal,analyze,report,all} ...

Combined external + internal reconnaissance orchestrator (authorized testing only).

    shell      interactive mode: banner + prompt (default with no args)
    init       create a case + folder structure + scope file
    passive    passive discovery (crt.sh, wayback, dig, whois)
    harvest    OSINT harvest: emails/hosts (theHarvester or native)
    deps       check OS + install required/optional tools (with consent)
    scope      print/triage the scope table from passive results
    active     active checks on one approved target (nmap/curl/openssl)
    content    directory/content discovery (native, or ffuf/gobuster)
    internal   internal network discovery (local + optional probe)
    analyze    turn results into ranked leads
    report     write the report note (section 8 template + leads)
    all        init+passive+scope (+active/analyze/report if authorized)
```

## Interactive shell

Run `recon.py` with no arguments (or `recon.py shell`) to drop into an
interactive prompt. It draws the banner and lets you type the commands below
directly — `init example.com --host www.example.com`, then `passive`, `scope`,
etc. — without re-typing `python3 recon.py` each time. The current case is
shared across commands just like the plain CLI. `help` lists commands,
`help <command>` shows a command's options, and `exit` (or Ctrl-D) quits.

## Workflow

Every phase feeds the next, and the active side of the pipeline is sealed behind
an authorization gate that will not open on a resolving hostname alone:

```text
   ┌── passive ──┬── harvest ──┬── scope ──┐
   │  crt.sh     │  emails     │  triage   │
   │  wayback    │  hosts      │  leads    │
   │  dig·whois  │             │           │
   └─────────────┴─────────────┴───────────┘
                                     │
                       ╔═════════════▼═════════════╗
                       ║     AUTHORIZATION  GATE   ║
                       ║  written consent required ║
                       ║  scope.json → "true"      ║
                       ╚═════════════╤═════════════╝
                                     │
   ┌── active ───┬── content ──┬── analyze ─┬── report ──┐
   │  nmap       │  dir/file   │  rank      │  section-8  │
   │  curl·tls   │  fuzzing    │  leads     │  note        │
   └─────────────┴─────────────┴────────────┴─────────────┘
```

The same commands work non-interactively:

```bash
cd reconkit

# 1. open a case + folder structure + scope file
python3 recon.py init example.com --host www.example.com

# 2. passive discovery (crt.sh, Wayback, dig records, whois)
python3 recon.py passive

# 3. OSINT emails/hosts
python3 recon.py harvest

# 4. triage leads into an approved target list
python3 recon.py scope

#    >>> confirm written authorization, then edit the case's scope.json:
#        "authorized": true   (and list the exact hosts/IPs/CIDRs)

# 5. active checks on ONE approved target
python3 recon.py active --target www.example.com

# 6. content / directory discovery
python3 recon.py content --url https://www.example.com/ --ext php,bak,zip

# 7. rank findings into leads + pick the point to elaborate
python3 recon.py analyze

# 8. write the report note (cheat-sheet section 8 template + leads)
python3 recon.py report
```

`python3 recon.py all example.com --host www.example.com` chains
init → passive → harvest → scope, and continues into active/analyze/report
only if the scope is marked authorized.

## Internal mode (post-foothold)

```text
   foothold ──▶ local clues ──▶ [--authorized] ──▶ subnet sweep
   (LOCAL)      ip·route·ss       role presets        nmap probe
                resolvectl        linux web           --confirm-sweep
                                  windows dc db
```

```bash
python3 recon.py internal                              # local clues only (LOCAL)
python3 recon.py internal --ip 10.0.0.5 --role windows --authorized
python3 recon.py internal --domain corp.local --dns 10.0.0.1   # AD DC SRV lookup
python3 recon.py internal --sweep 10.0.0.0/28 --authorized --confirm-sweep
```

Role presets (`--role`): `linux` `web` `windows` `dc` `db`.

## Output layout

```text
recon/<target>/<UTC-stamp>/
├── passive/    whois, dig_*, crtsh.json, wayback.txt, subdomains.txt,
│               resolved.txt, emails.txt, indexes.json
├── active/     nmap top100/versions/banners (.nmap/.xml/.gnmap),
│               headers.txt, tls-cert.txt
├── content/    dirscan.txt
├── internal/   ip-addr/route/neigh, resolvectl, ss-*, nmap-*
├── evidence/   start-utc.txt, commands.log   ◀─ every command, reproducible
└── report/     scope-table.md, recon-note-<target>.md
    scope.json  case.json  *_summary.json  leads.json
```

## Design notes / limits

- **Leads, not verdicts.** A banner or version string is labelled
  *"possible / needs validation"*. No exploit checks, credential attempts, or
  `vuln` NSE categories are ever run.
- **Soft-404 calibration.** The content fuzzer probes random paths first and
  filters catch-all 200 responses, so a wildcard server doesn't fill the report
  with fake hits. It does not follow redirects; 301/302/401/403 are reported.
- **Ranking.** Leads are ordered RCE-adjacent first, then by severity, then
  confidence, and `analyze` prints the single primary point to elaborate.
- Keeps IPv4/IPv6 separate and records which address was contacted.
- `-p-`, `-O`, `-sU`, and subnet sweeps are behind explicit flags; `sudo` is
  only ever invoked (as `sudo -n`) for `-O`/`-sU`, never silently elsewhere.

## License

GPL-3.0-or-later. Copyright (C) 2026 Elchin Guliyev. See [LICENSE](LICENSE).

For authorized security testing only. You are responsible for having written
permission before running any active phase against a target you do not own.

<p align="center">
  <br>
  <img src="reconkit-logo.svg" alt="reconkit" width="96"/>
  <br>
  <sub><b>recon</b><span>kit</span> · authorized testing only · leads, not verdicts</sub>
</p>
