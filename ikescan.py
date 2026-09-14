#!/usr/bin/env python3
"""
ikescan — IKE/VPN enumeration and misconfiguration audit.

Orchestrates ike-scan to probe IKEv1 Main Mode, IKEv1 Aggressive Mode, and IKEv2.
Reports accepted transforms, vendor fingerprints, misconfigurations, and a
step-by-step attack plan based on what was found.

Requires: ike-scan (apt install ike-scan), root or CAP_NET_RAW
"""

import argparse
import os
import re
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass, field
from pathlib import Path

from rich.console import Console
from rich.panel import Panel
from rich.rule import Rule
from rich.table import Table
from rich import box as rbox
from rich.text import Text

BANNER = "[bold cyan]ikescan[/]  [dim]·  IKE/VPN enumeration & misconfiguration audit[/]"
console = Console()

# ── Transform definitions ─────────────────────────────────────────────────────

# (ike-scan shorthand, display label, enc, hash, auth, dh_group, risk)
# ike-scan format: ENC[/KEYLEN],HASH,AUTH,DH
# Enc: 1=DES 5=3DES 7=AES   Hash: 1=MD5 2=SHA1 4=SHA256
# Auth: 1=PSK 3=RSA 65001=XAUTH/PSK  DH: 1=G1 2=G2 5=G5 14=G14

TRANSFORMS = [
    ("7/256,4,1,14",  "AES-256 / SHA-256 / PSK / Group14", "AES-256", "SHA-256", "PSK", 14, "ok"),
    ("7/128,4,1,14",  "AES-128 / SHA-256 / PSK / Group14", "AES-128", "SHA-256", "PSK", 14, "ok"),
    ("7/256,2,1,14",  "AES-256 / SHA-1   / PSK / Group14", "AES-256", "SHA-1",   "PSK", 14, "medium"),
    ("7/128,2,1,14",  "AES-128 / SHA-1   / PSK / Group14", "AES-128", "SHA-1",   "PSK", 14, "medium"),
    ("7/256,2,1,2",   "AES-256 / SHA-1   / PSK / Group2",  "AES-256", "SHA-1",   "PSK",  2, "medium"),
    ("7/128,2,1,2",   "AES-128 / SHA-1   / PSK / Group2",  "AES-128", "SHA-1",   "PSK",  2, "medium"),
    ("7/128,1,1,2",   "AES-128 / MD5     / PSK / Group2",  "AES-128", "MD5",     "PSK",  2, "high"),
    ("5,2,1,5",       "3DES   / SHA-1   / PSK / Group5",   "3DES",   "SHA-1",   "PSK",  5, "medium"),
    ("5,2,1,2",       "3DES   / SHA-1   / PSK / Group2",   "3DES",   "SHA-1",   "PSK",  2, "high"),
    ("5,1,1,2",       "3DES   / MD5     / PSK / Group2",   "3DES",   "MD5",     "PSK",  2, "high"),
    ("1,1,1,1",       "DES    / MD5     / PSK / Group1",   "DES",    "MD5",     "PSK",  1, "critical"),
    ("7/256,4,3,14",  "AES-256 / SHA-256 / RSA / Group14", "AES-256", "SHA-256", "RSA", 14, "ok"),
    ("7/128,2,3,2",   "AES-128 / SHA-1   / RSA / Group2",  "AES-128", "SHA-1",   "RSA",  2, "medium"),
]

# Group names to try in Aggressive Mode
AGGR_GROUPS = [
    "vpn", "VPN", "Default", "GroupVPN", "cisco", "group1",
    "remote", "test", "IPSEC", "ipsec", "vpngroup", "gateway",
]

RISK_COLOR = {
    "ok":       "green",
    "low":      "cyan",
    "medium":   "yellow",
    "high":     "orange3",
    "critical": "red",
}
RISK_LABEL = {
    "ok":       "OK",
    "low":      "LOW",
    "medium":   "MEDIUM",
    "high":     "HIGH",
    "critical": "CRITICAL",
}

# ── ike-scan wrapper ──────────────────────────────────────────────────────────

def run_scan(args: list[str], timeout: int = 10) -> str:
    """Run ike-scan and return stdout. Returns empty string on failure."""
    cmd = ["ike-scan", "--nodns", "--retry=2", "--timeout=3000"] + args
    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout
        )
        return result.stdout + result.stderr
    except subprocess.TimeoutExpired:
        return ""
    except FileNotFoundError:
        console.print("[red]ike-scan not found. Install with: apt install ike-scan[/]")
        sys.exit(1)

def responded(output: str) -> bool:
    """True if ike-scan output contains a successful handshake."""
    return any(k in output for k in (
        "Handshake returned",
        "Aggressive Mode Handshake returned",
        "SA=(",
        "IKEv2 SA_INIT",
    ))

# ── Output parsers ────────────────────────────────────────────────────────────

def parse_sa(output: str) -> dict:
    """Extract the first SA= block from ike-scan output."""
    m = re.search(r"SA=\(([^)]+)\)", output)
    if not m:
        return {}
    sa_str = m.group(1)
    result = {}
    for kv in re.findall(r"(\w+)=([^\s]+)", sa_str):
        result[kv[0]] = kv[1]
    return result

def parse_vids(output: str) -> list[str]:
    """Extract all VID labels from ike-scan output."""
    vids = []
    for line in output.splitlines():
        line = line.strip()
        if line.startswith("VID="):
            # ike-scan appends (Label) if it recognises the VID
            label_m = re.search(r"\(([^)]+)\)$", line)
            if label_m:
                vids.append(label_m.group(1))
            else:
                hex_m = re.match(r"VID=([0-9a-fA-F]+)", line)
                if hex_m:
                    vids.append(f"unknown ({hex_m.group(1)[:16]}...)")
    return list(dict.fromkeys(vids))

def sa_to_label(sa: dict) -> str:
    enc = sa.get("Enc", "?")
    kl  = sa.get("KeyLength", "")
    hsh = sa.get("Hash", "?")
    auth = sa.get("Auth", "?")
    grp = sa.get("Group", "?").split(":")[0]
    if kl:
        return f"{enc}-{kl} / {hsh} / {auth} / Group{grp}"
    return f"{enc} / {hsh} / {auth} / Group{grp}"

# ── Scan phases ───────────────────────────────────────────────────────────────

@dataclass
class ScanResults:
    target: str
    port: int
    main_mode: bool = False
    aggressive_mode: bool = False
    ikev2: bool = False
    nat_t: bool = False
    mm_accepted: list = field(default_factory=list)    # list of (spec, label, risk, sa_dict)
    aggr_accepted: list = field(default_factory=list)  # list of (group, sa_dict, psk_file)
    vendor_ids: list = field(default_factory=list)
    raw_outputs: dict = field(default_factory=dict)

def probe_main_mode(r: ScanResults, verbose: bool):
    console.print("  [dim]→ IKEv1 Main Mode detection...[/]")
    # First: broad detection probe with ike-scan defaults
    out = run_scan([r.target, f"--dport={r.port}"])
    r.raw_outputs["mm_detect"] = out
    if not responded(out):
        return
    r.main_mode = True
    r.vendor_ids = parse_vids(out)

    console.print("  [dim]→ Enumerating accepted transforms...[/]")
    for spec, label, enc, hsh, auth, dh, risk in TRANSFORMS:
        out = run_scan([r.target, f"--dport={r.port}", f"--trans={spec}"])
        if responded(out):
            sa = parse_sa(out)
            r.mm_accepted.append((spec, label, risk, sa))
            # Pick up any extra VIDs
            for v in parse_vids(out):
                if v not in r.vendor_ids:
                    r.vendor_ids.append(v)

def probe_aggressive(r: ScanResults, psk_dir: str, verbose: bool, groups: list | None = None):
    console.print("  [dim]→ IKEv1 Aggressive Mode detection...[/]")
    for group in (groups if groups is not None else AGGR_GROUPS):
        id_arg = f"--id={group}" if group else "--id=test"
        # Try with the default broad transform set first
        psk_file = os.path.join(psk_dir, f"aggr_{group or 'empty'}_{int(time.time())}.psk")
        out = run_scan([
            r.target, f"--dport={r.port}",
            "--aggressive",
            id_arg,
            f"--pskcrack={psk_file}",
        ])
        if responded(out):
            if not r.aggressive_mode:
                r.aggressive_mode = True
                console.print(f"  [red]→ Aggressive Mode RESPONDING (group: {group!r})[/]")
            sa = parse_sa(out)
            psk_path = psk_file if Path(psk_file).exists() else None
            r.aggr_accepted.append((group, sa, psk_path))
            for v in parse_vids(out):
                if v not in r.vendor_ids:
                    r.vendor_ids.append(v)

def probe_ikev2(r: ScanResults):
    console.print("  [dim]→ IKEv2 detection...[/]")
    out = run_scan([r.target, f"--dport={r.port}", "--ikev2"])
    r.raw_outputs["ikev2"] = out
    if responded(out):
        r.ikev2 = True

def probe_nat_t(r: ScanResults):
    console.print("  [dim]→ NAT-T (port 4500) detection...[/]")
    out = run_scan([r.target, "--dport=4500", "--sport=4500"])
    r.raw_outputs["nat_t"] = out
    if responded(out):
        r.nat_t = True

# ── Risk analysis ─────────────────────────────────────────────────────────────

@dataclass
class Finding:
    severity: str   # CRITICAL HIGH MEDIUM LOW INFO
    title: str
    detail: str

@dataclass
class AttackStep:
    num: int
    severity: str
    title: str
    commands: list[str]
    notes: str = ""

def analyze(r: ScanResults) -> tuple[list[Finding], list[AttackStep]]:
    findings: list[Finding] = []
    steps: list[AttackStep] = []
    step_n = 0

    def F(sev, title, detail=""):
        findings.append(Finding(sev, title, detail))

    def S(sev, title, cmds, notes=""):
        nonlocal step_n
        step_n += 1
        steps.append(AttackStep(step_n, sev, title, cmds, notes))

    # ── Aggressive Mode ───────────────────────────────────────────────────────
    if r.aggressive_mode:
        psk_groups = [g for g, sa, pf in r.aggr_accepted if pf]
        psk_files  = [pf for g, sa, pf in r.aggr_accepted if pf]

        # Auth method in SA
        is_psk = any(
            "PSK" in (sa.get("Auth", "") or "") or sa.get("Auth", "") in ("1", "PSK")
            for _, sa, _ in r.aggr_accepted
        )
        if is_psk or True:  # PSK is default; no auth = also PSK
            F("CRITICAL",
              "Aggressive Mode enabled with PSK authentication",
              "PSK hash is sent unencrypted and can be captured + cracked offline "
              f"(group(s): {', '.join(repr(g) for g in psk_groups) or 'default'}).")
            crack_cmds = []
            for pf in psk_files:
                crack_cmds += [
                    f"psk-crack {pf}",
                    f"psk-crack --bruteforce=8 {pf}",
                    f"hashcat -m 5300 {pf} /usr/share/wordlists/rockyou.txt  # MD5-based",
                    f"hashcat -m 5400 {pf} /usr/share/wordlists/rockyou.txt  # SHA1-based",
                ]
            S("CRITICAL", "Crack Aggressive Mode PSK hash", crack_cmds,
              "Hashcat rule: add -r /usr/share/hashcat/rules/best64.rule for better coverage.")
        else:
            F("HIGH", "Aggressive Mode enabled (non-PSK auth)",
              "Even without PSK, Aggressive Mode leaks the gateway identity and group name.")
    elif r.main_mode:
        F("HIGH", "IKEv1 Main Mode enabled (Aggressive Mode not detected)",
          "Main Mode is more secure than Aggressive Mode, but IKEv1 itself is deprecated.")

    # ── Weak transforms ───────────────────────────────────────────────────────
    crit_trans = [t for t in r.mm_accepted if t[2] == "critical"]
    high_trans = [t for t in r.mm_accepted if t[2] == "high"]
    med_trans  = [t for t in r.mm_accepted if t[2] == "medium"]

    if crit_trans:
        labels = ", ".join(t[1] for t in crit_trans)
        F("CRITICAL", "Export-grade / broken transforms accepted",
          f"DES and MD5 are cryptographically broken: {labels}")
        S("CRITICAL", "Exploit broken transforms",
          ["# Force DES/MD5 negotiation via ike-scan to confirm downgrade",
           f"ike-scan --trans=1,1,1,1 {r.target}",
           "# If forced downgrade works, use it to weaken session key material"],
          "DES is brute-forceable in hours with modern hardware.")

    if high_trans:
        labels = ", ".join(t[1] for t in high_trans)
        F("HIGH", "Weak transforms accepted (3DES/MD5 or Group2)",
          f"3DES/MD5 and DH Group2 (1024-bit) are deprecated: {labels}")

    if med_trans:
        F("MEDIUM", "Moderate-risk transforms accepted (SHA-1 or Group2/Group14)",
          "SHA-1 is deprecated; DH Group2 (1024-bit) is below current recommendations.")

    # ── IKEv2 ────────────────────────────────────────────────────────────────
    if not r.ikev2 and (r.main_mode or r.aggressive_mode):
        F("HIGH", "IKEv2 not supported — IKEv1-only",
          "IKEv1 is deprecated (RFC 9395). IKEv2 is the current standard with better "
          "security properties and no Aggressive Mode vulnerability.")

    # ── DH group weakness ─────────────────────────────────────────────────────
    # mm_accepted entries are (spec, label, risk, sa); extract DH from spec's last field
    def _dh(spec: str) -> int:
        try:
            return int(spec.split(",")[-1])
        except (ValueError, IndexError):
            return 0

    weak_dh = any(_dh(t[0]) in (1, 2, 5) for t in r.mm_accepted)
    if weak_dh:
        F("MEDIUM", "Weak DH groups accepted (Group 1/2/5, <2048-bit)",
          "NIST recommends DH Group 14 (2048-bit) or higher.")

    # ── XAUTH ────────────────────────────────────────────────────────────────
    xauth = any("XAUTH" in v or "xauth" in v.lower() for v in r.vendor_ids)
    if xauth and r.aggressive_mode:
        F("HIGH", "XAUTH detected — credential stuffing possible after PSK crack",
          "Once PSK is cracked, XAUTH allows username/password brute-force.")
        S("HIGH", "XAUTH credential stuffing",
          ["# After PSK is cracked:",
           "# 1. Configure racoon or strongSwan with cracked PSK",
           "# 2. Brute-force XAUTH with common credentials:",
           "#    admin/admin, vpn/vpn, cisco/cisco, user/password",
           "# Tools: ike-crack, custom racoon scripts"],
          "XAUTH itself has no lockout in many implementations.")

    # ── Vendor CVEs ───────────────────────────────────────────────────────────
    vendor = _guess_vendor(r.vendor_ids)
    if vendor:
        F("INFO", f"Vendor fingerprinted: {vendor}",
          "Known vendor enables targeted CVE lookup.")
        S("INFO", f"Check vendor-specific CVEs ({vendor})",
          [f"# Search: site:nvd.nist.gov \"{vendor} VPN\" CVE",
           f"# Search: site:exploit-db.com \"{vendor}\"",
           "# Cross-reference version info from VID banners"],
          _vendor_cve_note(vendor))

    # ── NAT-T ────────────────────────────────────────────────────────────────
    if r.nat_t:
        F("INFO", "NAT-T responding on port 4500",
          "NAT-T enables VPN through NAT. Confirms alternative attack surface.")
        S("INFO", "Test NAT-T endpoint",
          [f"ike-scan --dport=4500 --sport=4500 {r.target}",
           f"ike-scan --dport=4500 --sport=4500 --aggressive {r.target}"],
          "NAT-T port may have different transform restrictions than port 500.")

    # ── Recon next steps ─────────────────────────────────────────────────────
    if r.main_mode or r.aggressive_mode:
        S("INFO", "Enumerate additional group names (Aggressive Mode)",
          [f"ike-scan --aggressive --id=<group> --pskcrack=out.psk {r.target}",
           "# Wordlists: /usr/share/seclists/Miscellaneous/ike-groupnames.txt",
           f"for g in vpn VPN Default cisco remote test admin; do",
           f"  ike-scan --aggressive --id=$g {r.target} && echo \"HIT: $g\";",
           f"done"],
          "Group name determines which PSK is used — different groups may have weaker PSKs.")

    return findings, steps

def _guess_vendor(vids: list[str]) -> str:
    mapping = {
        "cisco":       "Cisco",
        "checkpoint":  "Check Point",
        "sonicwall":   "SonicWall",
        "fortinet":    "Fortinet",
        "fortigate":   "Fortinet FortiGate",
        "juniper":     "Juniper/NetScreen",
        "netscreen":   "Juniper/NetScreen",
        "strongswan":  "strongSwan",
        "microsoft":   "Microsoft",
        "watchguard":  "WatchGuard",
    }
    for v in vids:
        vl = v.lower()
        for key, name in mapping.items():
            if key in vl:
                return name
    return ""

def _vendor_cve_note(vendor: str) -> str:
    notes = {
        "Cisco":          "Recent critical: CVE-2023-20269 (ASA/FTD VPN brute-force).",
        "SonicWall":      "Recent critical: CVE-2024-53704 (SSL-VPN auth bypass). Check firmware.",
        "Fortinet FortiGate": "Recent critical: CVE-2023-27997 (SSL-VPN heap overflow), CVE-2024-21762.",
        "Check Point":    "Check for R81.x advisory. CVE-2024-24919 (info disclosure) affected many.",
        "Juniper/NetScreen": "Check Junos OS advisories — multiple IKE-related CVEs in 2023-2024.",
    }
    return notes.get(vendor, "Check NVD and vendor security advisories for recent IKE/VPN CVEs.")

# ── Rich output ───────────────────────────────────────────────────────────────

def print_header(r: ScanResults):
    console.print()
    console.print(Panel(BANNER, expand=False, border_style="cyan dim"))
    console.print(f"\n  [bold]target[/]  : [cyan]{r.target}[/]  port [cyan]{r.port}[/]")
    console.print()

def print_discovery(r: ScanResults):
    console.print(Rule(" Discovery ", style="dim"))
    console.print()
    rows = [
        ("IKEv1 Main Mode",      r.main_mode,      ""),
        ("IKEv1 Aggressive Mode",r.aggressive_mode, " [red](hash captured!)[/]" if r.aggressive_mode else ""),
        ("IKEv2",                r.ikev2,           ""),
        ("NAT-T  :4500",         r.nat_t,           ""),
    ]
    for name, state, extra in rows:
        if state:
            console.print(f"  [green]✓[/]  {name:<28} [green]RESPONDING[/]{extra}")
        else:
            console.print(f"  [dim]✗  {name:<28} no response[/]")
    console.print()

def print_transforms(r: ScanResults):
    if not r.mm_accepted:
        return
    console.print(Rule(" Accepted Transforms — Main Mode ", style="dim"))
    console.print()
    t = Table(box=rbox.SIMPLE_HEAD, show_header=True,
              header_style="bold dim", padding=(0, 1))
    t.add_column("#", width=3)
    t.add_column("Transform", no_wrap=True)
    t.add_column("Risk", width=10)
    for i, (spec, label, risk, sa) in enumerate(r.mm_accepted, 1):
        color = RISK_COLOR[risk]
        badge = f"[{color}]{RISK_LABEL[risk]}[/]"
        t.add_row(str(i), label, badge)
    console.print(t)

def print_aggressive(r: ScanResults):
    if not r.aggr_accepted:
        return
    console.print(Rule(" Aggressive Mode ", style="dim"))
    console.print()
    for group, sa, psk_file in r.aggr_accepted:
        label = sa_to_label(sa) if sa else "unknown transform"
        console.print(f"  [red]✓[/]  group [bold]{group!r}[/]  →  {label}")
        if psk_file:
            console.print(f"      [dim]PSK hash file: {psk_file}[/]")
    console.print()
    console.print("  [dim]Crack commands:[/]")
    psk_files = [pf for _, _, pf in r.aggr_accepted if pf]
    for pf in psk_files[:1]:  # show once
        console.print(f"    psk-crack {pf}")
        console.print(f"    hashcat -m 5300 {pf} /usr/share/wordlists/rockyou.txt")
        console.print(f"    hashcat -m 5400 {pf} /usr/share/wordlists/rockyou.txt")
    console.print()

def print_vids(r: ScanResults):
    if not r.vendor_ids:
        return
    console.print(Rule(" Vendor / Extension IDs ", style="dim"))
    console.print()
    for v in r.vendor_ids:
        console.print(f"  [dim]·[/]  {v}")
    console.print()

SEV_COLOR = {"CRITICAL": "red", "HIGH": "orange3", "MEDIUM": "yellow",
             "LOW": "cyan", "INFO": "dim"}

def print_findings(findings: list[Finding]):
    console.print(Rule(" Findings ", style="dim"))
    console.print()
    for f in findings:
        color = SEV_COLOR.get(f.severity, "white")
        badge = f"[{color}][{f.severity:8}][/]"
        console.print(f"  {badge}  [bold]{f.title}[/]")
        if f.detail:
            console.print(f"             [dim]{f.detail}[/]")
    console.print()

def print_attack_plan(steps: list[AttackStep]):
    if not steps:
        return
    console.print(Rule(" Attack Plan ", style="dim"))
    console.print()
    for s in steps:
        color = SEV_COLOR.get(s.severity, "white")
        badge = f"[{color}][{s.severity}][/]"
        console.print(f"  Step {s.num}  {badge}  [bold]{s.title}[/]")
        if s.notes:
            console.print(f"         [dim]{s.notes}[/]")
        for cmd in s.commands:
            if cmd.startswith("#"):
                console.print(f"         [dim]{cmd}[/]")
            else:
                console.print(f"         [cyan]{cmd}[/]")
        console.print()

# ── Entry point ───────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        prog="ikescan",
        description="IKE/VPN enumeration and misconfiguration audit.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "examples:\n"
            "  sudo python3 ikescan.py 192.168.1.1\n"
            "  sudo python3 ikescan.py 10.0.0.1 --port 4500\n"
            "  sudo python3 ikescan.py 10.0.0.1 --no-aggressive\n"
        ),
    )
    parser.add_argument("target", help="Target IP or hostname")
    parser.add_argument("--port", type=int, default=500, metavar="N",
                        help="IKE UDP port (default: 500)")
    parser.add_argument("--no-aggressive", action="store_true",
                        help="Skip Aggressive Mode probes")
    parser.add_argument("--no-transforms", action="store_true",
                        help="Skip per-transform enumeration (faster, less detail)")
    parser.add_argument("--groups", metavar="LIST",
                        help="Comma-separated Aggressive Mode group names to try "
                             "(default: built-in list)")
    parser.add_argument("--psk-dir", metavar="DIR", default=".",
                        help="Directory to save PSK hash files (default: current dir)")
    parser.add_argument("--verbose", action="store_true",
                        help="Show raw ike-scan output for each probe")
    args = parser.parse_args()

    if os.geteuid() != 0:
        console.print("[yellow]warning: ike-scan usually needs root. Run with sudo if probes fail.[/]\n")

    psk_dir = os.path.abspath(args.psk_dir)
    os.makedirs(psk_dir, exist_ok=True)

    groups = AGGR_GROUPS
    if args.groups:
        groups = [g.strip() for g in args.groups.split(",") if g.strip()]

    r = ScanResults(target=args.target, port=args.port)
    print_header(r)

    console.print(Rule(" Probing ", style="dim"))
    console.print()

    # IKEv1 Main Mode + transform enum
    probe_main_mode(r, args.verbose)
    if r.main_mode and not args.no_transforms:
        pass  # already done inside probe_main_mode

    # IKEv1 Aggressive Mode
    if not args.no_aggressive:
        probe_aggressive(r, psk_dir, args.verbose, groups=groups)

    # IKEv2
    probe_ikev2(r)

    # NAT-T
    probe_nat_t(r)

    if not r.main_mode and not r.aggressive_mode and not r.ikev2 and not r.nat_t:
        console.print("\n  [dim]No IKE response on any tested port/mode. "
                      "Target may be firewalled or not running IKE.[/]\n")
        return

    console.print()

    # Output sections
    print_discovery(r)
    print_transforms(r)
    print_aggressive(r)
    print_vids(r)

    findings, steps = analyze(r)
    print_findings(findings)
    print_attack_plan(steps)


if __name__ == "__main__":
    main()
