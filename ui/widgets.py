"""
AEGIS TUI Widgets — reusable terminal UI components.
Uses rich library when available, falls back to plain text.
"""
import sys
import hashlib
from datetime import datetime

try:
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    from rich.text import Text
    from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn
    from rich.prompt import Prompt, Confirm
    from rich.syntax import Syntax
    from rich import box
    HAS_RICH = True
except ImportError:
    HAS_RICH = False

console = Console() if HAS_RICH else None

SEVERITY_COLORS = {
    "CRITICAL": "bright_red",
    "HIGH": "red",
    "MEDIUM": "yellow",
    "LOW": "cyan",
    "INFO": "dim",
}

CLASSIFICATION_COLORS = {
    "TOP SECRET": "bright_red",
    "SECRET": "red",
    "CONFIDENTIAL": "yellow",
    "UNCLASSIFIED": "green",
}

BANNER_ART = r"""
    ___    _______________  _____
   /   |  / ____/ ____/  |/  /  |
  / /| | / __/ / / __/ /|_/ / /| |
 / ___ |/ /___/ /_/ / /  / / ___ |
/_/  |_/_____/\____/_/  /_/_/  |_|

  Autonomous Electronic Governance
  & Intelligence System v1.0
"""


def banner():
    if HAS_RICH:
        console.print(Panel(
            Text(BANNER_ART, style="cyan bold", justify="center"),
            border_style="cyan",
            box=box.DOUBLE,
            padding=(0, 2),
        ))
    else:
        print("=" * 50)
        print(BANNER_ART)
        print("=" * 50)


def classification_banner(level="UNCLASSIFIED"):
    level = level.upper()
    if HAS_RICH:
        color = CLASSIFICATION_COLORS.get(level, "white")
        console.print(Panel(
            Text(f"  {level}  ", style=f"bold {color} on black", justify="center"),
            border_style=color,
            box=box.HEAVY,
            padding=(0, 0),
        ))
    else:
        print(f"{'='*40}")
        print(f"  {level}")
        print(f"{'='*40}")


def findings_table(findings):
    if not findings:
        print_msg("No findings recorded.", "dim")
        return
    if HAS_RICH:
        table = Table(title="Findings", box=box.SIMPLE_HEAVY, border_style="dim",
                      show_lines=True, pad_edge=False)
        table.add_column("#", style="dim", width=4)
        table.add_column("Severity", width=10)
        table.add_column("Title", min_width=30)
        table.add_column("Host", width=16)
        table.add_column("CVE", width=16)
        table.add_column("CVSS", width=5, justify="right")
        table.add_column("MITRE", width=12)
        table.add_column("Status", width=8)
        for i, f in enumerate(findings, 1):
            sev = f.get("severity", "INFO")
            color = SEVERITY_COLORS.get(sev, "white")
            table.add_row(
                str(i),
                f"[{color}]{sev}[/{color}]",
                f.get("title", ""),
                f.get("host", ""),
                f.get("cve", ""),
                str(f.get("cvss", "")),
                f.get("mitre", ""),
                f.get("status", "OPEN"),
            )
        console.print(table)
    else:
        print(f"{'#':<4} {'Severity':<10} {'Title':<35} {'Host':<16} {'CVE':<16}")
        print("-" * 85)
        for i, f in enumerate(findings, 1):
            print(f"{i:<4} {f.get('severity',''):<10} {f.get('title','')[:35]:<35} {f.get('host',''):<16} {f.get('cve',''):<16}")


def action_log(actions, limit=20):
    if not actions:
        print_msg("No actions recorded.", "dim")
        return
    shown = actions[-limit:]
    if HAS_RICH:
        table = Table(title=f"Action Log (last {limit})", box=box.SIMPLE, border_style="dim")
        table.add_column("Time", style="dim", width=22)
        table.add_column("Module", width=14)
        table.add_column("Command", min_width=40)
        table.add_column("Result", width=10)
        for a in shown:
            table.add_row(
                a.get("created", "")[:19],
                a.get("module", ""),
                a.get("command", "")[:60],
                "[green]OK[/green]" if a.get("result") == "success" else a.get("result", "")[:10],
            )
        console.print(table)
    else:
        for a in shown:
            print(f"  [{a.get('created','')[:19]}] [{a.get('module','')}] {a.get('command','')[:60]}")


def ioc_table(iocs):
    if not iocs:
        print_msg("No IOCs recorded.", "dim")
        return
    if HAS_RICH:
        table = Table(title="Indicators of Compromise", box=box.SIMPLE_HEAVY, border_style="dim")
        table.add_column("Type", width=12)
        table.add_column("Value", min_width=30)
        table.add_column("Confidence", width=12)
        table.add_column("Context", min_width=20)
        for ioc in iocs:
            conf = ioc.get("confidence", "medium")
            conf_color = {"high": "red", "medium": "yellow", "low": "cyan"}.get(conf, "white")
            table.add_row(
                ioc.get("ioc_type", ""),
                ioc.get("value", ""),
                f"[{conf_color}]{conf}[/{conf_color}]",
                ioc.get("context", ""),
            )
        console.print(table)
    else:
        for ioc in iocs:
            print(f"  [{ioc.get('ioc_type','')}] {ioc.get('value','')} ({ioc.get('confidence','')})")


def credential_table(creds):
    if not creds:
        print_msg("No credentials recorded.", "dim")
        return
    if HAS_RICH:
        table = Table(title="Credentials Obtained", box=box.SIMPLE_HEAVY, border_style="dim")
        table.add_column("Service", width=12)
        table.add_column("Host", width=16)
        table.add_column("Username", width=16)
        table.add_column("Type", width=12)
        table.add_column("Source", width=16)
        for c in creds:
            table.add_row(
                c.get("service", ""), c.get("host", ""), c.get("username", ""),
                c.get("credential_type", ""), c.get("source", ""),
            )
        console.print(table)
    else:
        for c in creds:
            print(f"  {c.get('service','')}://{c.get('username','')}@{c.get('host','')}")


def status_bar(stats, mission=None):
    if HAS_RICH:
        parts = []
        if mission:
            parts.append(f"[bold cyan]Mission:[/bold cyan] {mission.name}")
            parts.append(f"[bold]Target:[/bold] {mission.target}")
            parts.append(f"[bold]Status:[/bold] {mission.status}")
        sev_parts = []
        for sev in ["critical", "high", "medium", "low", "info"]:
            count = stats.get(sev, 0)
            color = SEVERITY_COLORS.get(sev.upper(), "white")
            sev_parts.append(f"[{color}]{count} {sev.upper()}[/{color}]")
        parts.append("Findings: " + " | ".join(sev_parts))
        parts.append(f"Actions: {stats.get('actions', 0)} | IOCs: {stats.get('iocs', 0)} | Creds: {stats.get('credentials', 0)}")
        console.print(Panel("\n".join(parts), border_style="dim", box=box.ROUNDED))
    else:
        if mission:
            print(f"  Mission: {mission.name} | Target: {mission.target} | Status: {mission.status}")
        print(f"  Findings: {stats.get('critical',0)}C {stats.get('high',0)}H {stats.get('medium',0)}M {stats.get('low',0)}L {stats.get('info',0)}I")
        print(f"  Actions: {stats.get('actions',0)} | IOCs: {stats.get('iocs',0)} | Creds: {stats.get('credentials',0)}")


def confirm(prompt_text, audit_log=None):
    if HAS_RICH:
        result = Confirm.ask(f"[yellow]{prompt_text}[/yellow]")
    else:
        resp = input(f"{prompt_text} [y/n]: ").strip().lower()
        result = resp in ("y", "yes")
    if audit_log is not None:
        audit_log.append({
            "time": datetime.utcnow().isoformat() + "Z",
            "prompt": prompt_text,
            "response": "approved" if result else "denied",
        })
    return result


def prompt(text, default=""):
    if HAS_RICH:
        return Prompt.ask(f"[cyan]{text}[/cyan]", default=default)
    else:
        val = input(f"{text} [{default}]: ").strip()
        return val if val else default


def print_msg(text, style=""):
    if HAS_RICH:
        console.print(f"[{style}]{text}[/{style}]" if style else text)
    else:
        print(text)


def print_success(text):
    print_msg(f"[+] {text}", "green")


def print_error(text):
    print_msg(f"[-] {text}", "red")


def print_warning(text):
    print_msg(f"[!] {text}", "yellow")


def print_info(text):
    print_msg(f"[*] {text}", "cyan")


def severity_color(severity):
    return SEVERITY_COLORS.get(severity.upper(), "white")


def show_code(code, language="bash"):
    if HAS_RICH:
        console.print(Syntax(code, language, theme="monokai", line_numbers=False, padding=1))
    else:
        print(f"  {code}")


def clear():
    import os
    os.system("cls" if os.name == "nt" else "clear")
