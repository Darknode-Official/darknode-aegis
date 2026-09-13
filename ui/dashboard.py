#!/usr/bin/env python3
"""
AEGIS Operations Dashboard — the main TUI interface.
Provides mission management, module execution, and real-time status.
"""
import sys
import os
import traceback

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

try:
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    from rich.text import Text
    from rich.columns import Columns
    from rich import box
    HAS_RICH = True
    console = Console()
except ImportError:
    HAS_RICH = False
    console = None

from core.db import MissionDB
from ui.widgets import (
    banner, classification_banner, findings_table, action_log, ioc_table,
    credential_table, status_bar, confirm, prompt, print_msg, print_success,
    print_error, print_warning, print_info, show_code, clear, severity_color,
)

# Lazy import to avoid circular
_engine_mod = None
def get_engine_class():
    global _engine_mod
    if not _engine_mod:
        from core import __init__  # noqa
        # Manual import to avoid naming issues with hyphenated filename
        import importlib.util
        spec = importlib.util.spec_from_file_location(
            "aegis_engine",
            os.path.join(os.path.dirname(__file__), "..", "core", "aegis-engine.py")
        )
        _engine_mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(_engine_mod)
    return _engine_mod.AegisEngine, _engine_mod.MODULES, _engine_mod.DOMAIN_NAMES


DOMAIN_KEYS = ["recon", "vuln", "exploit", "intel", "defense", "crypto", "network", "ai", "reporting"]
DOMAIN_NUMBERS = {str(i+1): k for i, k in enumerate(DOMAIN_KEYS)}
DOMAIN_NUMBERS["0"] = "mission_board"


def main():
    clear()
    banner()
    print()

    AegisEngine, MODULES, DOMAIN_NAMES = get_engine_class()
    engine = AegisEngine()

    print_info("AEGIS Cyber Operations Platform initialized.")
    print_info(f"Database: {engine.db.db_path}")
    print_info(f"Classification: {engine.config.get('classification', 'UNCLASSIFIED')}")
    print()

    # Check for existing missions
    missions = engine.list_missions()
    active = [m for m in missions if m.status == "ACTIVE"]
    if active:
        print_info(f"Found {len(active)} active mission(s).")
        if len(active) == 1 and confirm(f"Resume mission '{active[0].name}'?"):
            engine.load_mission(active[0].id)
        else:
            print_info("Use the Mission Board [0] to manage missions.")
    else:
        print_info("No active missions. Create one with [m].")

    print()
    main_loop(engine, MODULES, DOMAIN_NAMES)
    engine.close()


def main_loop(engine, MODULES, DOMAIN_NAMES):
    while True:
        try:
            show_main_menu(engine, MODULES, DOMAIN_NAMES)
            choice = prompt("\nAEGIS").strip().lower()

            if choice == "q":
                if confirm("Exit AEGIS?"):
                    print_info("AEGIS shutting down. Stay safe.")
                    break
            elif choice == "m":
                create_mission_inline(engine)
            elif choice == "l":
                load_mission_inline(engine)
            elif choice == "s":
                show_status(engine)
            elif choice == "f":
                show_findings(engine)
            elif choice == "a":
                show_actions(engine)
            elif choice == "i":
                show_iocs(engine)
            elif choice == "k":
                show_credentials(engine)
            elif choice == "r":
                generate_report(engine)
            elif choice == "0":
                from ui import __init__  # noqa
                import importlib.util
                spec = importlib.util.spec_from_file_location(
                    "mission_board",
                    os.path.join(os.path.dirname(__file__), "mission-board.py")
                )
                mb = importlib.util.module_from_spec(spec)
                spec.loader.exec_module(mb)
                mb.show_mission_board(engine)
            elif choice in DOMAIN_NUMBERS and choice != "0":
                domain = DOMAIN_NUMBERS[choice]
                run_domain_menu(engine, domain, MODULES, DOMAIN_NAMES)
            else:
                print_error(f"Unknown command: '{choice}'")

        except KeyboardInterrupt:
            print()
            print_warning("Ctrl+C pressed. Use 'q' to quit.")
        except Exception as e:
            print_error(f"Error: {e}")
            if confirm("Show traceback?"):
                traceback.print_exc()


def show_main_menu(engine, MODULES, DOMAIN_NAMES):
    clear()
    classification = engine.config.get("classification", "UNCLASSIFIED")

    if HAS_RICH:
        header_parts = [
            f"[bold cyan]AEGIS v1.0[/bold cyan] -- Cyber Operations Platform",
        ]
        cls_color = {"TOP SECRET": "bright_red", "SECRET": "red", "CONFIDENTIAL": "yellow"}.get(classification, "green")
        header_parts.append(f"  [{cls_color}][{classification}][/{cls_color}]")

        console.print(Panel(
            "  ".join(header_parts),
            border_style="cyan",
            box=box.DOUBLE,
        ))

        if engine.current_mission:
            m = engine.current_mission
            stats = engine.get_stats()
            console.print(Panel(
                f"[bold]Mission:[/bold] {m.name}  |  "
                f"[bold]Target:[/bold] {m.target}  |  "
                f"[bold]Status:[/bold] [green]{m.status}[/green]  |  "
                f"[bold]ID:[/bold] [dim]{m.id}[/dim]",
                border_style="dim",
                box=box.ROUNDED,
            ))
            status_bar(stats, m)
        else:
            console.print(Panel(
                "[yellow]No active mission. Press [m] to create one or [0] for Mission Board.[/yellow]",
                border_style="yellow",
                box=box.ROUNDED,
            ))

        print()
        # Domain menu in two columns
        left = []
        right = []
        for i, domain in enumerate(DOMAIN_KEYS):
            label = DOMAIN_NAMES.get(domain, domain.title())
            entry = f"  [cyan][{i+1}][/cyan] {label}"
            if i < 5:
                left.append(entry)
            else:
                right.append(entry)
        while len(right) < len(left):
            right.append("")

        for l, r in zip(left, right):
            lpad = l + " " * max(0, 35 - len(l.replace("[cyan]", "").replace("[/cyan]", "")))
            console.print(f"{lpad}{r}")

        print()
        console.print("  [cyan][0][/cyan] Mission Board    [cyan][m][/cyan] New Mission    [cyan][l][/cyan] Load Mission")
        console.print("  [cyan][s][/cyan] Status           [cyan][f][/cyan] Findings       [cyan][a][/cyan] Actions")
        console.print("  [cyan][i][/cyan] IOCs             [cyan][k][/cyan] Credentials    [cyan][r][/cyan] Report")
        console.print("  [cyan][q][/cyan] Quit")
    else:
        print(f"  AEGIS v1.0 -- Cyber Operations Platform  [{classification}]")
        print()
        if engine.current_mission:
            m = engine.current_mission
            print(f"  Mission: {m.name} | Target: {m.target} | Status: {m.status}")
            stats = engine.get_stats()
            status_bar(stats, m)
        else:
            print("  No active mission. Press [m] to create one.")
        print()
        for i, domain in enumerate(DOMAIN_KEYS):
            print(f"  [{i+1}] {DOMAIN_NAMES.get(domain, domain.title())}")
        print()
        print("  [0] Mission Board  [m] New Mission  [l] Load  [s] Status")
        print("  [f] Findings  [a] Actions  [i] IOCs  [k] Creds  [r] Report  [q] Quit")


def run_domain_menu(engine, domain, MODULES, DOMAIN_NAMES):
    if not engine.current_mission:
        print_warning("Create or load a mission first.")
        prompt("Press Enter")
        return

    domain_mods = MODULES.get(domain, {})
    domain_name = DOMAIN_NAMES.get(domain, domain.title())

    while True:
        clear()
        if HAS_RICH:
            console.print(Panel(
                f"[bold cyan]{domain_name}[/bold cyan]\n"
                f"Mission: {engine.current_mission.name} | Target: {engine.current_mission.target}",
                border_style="cyan", box=box.DOUBLE,
            ))
        else:
            print(f"\n  === {domain_name} ===")
            print(f"  Mission: {engine.current_mission.name} | Target: {engine.current_mission.target}")

        print()
        mod_keys = list(domain_mods.keys())
        for i, key in enumerate(mod_keys, 1):
            mod = domain_mods[key]
            risk_badge = {"passive": "[green]PASSIVE[/green]", "active": "[yellow]ACTIVE[/yellow]", "exploit": "[red]EXPLOIT[/red]"}.get(mod["risk"], mod["risk"]) if HAS_RICH else f"[{mod['risk'].upper()}]"
            tools_available = engine.check_module_tools(domain, key)
            tool_str = ""
            if mod.get("tools"):
                tool_parts = []
                for t in mod["tools"]:
                    avail = tools_available.get(t, False)
                    if HAS_RICH:
                        tool_parts.append(f"[green]{t}[/green]" if avail else f"[red]{t}[/red]")
                    else:
                        tool_parts.append(f"{t}({'Y' if avail else 'N'})")
                tool_str = " | Tools: " + ", ".join(tool_parts)

            if HAS_RICH:
                console.print(f"  [cyan][{i}][/cyan] {mod['name']} {risk_badge}")
                console.print(f"      [dim]{mod['desc']}{tool_str}[/dim]")
            else:
                print(f"  [{i}] {mod['name']} [{mod['risk'].upper()}]")
                print(f"      {mod['desc']}{tool_str}")

        print()
        print_msg("  [b] Back to main menu")
        print()

        choice = prompt(f"AEGIS/{domain}").strip().lower()

        if choice == "b":
            return

        try:
            idx = int(choice) - 1
            if 0 <= idx < len(mod_keys):
                run_module(engine, domain, mod_keys[idx], domain_mods[mod_keys[idx]])
            else:
                print_error("Invalid number.")
                prompt("Press Enter")
        except ValueError:
            print_error(f"Unknown command: '{choice}'")
            prompt("Press Enter")


def run_module(engine, domain, mod_key, mod_info):
    clear()
    if HAS_RICH:
        console.print(Panel(
            f"[bold cyan]{mod_info['name']}[/bold cyan]\n{mod_info['desc']}",
            border_style="cyan",
        ))
    else:
        print(f"\n  === {mod_info['name']} ===")
        print(f"  {mod_info['desc']}")

    risk = mod_info.get("risk", "passive")
    if risk == "exploit":
        print()
        print_warning("WARNING: This module performs EXPLOITATION actions.")
        print_warning("Ensure you have WRITTEN AUTHORIZATION for the target.")
        if not confirm("Do you have written authorization to proceed?"):
            print_info("Module cancelled.")
            prompt("Press Enter")
            return
    elif risk == "active":
        print()
        print_warning("This module performs ACTIVE scanning against the target.")
        if engine.config.get("modules", {}).get("confirm_before_active", True):
            if not confirm("Proceed with active scanning?"):
                print_info("Module cancelled.")
                prompt("Press Enter")
                return

    # Module-specific logic
    target = engine.current_mission.target
    module_path = os.path.join(engine.base_dir, "modules", domain, f"{mod_key}.py")

    if os.path.exists(module_path):
        print_info(f"Executing module: {mod_key}")
        print_info(f"Target: {target}")
        print()

        # Load and execute the module
        try:
            import importlib.util
            spec = importlib.util.spec_from_file_location(mod_key.replace("-", "_"), module_path)
            mod = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(mod)
            if hasattr(mod, "run"):
                result = mod.run(engine, target)
                if result:
                    print_success(f"Module completed. {len(result.findings)} finding(s).")
                else:
                    print_info("Module completed.")
            else:
                print_warning(f"Module {mod_key} has no run() function.")
        except Exception as e:
            print_error(f"Module error: {e}")
            if confirm("Show traceback?"):
                traceback.print_exc()
    else:
        print_warning(f"Module file not found: {module_path}")
        print_info("Running in interactive mode...")
        print()
        run_interactive_module(engine, domain, mod_key, mod_info, target)

    prompt("\nPress Enter to continue")


def run_interactive_module(engine, domain, mod_key, mod_info, target):
    """Fallback interactive mode when module file doesn't exist yet."""
    commands = get_suggested_commands(domain, mod_key, target)
    if not commands:
        print_info("No predefined commands for this module. Enter commands manually.")
        while True:
            cmd = prompt("Command (or 'done')")
            if cmd.lower() in ("done", "exit", "quit", ""):
                break
            print()
            show_code(cmd)
            if confirm(f"Execute this command?"):
                result = engine.run_command(cmd)
                engine.log_action(cmd, result.output[:2000], "success" if result.success else "failed", f"{domain}/{mod_key}")
                if result.output:
                    if HAS_RICH:
                        console.print(Panel(result.output[:3000], title="Output", border_style="dim"))
                    else:
                        print(result.output[:3000])
        return

    print_info(f"Suggested commands for {mod_info['name']}:")
    print()
    for i, (desc, cmd) in enumerate(commands, 1):
        if HAS_RICH:
            console.print(f"  [cyan][{i}][/cyan] {desc}")
            console.print(f"      [dim]{cmd}[/dim]")
        else:
            print(f"  [{i}] {desc}")
            print(f"      {cmd}")
    print()
    print_msg("  [a] Run all  [c] Custom command  [d] Done")
    print()

    while True:
        choice = prompt(f"AEGIS/{domain}/{mod_key}").strip().lower()
        if choice in ("d", "done", ""):
            break
        elif choice == "c":
            cmd = prompt("Enter command")
            if cmd and confirm(f"Execute: {cmd}?"):
                result = engine.run_command(cmd)
                engine.log_action(cmd, result.output[:2000], "success" if result.success else "failed", f"{domain}/{mod_key}")
                print(result.output[:3000] if result.output else "(no output)")
        elif choice == "a":
            for desc, cmd in commands:
                print()
                print_info(desc)
                show_code(cmd)
                if confirm("Execute?"):
                    result = engine.run_command(cmd)
                    engine.log_action(cmd, result.output[:2000], "success" if result.success else "failed", f"{domain}/{mod_key}")
                    if result.output:
                        print(result.output[:2000])
        else:
            try:
                idx = int(choice) - 1
                if 0 <= idx < len(commands):
                    desc, cmd = commands[idx]
                    print()
                    show_code(cmd)
                    if confirm("Execute?"):
                        result = engine.run_command(cmd)
                        engine.log_action(cmd, result.output[:2000], "success" if result.success else "failed", f"{domain}/{mod_key}")
                        if result.output:
                            print(result.output[:3000])
                else:
                    print_error("Invalid number.")
            except ValueError:
                print_error(f"Unknown: '{choice}'")


def get_suggested_commands(domain, mod_key, target):
    """Return list of (description, command) tuples for common operations."""
    t = target
    commands = {
        ("recon", "passive-recon"): [
            ("WHOIS lookup", f"whois {t}"),
            ("DNS records (ALL)", f"dig {t} ANY +noall +answer"),
            ("DNS A records", f"dig {t} A +short"),
            ("DNS MX records", f"dig {t} MX +short"),
            ("DNS TXT records (SPF/DKIM/DMARC)", f"dig {t} TXT +short"),
            ("DNS NS records", f"dig {t} NS +short"),
            ("Reverse DNS", f"dig -x {t} +short"),
            ("Zone transfer attempt", f"dig @$(dig {t} NS +short | head -1) {t} AXFR"),
            ("Certificate Transparency (crt.sh)", f"curl -s 'https://crt.sh/?q=%25.{t}&output=json' | python3 -m json.tool | head -100"),
        ],
        ("recon", "active-recon"): [
            ("Quick port scan (top 1000)", f"nmap -sV --top-ports 1000 -T4 {t}"),
            ("Full port scan", f"nmap -sV -p- -T4 {t}"),
            ("OS detection", f"sudo nmap -O {t}"),
            ("Aggressive scan (scripts + OS + versions)", f"nmap -A -T4 {t}"),
            ("UDP scan (top 20)", f"sudo nmap -sU --top-ports 20 -T4 {t}"),
            ("Service version detection", f"nmap -sV --version-intensity 5 {t}"),
            ("Vuln scan scripts", f"nmap --script vuln {t}"),
        ],
        ("recon", "web-recon"): [
            ("HTTP headers", f"curl -sI https://{t}"),
            ("Security headers check", f"curl -sI https://{t} | grep -iE 'strict-transport|content-security|x-frame|x-content-type|referrer-policy|permissions-policy'"),
            ("Web technology fingerprint", f"whatweb https://{t}"),
            ("Directory brute force", f"gobuster dir -u https://{t} -w /usr/share/wordlists/dirb/common.txt -t 50"),
            ("Robots.txt", f"curl -s https://{t}/robots.txt"),
            ("Sitemap", f"curl -s https://{t}/sitemap.xml | head -50"),
        ],
        ("vuln", "vuln-scanner"): [
            ("Nmap vuln scripts", f"nmap --script vuln -sV {t}"),
            ("Nmap safe scripts", f"nmap --script safe -sV {t}"),
            ("Search for exploits", f"searchsploit {t}"),
        ],
        ("vuln", "web-audit"): [
            ("Nikto web scan", f"nikto -h https://{t}"),
            ("SQLMap test (GET parameter)", f"sqlmap -u 'https://{t}/?id=1' --batch --level=3 --risk=2"),
        ],
        ("vuln", "crypto-audit"): [
            ("SSL/TLS scan", f"sslscan {t}"),
            ("SSL certificate details", f"echo | openssl s_client -connect {t}:443 -servername {t} 2>/dev/null | openssl x509 -noout -text"),
            ("Test for SSLv3 (POODLE)", f"openssl s_client -ssl3 -connect {t}:443 2>&1 | head -5"),
            ("Test for TLS 1.0", f"openssl s_client -tls1 -connect {t}:443 2>&1 | head -5"),
        ],
        ("network", "traffic-analysis"): [
            ("Capture packets (10 seconds)", f"sudo timeout 10 tcpdump -i any host {t} -w /tmp/aegis-capture.pcap"),
            ("Analyze capture", f"tshark -r /tmp/aegis-capture.pcap -q -z conv,ip"),
            ("DNS queries in capture", f"tshark -r /tmp/aegis-capture.pcap -Y dns -T fields -e dns.qry.name | sort -u"),
        ],
        ("crypto", "crypto-suite"): [
            ("Generate RSA key pair", "openssl genrsa -out /tmp/aegis-key.pem 4096"),
            ("Generate self-signed cert", f"openssl req -new -x509 -key /tmp/aegis-key.pem -out /tmp/aegis-cert.pem -days 365 -subj '/CN={t}'"),
            ("Hash a file (SHA256)", "sha256sum <file>"),
        ],
    }
    return commands.get((domain, mod_key), [])


def create_mission_inline(engine):
    print()
    name = prompt("Mission name")
    if not name:
        return
    target = prompt("Target (IP/domain)")
    if not target:
        return
    scope = prompt("Scope", "Full scope")
    mission = engine.create_mission(name, target, scope)
    print_success(f"Mission created: {mission.id}")
    classification_banner(mission.classification)
    prompt("Press Enter")


def load_mission_inline(engine):
    missions = engine.list_missions()
    if not missions:
        print_warning("No missions found.")
        prompt("Press Enter")
        return
    for i, m in enumerate(missions, 1):
        print(f"  [{i}] {m.name} ({m.target}) [{m.status}]")
    choice = prompt("Mission number")
    try:
        idx = int(choice) - 1
        if 0 <= idx < len(missions):
            engine.load_mission(missions[idx].id)
            print_success(f"Loaded: {missions[idx].name}")
        else:
            print_error("Invalid.")
    except ValueError:
        print_error("Enter a number.")
    prompt("Press Enter")


def show_status(engine):
    clear()
    if not engine.current_mission:
        print_warning("No active mission.")
        prompt("Press Enter")
        return
    stats = engine.get_stats()
    status_bar(stats, engine.current_mission)
    print()
    prompt("Press Enter")


def show_findings(engine):
    clear()
    if not engine.current_mission:
        print_warning("No active mission.")
        prompt("Press Enter")
        return
    findings = engine.get_findings()
    findings_table(findings)
    print()
    prompt("Press Enter")


def show_actions(engine):
    clear()
    if not engine.current_mission:
        print_warning("No active mission.")
        prompt("Press Enter")
        return
    actions = engine.get_actions()
    action_log(actions, limit=50)
    print()
    prompt("Press Enter")


def show_iocs(engine):
    clear()
    if not engine.current_mission:
        print_warning("No active mission.")
        prompt("Press Enter")
        return
    iocs = engine.get_iocs()
    ioc_table(iocs)
    print()
    prompt("Press Enter")


def show_credentials(engine):
    clear()
    if not engine.current_mission:
        print_warning("No active mission.")
        prompt("Press Enter")
        return
    creds = engine.get_credentials()
    credential_table(creds)
    print()
    prompt("Press Enter")


def generate_report(engine):
    clear()
    if not engine.current_mission:
        print_warning("No active mission.")
        prompt("Press Enter")
        return
    print_info("Generating engagement report...")
    report = engine.generate_report()
    if report:
        print_success("Report generated successfully.")
        print()
        if HAS_RICH:
            from rich.markdown import Markdown
            console.print(Markdown(report[:5000]))
        else:
            print(report[:5000])
        if len(report) > 5000:
            print_info(f"(Report truncated in display. Full report saved to missions/{engine.current_mission.id}/reports/)")
    prompt("\nPress Enter")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n")
        print_info("AEGIS terminated.")
        sys.exit(0)
