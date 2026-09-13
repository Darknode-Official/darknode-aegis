"""
AEGIS Mission Board — create, list, load, archive, and compare missions.
"""
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

try:
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    from rich import box
    HAS_RICH = True
    console = Console()
except ImportError:
    HAS_RICH = False
    console = None

from ui.widgets import (
    banner, classification_banner, confirm, prompt, print_msg,
    print_success, print_error, print_warning, print_info, clear, status_bar,
)
from core.db import MissionDB


def show_mission_board(engine):
    while True:
        clear()
        if HAS_RICH:
            console.print(Panel(
                "[bold cyan]AEGIS Mission Board[/bold cyan]\n"
                "Manage operations, create new missions, review past engagements.",
                border_style="cyan", box=box.DOUBLE,
            ))
        else:
            print("=" * 50)
            print("  AEGIS Mission Board")
            print("=" * 50)
        print()

        missions = engine.list_missions()

        if missions:
            if HAS_RICH:
                table = Table(title=f"Missions ({len(missions)})", box=box.SIMPLE_HEAVY, border_style="dim")
                table.add_column("#", style="dim", width=4)
                table.add_column("ID", width=20)
                table.add_column("Name", min_width=20)
                table.add_column("Target", width=20)
                table.add_column("Status", width=12)
                table.add_column("Class", width=14)
                table.add_column("Created", width=12)
                table.add_column("Findings", width=10, justify="right")
                for i, m in enumerate(missions, 1):
                    stats = engine.db.get_stats(m.id)
                    status_color = {"ACTIVE": "green", "COMPLETE": "blue", "ARCHIVED": "dim"}.get(m.status, "white")
                    table.add_row(
                        str(i), m.id, m.name, m.target,
                        f"[{status_color}]{m.status}[/{status_color}]",
                        m.classification, m.created[:10],
                        str(stats.get("total_findings", 0)),
                    )
                console.print(table)
            else:
                print(f"{'#':<4} {'ID':<20} {'Name':<20} {'Target':<20} {'Status':<12}")
                print("-" * 80)
                for i, m in enumerate(missions, 1):
                    print(f"{i:<4} {m.id:<20} {m.name:<20} {m.target:<20} {m.status:<12}")
        else:
            print_warning("No missions found. Create one to get started.")

        print()
        print("  [n] New Mission    [l] Load Mission    [a] Archive Mission")
        print("  [c] Compare        [d] Delete Mission  [b] Back")
        print()

        choice = prompt("Select").strip().lower()

        if choice == "n":
            create_mission_wizard(engine)
        elif choice == "l":
            if not missions:
                print_warning("No missions to load.")
                prompt("Press Enter to continue")
                continue
            idx = prompt("Mission number to load")
            try:
                idx = int(idx) - 1
                if 0 <= idx < len(missions):
                    engine.load_mission(missions[idx].id)
                    print_success(f"Mission '{missions[idx].name}' loaded.")
                    prompt("Press Enter to continue")
                    return
                else:
                    print_error("Invalid number.")
            except ValueError:
                print_error("Enter a number.")
            prompt("Press Enter to continue")
        elif choice == "a":
            if not missions:
                print_warning("No missions to archive.")
                prompt("Press Enter to continue")
                continue
            idx = prompt("Mission number to archive")
            try:
                idx = int(idx) - 1
                if 0 <= idx < len(missions):
                    engine.db.update_mission_status(missions[idx].id, "ARCHIVED")
                    print_success(f"Mission '{missions[idx].name}' archived.")
                else:
                    print_error("Invalid number.")
            except ValueError:
                print_error("Enter a number.")
            prompt("Press Enter to continue")
        elif choice == "c":
            compare_missions(engine, missions)
        elif choice == "d":
            if not missions:
                print_warning("No missions to delete.")
                prompt("Press Enter to continue")
                continue
            idx = prompt("Mission number to delete")
            try:
                idx = int(idx) - 1
                if 0 <= idx < len(missions):
                    if confirm(f"Delete mission '{missions[idx].name}'? This cannot be undone."):
                        engine.db.conn.execute("DELETE FROM findings WHERE mission_id=?", (missions[idx].id,))
                        engine.db.conn.execute("DELETE FROM actions WHERE mission_id=?", (missions[idx].id,))
                        engine.db.conn.execute("DELETE FROM iocs WHERE mission_id=?", (missions[idx].id,))
                        engine.db.conn.execute("DELETE FROM credentials WHERE mission_id=?", (missions[idx].id,))
                        engine.db.conn.execute("DELETE FROM evidence WHERE mission_id=?", (missions[idx].id,))
                        engine.db.conn.execute("DELETE FROM missions WHERE id=?", (missions[idx].id,))
                        engine.db.conn.commit()
                        print_success("Mission deleted.")
                else:
                    print_error("Invalid number.")
            except ValueError:
                print_error("Enter a number.")
            prompt("Press Enter to continue")
        elif choice == "b":
            return
        else:
            print_error("Unknown option.")
            prompt("Press Enter to continue")


def create_mission_wizard(engine):
    print()
    print_info("--- New Mission Setup ---")
    print()
    name = prompt("Mission name (e.g., 'Q4 External Pentest')")
    if not name:
        print_error("Mission name is required.")
        prompt("Press Enter to continue")
        return
    target = prompt("Primary target (IP, domain, or CIDR)")
    if not target:
        print_error("Target is required.")
        prompt("Press Enter to continue")
        return
    scope = prompt("Scope description (optional)", "")
    print()
    print("  Classification levels:")
    print("  [1] UNCLASSIFIED")
    print("  [2] CONFIDENTIAL")
    print("  [3] SECRET")
    print("  [4] TOP SECRET")
    cls_choice = prompt("Classification", "1")
    classification = {"1": "UNCLASSIFIED", "2": "CONFIDENTIAL", "3": "SECRET", "4": "TOP SECRET"}.get(cls_choice, "UNCLASSIFIED")

    print()
    print_info(f"Creating mission: {name}")
    print_info(f"Target: {target}")
    print_info(f"Scope: {scope or 'Full scope'}")
    print_info(f"Classification: {classification}")
    print()

    if confirm("Create this mission?"):
        mission = engine.create_mission(name, target, scope, classification)
        print_success(f"Mission created: {mission.id}")
        classification_banner(classification)
    else:
        print_warning("Mission creation cancelled.")

    prompt("Press Enter to continue")


def compare_missions(engine, missions):
    if len(missions) < 2:
        print_warning("Need at least 2 missions to compare.")
        prompt("Press Enter to continue")
        return
    print()
    a_idx = prompt("First mission number")
    b_idx = prompt("Second mission number")
    try:
        a_idx = int(a_idx) - 1
        b_idx = int(b_idx) - 1
        if not (0 <= a_idx < len(missions) and 0 <= b_idx < len(missions)):
            print_error("Invalid numbers.")
            prompt("Press Enter to continue")
            return
    except ValueError:
        print_error("Enter numbers.")
        prompt("Press Enter to continue")
        return

    m_a, m_b = missions[a_idx], missions[b_idx]
    s_a = engine.db.get_stats(m_a.id)
    s_b = engine.db.get_stats(m_b.id)

    if HAS_RICH:
        table = Table(title="Mission Comparison", box=box.DOUBLE, border_style="cyan")
        table.add_column("Metric", min_width=20)
        table.add_column(m_a.name, min_width=15, justify="right")
        table.add_column(m_b.name, min_width=15, justify="right")
        for key in ["critical", "high", "medium", "low", "info", "total_findings", "actions", "iocs", "credentials"]:
            label = key.replace("_", " ").title()
            va, vb = s_a.get(key, 0), s_b.get(key, 0)
            table.add_row(label, str(va), str(vb))
        console.print(table)
    else:
        print(f"{'Metric':<20} {m_a.name:<15} {m_b.name:<15}")
        print("-" * 50)
        for key in ["critical", "high", "medium", "low", "info", "total_findings", "actions", "iocs", "credentials"]:
            print(f"{key:<20} {s_a.get(key,0):<15} {s_b.get(key,0):<15}")

    prompt("\nPress Enter to continue")
