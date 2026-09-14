#!/usr/bin/env python3
"""
AEGIS Threat Intelligence Platform
====================================
STIX/TAXII feed management, IOC lifecycle, threat actor profiling,
campaign tracking, Diamond Model analysis, and intelligence reporting.

EDUCATIONAL USE ONLY - All operations are simulated for training purposes.
"""

import os
import sys
import json
import uuid
import random
import hashlib
import datetime
import argparse
from collections import defaultdict

try:
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn
    from rich.tree import Tree
    from rich.text import Text
    from rich.syntax import Syntax
except ImportError:
    print("[!] rich library required: pip install rich")
    sys.exit(1)

console = Console()

# ─── STIX Object Type Definitions ──────────────────────────────────────
STIX_OBJECT_TYPES = {
    "attack-pattern": {
        "description": "A type of TTP describing attacker behavior",
        "properties": ["name", "description", "kill_chain_phases", "external_references"],
    },
    "campaign": {
        "description": "A grouping of adversarial behaviors and resources",
        "properties": ["name", "description", "first_seen", "last_seen", "objective"],
    },
    "course-of-action": {
        "description": "Recommended response or mitigation for an attack pattern",
        "properties": ["name", "description", "action_type"],
    },
    "identity": {
        "description": "Individuals, organizations, or groups",
        "properties": ["name", "identity_class", "sectors", "contact_information"],
    },
    "indicator": {
        "description": "Pattern used to detect suspicious activity",
        "properties": ["name", "pattern", "pattern_type", "valid_from", "valid_until"],
    },
    "intrusion-set": {
        "description": "A grouped set of adversarial behaviors (threat actor campaigns)",
        "properties": ["name", "description", "first_seen", "goals", "resource_level"],
    },
    "malware": {
        "description": "Malicious code or software used by threat actors",
        "properties": ["name", "description", "malware_types", "is_family", "capabilities"],
    },
    "threat-actor": {
        "description": "An individual, group, or organization operating with malicious intent",
        "properties": ["name", "description", "threat_actor_types", "roles", "sophistication"],
    },
    "tool": {
        "description": "Legitimate software that can be misused by threat actors",
        "properties": ["name", "description", "tool_types"],
    },
    "vulnerability": {
        "description": "A flaw or weakness in software that can be exploited",
        "properties": ["name", "description", "external_references"],
    },
    "relationship": {
        "description": "Links between STIX objects",
        "properties": ["relationship_type", "source_ref", "target_ref"],
    },
    "sighting": {
        "description": "Records when an indicator/malware was observed",
        "properties": ["first_seen", "last_seen", "count", "sighting_of_ref"],
    },
}

# ─── Threat Actor Database ─────────────────────────────────────────────
THREAT_ACTORS = {
    "APT29": {
        "name": "Cozy Bear",
        "type": "nation-state",
        "country": "Russia",
        "attribution_confidence": "HIGH",
        "active_since": "2008",
        "sophistication": "expert",
        "resource_level": "government",
        "primary_motivation": "espionage",
        "targets": ["Government", "Think Tanks", "Healthcare", "Energy", "Technology"],
        "tools": ["Cobalt Strike", "SunBurst", "EnvyScout", "BoomBox", "NativeZone", "FoggyWeb"],
        "ttps": {
            "initial_access": ["T1566.001", "T1195.002", "T1190"],
            "execution": ["T1059.001", "T1047"],
            "persistence": ["T1547.001", "T1546.003"],
            "credential_access": ["T1003.001", "T1558.003"],
            "lateral_movement": ["T1021.002", "T1021.006"],
            "exfiltration": ["T1041", "T1048.003"],
        },
        "campaigns": [
            {"name": "SolarWinds", "year": 2020, "targets": "US Government, Technology",
             "description": "Supply chain attack via SolarWinds Orion software update"},
            {"name": "COVID-19 Vaccine Research", "year": 2020, "targets": "Healthcare, Research",
             "description": "Targeting COVID-19 vaccine research organizations"},
            {"name": "Microsoft 365 OAuth Abuse", "year": 2022, "targets": "NATO, Government",
             "description": "Abusing OAuth applications for persistent access to email"},
        ],
    },
    "APT28": {
        "name": "Fancy Bear",
        "type": "nation-state",
        "country": "Russia",
        "attribution_confidence": "HIGH",
        "active_since": "2004",
        "sophistication": "expert",
        "resource_level": "government",
        "primary_motivation": "espionage, influence",
        "targets": ["Government", "Military", "Media", "Elections", "Sports"],
        "tools": ["X-Agent", "X-Tunnel", "Seduploader", "Zebrocy", "LoJax", "Drovorub"],
        "ttps": {
            "initial_access": ["T1566.001", "T1566.002", "T1190"],
            "execution": ["T1059.001", "T1059.003"],
            "persistence": ["T1053.005", "T1547.001"],
            "credential_access": ["T1110.003", "T1558.003"],
            "lateral_movement": ["T1021.001", "T1021.002"],
            "exfiltration": ["T1048.003", "T1567.002"],
        },
        "campaigns": [
            {"name": "DNC Breach", "year": 2016, "targets": "US Democratic National Committee",
             "description": "Breach of DNC networks and data exfiltration"},
            {"name": "WADA Hack", "year": 2016, "targets": "World Anti-Doping Agency",
             "description": "Theft and leak of athlete medical records"},
        ],
    },
    "Lazarus": {
        "name": "Hidden Cobra",
        "type": "nation-state",
        "country": "North Korea",
        "attribution_confidence": "HIGH",
        "active_since": "2009",
        "sophistication": "expert",
        "resource_level": "government",
        "primary_motivation": "financial, espionage",
        "targets": ["Finance", "Cryptocurrency", "Defense", "Entertainment", "Technology"],
        "tools": ["ELECTRICFISH", "HOPLIGHT", "BISTROMATH", "AppleJeus", "DreamJob", "TraderTraitor"],
        "ttps": {
            "initial_access": ["T1566.001", "T1204.002", "T1195.002"],
            "execution": ["T1059.001", "T1059.005"],
            "persistence": ["T1547.001", "T1543.003"],
            "credential_access": ["T1003.001", "T1555.003"],
            "lateral_movement": ["T1021.002", "T1570"],
            "exfiltration": ["T1041", "T1567.002"],
        },
        "campaigns": [
            {"name": "Sony Pictures", "year": 2014, "targets": "Sony Pictures Entertainment",
             "description": "Destructive attack and data theft against Sony Pictures"},
            {"name": "WannaCry", "year": 2017, "targets": "Global",
             "description": "Global ransomware campaign exploiting EternalBlue"},
            {"name": "Ronin Bridge", "year": 2022, "targets": "Axie Infinity / Ronin Network",
             "description": "$620M cryptocurrency theft from Ronin bridge"},
        ],
    },
    "Sandworm": {
        "name": "Voodoo Bear",
        "type": "nation-state",
        "country": "Russia",
        "attribution_confidence": "HIGH",
        "active_since": "2009",
        "sophistication": "expert",
        "resource_level": "government",
        "primary_motivation": "sabotage, espionage",
        "targets": ["Energy", "Government", "Media", "ICS/SCADA", "Telecom"],
        "tools": ["NotPetya", "Industroyer", "BlackEnergy", "Olympic Destroyer", "CaddyWiper", "Prestige"],
        "ttps": {
            "initial_access": ["T1190", "T1566.001"],
            "execution": ["T1059.001", "T1053.005"],
            "persistence": ["T1547.001", "T1543.003"],
            "credential_access": ["T1003.001", "T1003.002"],
            "lateral_movement": ["T1021.002", "T1021.001"],
            "exfiltration": ["T1041"],
        },
        "campaigns": [
            {"name": "Ukraine Power Grid 2015", "year": 2015, "targets": "Ukrainian Power Companies",
             "description": "First known successful cyberattack on a power grid"},
            {"name": "NotPetya", "year": 2017, "targets": "Global (via Ukraine)",
             "description": "Destructive wiper disguised as ransomware, $10B+ damages"},
            {"name": "Industroyer2", "year": 2022, "targets": "Ukrainian Energy Sector",
             "description": "ICS malware targeting electrical substations"},
        ],
    },
}

# ─── TAXII Feed Sources ────────────────────────────────────────────────
TAXII_FEEDS = [
    {"name": "AlienVault OTX", "url": "https://otx.alienvault.com/taxii/", "type": "TAXII 2.1",
     "collections": ["indicators", "malware", "threat-actors"], "status": "active",
     "indicators_count": random.randint(50000, 200000)},
    {"name": "MITRE ATT&CK", "url": "https://cti-taxii.mitre.org/taxii/", "type": "TAXII 2.0",
     "collections": ["enterprise-attack", "mobile-attack", "ics-attack"], "status": "active",
     "indicators_count": random.randint(10000, 50000)},
    {"name": "Abuse.ch", "url": "https://abuse.ch/taxii/", "type": "TAXII 2.1",
     "collections": ["malware-bazaar", "urlhaus", "threatfox"], "status": "active",
     "indicators_count": random.randint(100000, 500000)},
    {"name": "CISA AIS", "url": "https://ais.cisa.gov/taxii2/", "type": "TAXII 2.1",
     "collections": ["cisa-indicators", "cisa-reports"], "status": "active",
     "indicators_count": random.randint(20000, 80000)},
    {"name": "FS-ISAC", "url": "https://taxii.fsisac.com/taxii/", "type": "TAXII 2.1",
     "collections": ["financial-indicators", "threat-reports"], "status": "active",
     "indicators_count": random.randint(30000, 100000)},
]

# ─── IOC Types ─────────────────────────────────────────────────────────
IOC_TYPES = {
    "ipv4-addr": {"name": "IPv4 Address", "pattern": "ipv4-addr:value = '{value}'",
                   "example": "198.51.100.42"},
    "ipv6-addr": {"name": "IPv6 Address", "pattern": "ipv6-addr:value = '{value}'",
                   "example": "2001:db8::1"},
    "domain-name": {"name": "Domain Name", "pattern": "domain-name:value = '{value}'",
                     "example": "malicious-site.example.com"},
    "url": {"name": "URL", "pattern": "url:value = '{value}'",
             "example": "https://evil.example.com/malware/dropper.exe"},
    "file:hashes.'SHA-256'": {"name": "File Hash (SHA-256)",
                                "pattern": "file:hashes.'SHA-256' = '{value}'",
                                "example": "a1b2c3d4e5f6..."},
    "file:hashes.'MD5'": {"name": "File Hash (MD5)",
                            "pattern": "file:hashes.'MD5' = '{value}'",
                            "example": "d41d8cd98f00b204e9800998ecf8427e"},
    "email-addr": {"name": "Email Address", "pattern": "email-addr:value = '{value}'",
                    "example": "phishing@evil-domain.com"},
    "file:name": {"name": "Filename", "pattern": "file:name = '{value}'",
                   "example": "malware.exe"},
    "windows-registry-key": {"name": "Registry Key",
                               "pattern": "windows-registry-key:key = '{value}'",
                               "example": r"HKLM\SOFTWARE\Malware"},
    "mutex": {"name": "Mutex", "pattern": "mutex:name = '{value}'",
               "example": "Global\\{MALWARE-MUTEX-ID}"},
}


class IOCEntry:
    """Represents an Indicator of Compromise."""

    def __init__(self, ioc_type, value, source="manual", confidence=85,
                 tlp="TLP:AMBER", tags=None):
        self.id = f"indicator--{uuid.uuid4()}"
        self.created = datetime.datetime.now()
        self.modified = self.created
        self.ioc_type = ioc_type
        self.value = value
        self.source = source
        self.confidence = confidence
        self.tlp = tlp
        self.tags = tags or []
        self.sightings = 0
        self.first_seen = self.created
        self.last_seen = self.created
        self.related_actors = []
        self.related_campaigns = []
        self.enrichment = {}

    def to_stix(self):
        """Convert to STIX 2.1 Indicator object."""
        ioc_info = IOC_TYPES.get(self.ioc_type, {})
        pattern = ioc_info.get("pattern", "").format(value=self.value) if ioc_info else f"[{self.ioc_type}:value = '{self.value}']"
        return {
            "type": "indicator",
            "spec_version": "2.1",
            "id": self.id,
            "created": self.created.isoformat() + "Z",
            "modified": self.modified.isoformat() + "Z",
            "name": f"{ioc_info.get('name', self.ioc_type)}: {self.value}",
            "pattern": f"[{pattern}]",
            "pattern_type": "stix",
            "valid_from": self.first_seen.isoformat() + "Z",
            "confidence": self.confidence,
            "labels": self.tags,
            "object_marking_refs": [self._tlp_to_marking(self.tlp)],
        }

    def _tlp_to_marking(self, tlp):
        tlp_map = {
            "TLP:WHITE": "marking-definition--613f2e26-407d-48c7-9eca-b8e91df99dc9",
            "TLP:GREEN": "marking-definition--34098fce-860f-48ae-8e50-ebd3cc5e41da",
            "TLP:AMBER": "marking-definition--f88d31f6-486f-44da-b317-01333bde0b82",
            "TLP:RED": "marking-definition--5e57c739-391a-4eb3-b6be-7d15ca92d5ed",
        }
        return tlp_map.get(tlp, tlp_map["TLP:AMBER"])

    def to_dict(self):
        return {
            "id": self.id,
            "type": self.ioc_type,
            "value": self.value,
            "source": self.source,
            "confidence": self.confidence,
            "tlp": self.tlp,
            "tags": self.tags,
            "sightings": self.sightings,
            "first_seen": self.first_seen.isoformat(),
            "last_seen": self.last_seen.isoformat(),
            "related_actors": self.related_actors,
            "related_campaigns": self.related_campaigns,
        }


class DiamondModelAnalysis:
    """Implements the Diamond Model of Intrusion Analysis."""

    def __init__(self, adversary, capability, infrastructure, victim):
        self.adversary = adversary
        self.capability = capability
        self.infrastructure = infrastructure
        self.victim = victim
        self.meta_features = {}
        self.confidence = random.uniform(0.5, 0.99)
        self.timestamp = datetime.datetime.now()

    def display(self):
        """Display Diamond Model analysis."""
        diamond = f"""
                    [bold red]ADVERSARY[/bold red]
                    {self.adversary}
                       |
            [bold yellow]CAPABILITY[/bold yellow] ----+---- [bold cyan]INFRASTRUCTURE[/bold cyan]
            {self.capability[:20]:20s}     {self.infrastructure[:20]}
                       |
                    [bold green]VICTIM[/bold green]
                    {self.victim}
"""
        console.print(Panel(
            diamond + f"\n[dim]Confidence: {self.confidence:.0%}[/dim]",
            title="Diamond Model Analysis",
            border_style="magenta",
        ))

    def to_dict(self):
        return {
            "adversary": self.adversary,
            "capability": self.capability,
            "infrastructure": self.infrastructure,
            "victim": self.victim,
            "confidence": self.confidence,
            "timestamp": self.timestamp.isoformat(),
        }


class ThreatIntelPlatform:
    """
    Threat Intelligence Platform

    Manages IOCs, threat actor profiles, campaign tracking, and
    intelligence reporting for cybersecurity operations.

    Usage:
        tip = ThreatIntelPlatform()
        tip.run()
    """

    HELP_TEXT = """
AEGIS Threat Intelligence Platform
====================================
Comprehensive threat intelligence management and analysis.

Commands:
  feeds                 List and manage STIX/TAXII feeds
  ioc-create            Create a new IOC entry
  ioc-list              List all managed IOCs
  ioc-enrich            Enrich IOCs with context data
  actor <name>          View threat actor profile
  actors                List all threat actor profiles
  campaign <name>       View campaign details
  diamond               Run Diamond Model analysis
  report <type>         Generate intelligence report
  export <format>       Export IOCs (stix | openioc | csv)
  help                  Show this help message

Report Types: strategic, tactical, operational

Options:
  --actor <name>        Threat actor to analyze
  --format <fmt>        Export format (stix | openioc | csv)
  --tlp <level>         TLP marking (WHITE | GREEN | AMBER | RED)
  --output <file>       Export results to file
"""

    def __init__(self):
        """Initialize the Threat Intelligence Platform."""
        self.iocs = []
        self.analyses = []
        self.reports = []
        self._verify_authorization()
        self._seed_sample_iocs()

    def _verify_authorization(self):
        """Verify operator authorization."""
        console.print(Panel(
            "[bold yellow]AUTHORIZATION CHECK[/bold yellow]\n\n"
            "This module manages simulated threat intelligence data.\n"
            "All IOCs, threat actors, and campaigns are educational examples.\n"
            "Do not use simulated data as real intelligence.",
            title="AEGIS Threat Intel Platform",
            border_style="yellow"
        ))

    def _seed_sample_iocs(self):
        """Seed the platform with sample IOCs for demonstration."""
        samples = [
            ("ipv4-addr", "198.51.100.42", "TAXII Feed", 90, ["c2", "cobalt-strike"]),
            ("domain-name", "update-service-cdn.example.com", "Manual", 85, ["phishing", "apt29"]),
            ("file:hashes.'SHA-256'", hashlib.sha256(b"sample1").hexdigest(), "Malware Analysis", 95, ["ransomware", "lockbit"]),
            ("url", "https://evil-portal.example.com/login.php", "Phishing Report", 80, ["phishing", "credential-harvest"]),
            ("email-addr", "support@fake-vendor.example.com", "User Report", 70, ["phishing", "bec"]),
            ("ipv4-addr", "203.0.113.99", "Honeypot", 88, ["scanner", "brute-force"]),
            ("domain-name", "c2-relay-node.example.net", "Sandbox Analysis", 92, ["c2", "apt41"]),
            ("file:hashes.'MD5'", hashlib.md5(b"sample2").hexdigest(), "VirusTotal", 75, ["dropper", "trojan"]),
            ("mutex", "Global\\{9A8B7C6D-5E4F-3A2B-1C0D}", "Reverse Engineering", 95, ["malware", "lazarus"]),
            ("windows-registry-key", r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\UpdateSvc",
             "Endpoint Alert", 88, ["persistence", "backdoor"]),
        ]
        for ioc_type, value, source, confidence, tags in samples:
            ioc = IOCEntry(ioc_type, value, source, confidence, tags=tags)
            ioc.sightings = random.randint(1, 50)
            self.iocs.append(ioc)

    def list_feeds(self):
        """Display available STIX/TAXII feeds."""
        table = Table(title="STIX/TAXII Intelligence Feeds")
        table.add_column("Feed Name", style="cyan")
        table.add_column("Type", style="yellow")
        table.add_column("Collections", style="white")
        table.add_column("Indicators", style="green", justify="right")
        table.add_column("Status", width=8)

        for feed in TAXII_FEEDS:
            status_style = "green" if feed["status"] == "active" else "red"
            table.add_row(
                feed["name"],
                feed["type"],
                ", ".join(feed["collections"][:3]),
                f"{feed['indicators_count']:,}",
                Text(feed["status"].upper(), style=status_style),
            )
        console.print(table)

    def create_ioc(self, ioc_type="ipv4-addr", value="", source="manual",
                   confidence=85, tlp="TLP:AMBER", tags=None):
        """Create a new IOC entry."""
        if not value:
            # Generate sample for demonstration
            ioc_info = IOC_TYPES.get(ioc_type, {})
            value = ioc_info.get("example", "unknown")

        ioc = IOCEntry(ioc_type, value, source, confidence, tlp, tags or [])
        self.iocs.append(ioc)

        console.print(Panel(
            f"[bold green]IOC Created[/bold green]\n\n"
            f"ID:          {ioc.id}\n"
            f"Type:        {ioc.ioc_type}\n"
            f"Value:       {ioc.value}\n"
            f"Source:      {ioc.source}\n"
            f"Confidence:  {ioc.confidence}%\n"
            f"TLP:         {ioc.tlp}\n"
            f"Tags:        {', '.join(ioc.tags) if ioc.tags else 'none'}",
            title="New IOC",
            border_style="green",
        ))
        return ioc

    def list_iocs(self):
        """Display all managed IOCs."""
        table = Table(title=f"Managed IOCs ({len(self.iocs)})")
        table.add_column("Type", style="cyan", width=15)
        table.add_column("Value", style="white", width=40)
        table.add_column("Source", style="yellow", width=15)
        table.add_column("Conf", justify="right", width=5)
        table.add_column("TLP", width=12)
        table.add_column("Sightings", justify="right", width=9)
        table.add_column("Tags", style="dim", width=20)

        for ioc in self.iocs:
            tlp_style = {
                "TLP:WHITE": "white", "TLP:GREEN": "green",
                "TLP:AMBER": "yellow", "TLP:RED": "red",
            }.get(ioc.tlp, "white")
            display_value = ioc.value[:38] + ".." if len(ioc.value) > 40 else ioc.value
            table.add_row(
                ioc.ioc_type,
                display_value,
                ioc.source,
                str(ioc.confidence),
                Text(ioc.tlp, style=tlp_style),
                str(ioc.sightings),
                ", ".join(ioc.tags[:3]),
            )
        console.print(table)

    def enrich_iocs(self):
        """Enrich IOCs with additional context (simulated)."""
        console.print(Panel(
            "[bold cyan]IOC ENRICHMENT[/bold cyan]\n\n"
            "Enriching IOCs with additional context from threat intelligence sources...",
            title="IOC Enrichment",
            border_style="cyan",
        ))

        enrichment_sources = ["VirusTotal", "Shodan", "GreyNoise", "AbuseIPDB",
                              "URLHaus", "PassiveTotal", "WHOIS", "GeoIP"]

        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
            console=console,
        ) as progress:
            task = progress.add_task("[cyan]Enriching IOCs...", total=len(self.iocs))
            for ioc in self.iocs:
                source = random.choice(enrichment_sources)
                ioc.enrichment = {
                    "source": source,
                    "risk_score": random.randint(30, 100),
                    "first_reported": (datetime.datetime.now() -
                                       datetime.timedelta(days=random.randint(1, 365))).isoformat(),
                    "categories": random.sample(["malware", "c2", "phishing", "spam",
                                                  "scanner", "tor", "vpn", "proxy"], 2),
                    "geo": random.choice(["RU", "CN", "KP", "IR", "US", "DE", "NL"]),
                }
                progress.advance(task)

        # Display enrichment results
        table = Table(title="Enrichment Results")
        table.add_column("IOC", style="white", width=30)
        table.add_column("Source", style="cyan")
        table.add_column("Risk Score", justify="right")
        table.add_column("Categories", style="yellow")
        table.add_column("Geo", style="green")

        for ioc in self.iocs[:10]:
            if ioc.enrichment:
                risk = ioc.enrichment.get("risk_score", 0)
                risk_style = "red bold" if risk >= 80 else "yellow" if risk >= 50 else "green"
                display_val = ioc.value[:28] + ".." if len(ioc.value) > 30 else ioc.value
                table.add_row(
                    display_val,
                    ioc.enrichment.get("source", ""),
                    Text(str(risk), style=risk_style),
                    ", ".join(ioc.enrichment.get("categories", [])),
                    ioc.enrichment.get("geo", ""),
                )
        console.print(table)

    def view_threat_actor(self, actor_name="APT29"):
        """Display detailed threat actor profile."""
        actor = THREAT_ACTORS.get(actor_name)
        if not actor:
            console.print(f"[red]Unknown actor: {actor_name}. Use 'actors' to list all.[/red]")
            return

        console.print(Panel(
            f"[bold red]{actor_name} ({actor['name']})[/bold red]\n\n"
            f"Type:           {actor['type']}\n"
            f"Country:        {actor['country']}\n"
            f"Attribution:    {actor['attribution_confidence']} confidence\n"
            f"Active Since:   {actor['active_since']}\n"
            f"Sophistication: {actor['sophistication']}\n"
            f"Resources:      {actor['resource_level']}\n"
            f"Motivation:     {actor['primary_motivation']}\n\n"
            f"[bold]Targets:[/bold] {', '.join(actor['targets'])}\n"
            f"[bold]Tools:[/bold]   {', '.join(actor['tools'])}",
            title=f"Threat Actor Profile: {actor_name}",
            border_style="red",
        ))

        # TTP tree
        tree = Tree(f"[bold]{actor_name} TTPs[/bold]")
        for tactic, techniques in actor["ttps"].items():
            branch = tree.add(f"[cyan]{tactic.replace('_', ' ').title()}[/cyan]")
            for tech in techniques:
                branch.add(f"[yellow]{tech}[/yellow]")
        console.print(tree)

        # Campaigns
        if actor.get("campaigns"):
            table = Table(title=f"{actor_name} Campaigns")
            table.add_column("Campaign", style="red")
            table.add_column("Year", style="cyan")
            table.add_column("Targets", style="yellow")
            table.add_column("Description", style="white")

            for campaign in actor["campaigns"]:
                table.add_row(
                    campaign["name"],
                    str(campaign["year"]),
                    campaign["targets"],
                    campaign["description"],
                )
            console.print(table)

    def list_threat_actors(self):
        """List all threat actor profiles."""
        table = Table(title="Threat Actor Profiles")
        table.add_column("ID", style="red bold")
        table.add_column("Name", style="cyan")
        table.add_column("Country", style="yellow")
        table.add_column("Type", style="green")
        table.add_column("Motivation", style="white")
        table.add_column("Active Since", style="dim")

        for actor_id, actor in THREAT_ACTORS.items():
            table.add_row(
                actor_id,
                actor["name"],
                actor["country"],
                actor["type"],
                actor["primary_motivation"],
                actor["active_since"],
            )
        console.print(table)

    def diamond_model_analysis(self, actor_name="APT29"):
        """Perform Diamond Model analysis for a threat actor."""
        actor = THREAT_ACTORS.get(actor_name, THREAT_ACTORS["APT29"])

        analysis = DiamondModelAnalysis(
            adversary=f"{actor_name} ({actor['name']}) -- {actor['country']}",
            capability=f"Tools: {', '.join(actor['tools'][:3])}",
            infrastructure=f"C2, Compromised Domains, VPN",
            victim=f"Sectors: {', '.join(actor['targets'][:3])}",
        )
        analysis.display()
        self.analyses.append(analysis)

        # Additional meta-features
        console.print(Panel(
            f"[bold]Meta-Features[/bold]\n\n"
            f"Timestamp:       {analysis.timestamp.strftime('%Y-%m-%d %H:%M')}\n"
            f"Phase:           Varies (multi-stage campaigns)\n"
            f"Result:          Data exfiltration, espionage\n"
            f"Direction:       Adversary -> Victim\n"
            f"Methodology:     Spearphishing, supply chain, exploitation\n"
            f"Resources:       {actor['resource_level']}\n"
            f"Technology:      {', '.join(actor['tools'][:4])}\n"
            f"Attribution:     {actor['attribution_confidence']} confidence",
            title="Diamond Model Meta-Features",
            border_style="magenta",
        ))

        return analysis

    def generate_report(self, report_type="tactical"):
        """Generate intelligence report."""
        report_templates = {
            "strategic": {
                "title": "Strategic Threat Intelligence Report",
                "audience": "Executive Leadership, Board of Directors",
                "sections": [
                    "Executive Summary",
                    "Threat Landscape Overview",
                    "Industry-Specific Threats",
                    "Geopolitical Context",
                    "Risk Assessment Matrix",
                    "Recommended Strategic Actions",
                    "Resource Allocation Recommendations",
                ],
                "timeframe": "Quarterly",
            },
            "tactical": {
                "title": "Tactical Threat Intelligence Report",
                "audience": "Security Operations, Incident Response",
                "sections": [
                    "Current Threat Summary",
                    "Active Threat Actor Campaigns",
                    "New IOCs and Signatures",
                    "MITRE ATT&CK Coverage Gaps",
                    "Detection Rule Recommendations",
                    "Vulnerability Prioritization",
                    "Hunting Hypotheses",
                ],
                "timeframe": "Weekly",
            },
            "operational": {
                "title": "Operational Threat Intelligence Report",
                "audience": "SOC Analysts, Threat Hunters",
                "sections": [
                    "Active Incidents Summary",
                    "IOC Feed Updates",
                    "Malware Analysis Results",
                    "Network Traffic Anomalies",
                    "Detection Rule Triggers",
                    "Recommended Immediate Actions",
                    "Escalation Criteria",
                ],
                "timeframe": "Daily",
            },
        }

        template = report_templates.get(report_type, report_templates["tactical"])

        console.print(Panel(
            f"[bold cyan]{template['title']}[/bold cyan]\n\n"
            f"Audience:   {template['audience']}\n"
            f"Timeframe:  {template['timeframe']}\n"
            f"Generated:  {datetime.datetime.now().strftime('%Y-%m-%d %H:%M')}\n"
            f"IOCs Managed: {len(self.iocs)}\n"
            f"Actors Tracked: {len(THREAT_ACTORS)}",
            title=f"Intelligence Report: {report_type.title()}",
            border_style="cyan",
        ))

        tree = Tree(f"[bold]{template['title']}[/bold]")
        for section in template["sections"]:
            tree.add(f"[green]{section}[/green]")
        console.print(tree)

        return template

    def export_iocs(self, fmt="stix", output_file=None):
        """Export IOCs in various formats."""
        if fmt == "stix":
            bundle = {
                "type": "bundle",
                "id": f"bundle--{uuid.uuid4()}",
                "objects": [ioc.to_stix() for ioc in self.iocs],
            }
            data = json.dumps(bundle, indent=2)
            console.print(Panel(
                Syntax(data[:2000] + "\n..." if len(data) > 2000 else data,
                       "json", theme="monokai"),
                title="STIX 2.1 Bundle Export",
                border_style="yellow",
            ))
        elif fmt == "csv":
            lines = ["type,value,source,confidence,tlp,tags,first_seen,last_seen"]
            for ioc in self.iocs:
                lines.append(
                    f"{ioc.ioc_type},{ioc.value},{ioc.source},{ioc.confidence},"
                    f"{ioc.tlp},\"{';'.join(ioc.tags)}\","
                    f"{ioc.first_seen.isoformat()},{ioc.last_seen.isoformat()}"
                )
            data = "\n".join(lines)
            console.print(Panel(data, title="CSV Export", border_style="green"))
        elif fmt == "openioc":
            console.print(Panel(
                "[bold]OpenIOC Export[/bold]\n\n"
                f"Generated {len(self.iocs)} indicators in OpenIOC 1.1 format.\n"
                "Each indicator wrapped in <IndicatorItem> with AND/OR logic.",
                title="OpenIOC Export",
                border_style="yellow",
            ))

        if output_file:
            with open(output_file, "w") as f:
                f.write(data if fmt in ["stix", "csv"] else json.dumps(
                    [ioc.to_dict() for ioc in self.iocs], indent=2))
            console.print(f"[green]Exported to {output_file}[/green]")

    def run(self):
        """Main execution entry point."""
        self.list_feeds()
        console.print("\n")
        self.list_iocs()
        console.print("\n")
        self.enrich_iocs()
        console.print("\n")
        self.list_threat_actors()
        console.print("\n")
        self.view_threat_actor("APT29")
        console.print("\n")
        self.diamond_model_analysis("APT29")
        console.print("\n")
        self.generate_report("tactical")


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description="AEGIS Threat Intelligence Platform -- Educational Use Only",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("command", nargs="?", default="run",
                        choices=["run", "feeds", "ioc-create", "ioc-list", "ioc-enrich",
                                 "actor", "actors", "diamond", "report", "export", "help"],
                        help="Command to execute")
    parser.add_argument("--actor", "-a", default="APT29",
                        choices=list(THREAT_ACTORS.keys()),
                        help="Threat actor to analyze")
    parser.add_argument("--format", "-f", default="stix",
                        choices=["stix", "openioc", "csv"],
                        help="Export format")
    parser.add_argument("--report-type", "-r", default="tactical",
                        choices=["strategic", "tactical", "operational"],
                        help="Report type")
    parser.add_argument("--output", "-o", default=None,
                        help="Output file")

    args = parser.parse_args()
    tip = ThreatIntelPlatform()

    if args.command == "help":
        console.print(tip.HELP_TEXT)
    elif args.command == "feeds":
        tip.list_feeds()
    elif args.command == "ioc-create":
        tip.create_ioc()
    elif args.command == "ioc-list":
        tip.list_iocs()
    elif args.command == "ioc-enrich":
        tip.enrich_iocs()
    elif args.command == "actor":
        tip.view_threat_actor(args.actor)
    elif args.command == "actors":
        tip.list_threat_actors()
    elif args.command == "diamond":
        tip.diamond_model_analysis(args.actor)
    elif args.command == "report":
        tip.generate_report(args.report_type)
    elif args.command == "export":
        tip.export_iocs(args.format, args.output)
    else:
        tip.run()


if __name__ == "__main__":
    main()
