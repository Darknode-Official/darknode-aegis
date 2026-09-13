#!/usr/bin/env python3
"""AEGIS APT Tracker — threat actor profiling and tracking."""
import sys

APT_DB = [
    {"name": "APT28", "aliases": ["Fancy Bear", "Sofacy", "Pawn Storm", "Sednit", "STRONTIUM"], "country": "Russia", "org": "GRU Unit 26165", "active": "2004", "sectors": ["government", "military", "media", "defense"], "regions": ["NATO", "Eastern Europe", "USA"], "ttps": ["T1566.001", "T1190", "T1059.001", "T1003", "T1550.002", "T1048"], "tools": ["X-Agent", "X-Tunnel", "Zebrocy", "LoJax", "Sofacy"], "campaigns": ["DNC Hack (2016)", "Olympic Destroyer (2018)", "Bundestag Hack (2015)"], "desc": "Russian military intelligence. Aggressive tactics, often leaves traces. Known for election interference and military espionage."},
    {"name": "APT29", "aliases": ["Cozy Bear", "The Dukes", "NOBELIUM", "Midnight Blizzard"], "country": "Russia", "org": "SVR", "active": "2008", "sectors": ["government", "think tanks", "healthcare", "tech"], "regions": ["USA", "Europe", "NATO"], "ttps": ["T1195.002", "T1059.001", "T1078", "T1550.003", "T1567.002"], "tools": ["Cobalt Strike", "WellMess", "EnvyScout", "BoomBox", "SUNBURST"], "campaigns": ["SolarWinds SUNBURST (2020)", "DNC Hack (2015)", "COVID-19 vaccine research (2020)"], "desc": "Russian foreign intelligence. Extremely sophisticated, patient, stealthy. Known for SolarWinds supply chain attack."},
    {"name": "Lazarus Group", "aliases": ["Hidden Cobra", "ZINC", "Labyrinth Chollima"], "country": "North Korea", "org": "RGB", "active": "2009", "sectors": ["financial", "cryptocurrency", "defense", "entertainment"], "regions": ["global"], "ttps": ["T1566.001", "T1059", "T1053.005", "T1003", "T1048"], "tools": ["FALLCHILL", "Bankshot", "AppleJeus", "DTrack", "BLINDINGCAN"], "campaigns": ["Sony Pictures (2014)", "Bangladesh Bank SWIFT ($81M, 2016)", "WannaCry (2017)", "Ronin Bridge ($625M, 2022)"], "desc": "North Korean state-sponsored. Financially motivated — fund regime. Known for bank heists and crypto theft totaling billions."},
    {"name": "APT1", "aliases": ["Comment Crew", "Comment Panda"], "country": "China", "org": "PLA Unit 61398", "active": "2006", "sectors": ["defense", "aerospace", "tech", "energy"], "regions": ["USA"], "ttps": ["T1566.001", "T1059", "T1003", "T1005"], "tools": ["WEBC2", "BISCUIT", "MANITSME"], "campaigns": ["141 companies across 20 industries (2006-2013)"], "desc": "Chinese military unit. Prolific IP theft from US companies. Exposed by Mandiant in 2013."},
    {"name": "Volt Typhoon", "aliases": ["VANGUARD PANDA", "Bronze Silhouette"], "country": "China", "org": "MSS", "active": "2021", "sectors": ["critical infrastructure", "telecom", "government"], "regions": ["USA", "Guam", "Pacific"], "ttps": ["T1190", "T1059.001", "T1078", "T1505.003", "T1070"], "tools": ["LOLBins only", "certutil", "netsh", "wmic", "ntdsutil"], "campaigns": ["US critical infrastructure pre-positioning (2023-present)"], "desc": "Chinese state-sponsored. Pre-positions in US critical infrastructure for potential future disruption. Uses ONLY living-off-the-land techniques — no custom malware. Extremely difficult to detect."},
    {"name": "Salt Typhoon", "aliases": ["GhostEmperor", "FamousSparrow"], "country": "China", "org": "MSS", "active": "2020", "sectors": ["telecom", "ISP", "government"], "regions": ["USA", "global"], "ttps": ["T1190", "T1003", "T1078", "T1021"], "tools": ["Demodex rootkit", "custom implants"], "campaigns": ["US telecom providers breach (2024) — AT&T, Verizon, T-Mobile"], "desc": "Chinese state-sponsored targeting telecommunications. Intercepted wiretap systems used by US law enforcement."},
    {"name": "Turla", "aliases": ["Snake", "Venomous Bear", "KRYPTON"], "country": "Russia", "org": "FSB", "active": "1996", "sectors": ["government", "military", "diplomatic"], "regions": ["global"], "ttps": ["T1195.002", "T1071.001", "T1059", "T1027"], "tools": ["Snake", "Carbon", "Kazuar", "ComRAT", "Gazer"], "campaigns": ["US DoD (2008)", "European government networks (ongoing)"], "desc": "Russian FSB. One of the most sophisticated APTs. Known for satellite-based C2 and hijacking other APT groups' infrastructure."},
    {"name": "Sandworm", "aliases": ["VOODOO BEAR", "IRIDIUM", "Seashell Blizzard"], "country": "Russia", "org": "GRU Unit 74455", "active": "2009", "sectors": ["energy", "government", "critical infrastructure"], "regions": ["Ukraine", "global"], "ttps": ["T1190", "T1059", "T1485", "T1498"], "tools": ["BlackEnergy", "Industroyer", "NotPetya", "Olympic Destroyer", "CaddyWiper"], "campaigns": ["Ukraine power grid (2015, 2016)", "NotPetya ($10B damage, 2017)", "Olympic Destroyer (2018)"], "desc": "Russian military intelligence. Destructive attacks on critical infrastructure. Responsible for the most expensive cyberattack in history (NotPetya)."},
    {"name": "Kimsuky", "aliases": ["Velvet Chollima", "Thallium", "Black Banshee"], "country": "North Korea", "org": "RGB", "active": "2012", "sectors": ["government", "think tanks", "nuclear", "defense"], "regions": ["South Korea", "USA", "Japan"], "ttps": ["T1566.001", "T1059.005", "T1003", "T1056.001"], "tools": ["BabyShark", "AppleSeed", "FlowerPower", "GoldDragon"], "campaigns": ["South Korean nuclear research (2014)", "Think tank targeting (ongoing)"], "desc": "North Korean intelligence gathering focused on nuclear/foreign policy intelligence from South Korea, USA, and Japan."},
    {"name": "Charming Kitten", "aliases": ["APT35", "Phosphorus", "Mint Sandstorm"], "country": "Iran", "org": "IRGC", "active": "2014", "sectors": ["government", "academia", "media", "human rights"], "regions": ["Middle East", "USA", "Europe"], "ttps": ["T1566.001", "T1566.002", "T1078", "T1056.001"], "tools": ["DownPaper", "MacDownloader", "PowerStar"], "campaigns": ["US election interference attempts", "Academic credential theft"], "desc": "Iranian state-sponsored. Focuses on espionage against dissidents, journalists, and policy researchers. Heavy use of social engineering."},
    {"name": "OilRig", "aliases": ["APT34", "Helix Kitten", "Hazel Sandstorm"], "country": "Iran", "org": "MOIS", "active": "2014", "sectors": ["government", "energy", "telecom", "financial"], "regions": ["Middle East"], "ttps": ["T1566.001", "T1059.005", "T1003", "T1071.001"], "tools": ["BONDUPDATER", "QUADAGENT", "OopsIE", "Helminth"], "campaigns": ["Middle East government and energy sector espionage"], "desc": "Iranian intelligence service. Supply chain attacks and credential harvesting in the Middle East."},
    {"name": "MuddyWater", "aliases": ["MERCURY", "Static Kitten", "Mango Sandstorm"], "country": "Iran", "org": "MOIS", "active": "2017", "sectors": ["government", "telecom", "oil & gas"], "regions": ["Middle East", "South Asia"], "ttps": ["T1566.001", "T1059.001", "T1059.005", "T1047"], "tools": ["POWERSTATS", "MuddyC2Go", "PhonyC2"], "campaigns": ["Middle East and South Asia espionage"], "desc": "Iranian intelligence. Uses commodity tools extensively. Known for macro-based initial access."},
    {"name": "Gamaredon", "aliases": ["Primitive Bear", "Actinium", "Armageddon"], "country": "Russia", "org": "FSB (Crimea)", "active": "2013", "sectors": ["government", "military", "NGO"], "regions": ["Ukraine"], "ttps": ["T1566.001", "T1059.005", "T1547.001", "T1071.001"], "tools": ["Pteranodon", "Pterodo", "QuietSieve"], "campaigns": ["Ukraine government targeting (ongoing since 2014)"], "desc": "Russian FSB operating from occupied Crimea. High-volume, low-sophistication attacks exclusively targeting Ukraine."},
    {"name": "FIN7", "aliases": ["Carbanak", "Navigator Group", "Carbon Spider"], "country": "Russia", "org": "Criminal", "active": "2013", "sectors": ["retail", "hospitality", "financial", "restaurants"], "regions": ["USA", "Europe"], "ttps": ["T1566.001", "T1059.005", "T1059.001", "T1003"], "tools": ["Carbanak", "GRIFFON", "HALFBAKED", "Cobalt Strike"], "campaigns": ["Retail POS breaches", "Restaurant chain compromises", "$1B+ stolen from banks"], "desc": "Financially motivated cybercrime group. Operated fake pentesting company (Combi Security). Members arrested but group continues."},
    {"name": "Scattered Spider", "aliases": ["UNC3944", "Octo Tempest", "0ktapus"], "country": "USA/UK", "org": "Criminal collective", "active": "2022", "sectors": ["telecom", "tech", "hospitality", "finance"], "regions": ["USA", "global"], "ttps": ["T1566.001", "T1078", "T1556", "T1098"], "tools": ["Social engineering", "SIM swap", "MFA fatigue", "Okta abuse"], "campaigns": ["MGM Resorts ($100M impact, 2023)", "Caesars ($15M ransom, 2023)", "Twilio/Cloudflare (2022)"], "desc": "Young English-speaking threat actors. Master social engineers — call help desks, impersonate employees. Known for MGM/Caesars casino breaches."},
    {"name": "LockBit", "aliases": ["LockBit 3.0", "LockBit Black"], "country": "Russia", "org": "RaaS affiliate model", "active": "2019", "sectors": ["any"], "regions": ["global"], "ttps": ["T1190", "T1059", "T1486", "T1021.002", "T1543.003"], "tools": ["LockBit ransomware", "StealBit", "Cobalt Strike"], "campaigns": ["Thousands of victims globally", "ICBC (2023)", "Boeing (2023)", "Royal Mail (2023)"], "desc": "Most prolific ransomware gang. Double extortion (encrypt + leak). Average dwell time 4-14 days. Disrupted by law enforcement in Feb 2024 but attempting comeback."},
    {"name": "BlackCat", "aliases": ["ALPHV", "Noberus"], "country": "Russia", "org": "Criminal", "active": "2021", "sectors": ["any"], "regions": ["global"], "ttps": ["T1190", "T1059", "T1486", "T1567"], "tools": ["BlackCat ransomware (Rust)", "ExMatter", "Eamfo"], "campaigns": ["Change Healthcare ($22M ransom, 2024)", "Reddit (2023)", "MGM (via Scattered Spider, 2023)"], "desc": "Ransomware-as-a-Service. First major ransomware written in Rust. Known for triple extortion (encrypt + leak + DDoS). Exit-scammed affiliates in 2024."},
    {"name": "Cl0p", "aliases": ["TA505", "FIN11"], "country": "Russia/Ukraine", "org": "Criminal", "active": "2019", "sectors": ["any"], "regions": ["global"], "ttps": ["T1190", "T1005", "T1567"], "tools": ["Cl0p ransomware", "DEWMODE", "LEMURLOOT"], "campaigns": ["MOVEit Transfer (2,500+ orgs, 2023)", "GoAnywhere MFT (130 orgs, 2023)", "Accellion FTA (2021)"], "desc": "Specializes in mass exploitation of file transfer appliances. MOVEit campaign was one of the largest breaches in history by victim count."},
    {"name": "APT41", "aliases": ["Winnti", "Barium", "Brass Typhoon"], "country": "China", "org": "MSS contractor", "active": "2012", "sectors": ["gaming", "tech", "healthcare", "telecom"], "regions": ["global"], "ttps": ["T1195.002", "T1190", "T1059", "T1003"], "tools": ["ShadowPad", "Winnti", "PlugX", "Cobalt Strike"], "campaigns": ["Supply chain attacks on software vendors", "Healthcare data theft", "Gaming industry targeting"], "desc": "Unique dual-mission group — conducts both state espionage and financially motivated cybercrime. Known for supply chain compromises."},
    {"name": "Equation Group", "aliases": ["PLATINUM (partial)"], "country": "USA", "org": "NSA TAO", "active": "1996", "sectors": ["government", "military", "telecom", "nuclear"], "regions": ["global"], "ttps": ["T1195.002", "T1542", "T1027.002"], "tools": ["EternalBlue", "DoublePulsar", "Stuxnet (co-developed)", "GRAYFISH", "EQUATIONDRUG"], "campaigns": ["Stuxnet (Iran nuclear program)", "Regin malware framework", "Shadow Brokers leak (2017)"], "desc": "Widely attributed to NSA's Tailored Access Operations. Most sophisticated threat actor ever documented. Created Stuxnet. Tools leaked by Shadow Brokers in 2017."},
]


class APTTracker:
    """APT group tracking and profiling."""

    def __init__(self):
        self.db = APT_DB

    def search(self, query):
        q = query.lower()
        return [g for g in self.db if q in g["name"].lower() or q in g.get("country", "").lower() or any(q in a.lower() for a in g.get("aliases", [])) or any(q in s.lower() for s in g.get("sectors", [])) or any(q in t.lower() for t in g.get("ttps", []))]

    def profile(self, name):
        q = name.lower()
        for g in self.db:
            if q == g["name"].lower() or any(q == a.lower() for a in g.get("aliases", [])):
                return g
        return None

    def by_country(self, country):
        c = country.lower()
        return [g for g in self.db if c in g.get("country", "").lower()]

    def who_targets(self, sector, region=""):
        results = []
        for g in self.db:
            sector_match = any(sector.lower() in s.lower() for s in g.get("sectors", [])) or "any" in g.get("sectors", [])
            region_match = not region or any(region.lower() in r.lower() for r in g.get("regions", [])) or "global" in g.get("regions", [])
            if sector_match and region_match:
                results.append(g)
        return results

    def compare(self, name1, name2):
        g1 = self.profile(name1)
        g2 = self.profile(name2)
        if not g1 or not g2:
            return None
        return {"group1": g1, "group2": g2, "shared_ttps": set(g1.get("ttps", [])) & set(g2.get("ttps", [])), "shared_sectors": set(g1.get("sectors", [])) & set(g2.get("sectors", []))}

    def format_profile(self, g):
        lines = [f"\n  === {g['name']} ==="]
        lines.append(f"  Aliases: {', '.join(g.get('aliases', []))}")
        lines.append(f"  Attribution: {g.get('country', '?')} ({g.get('org', '?')})")
        lines.append(f"  Active since: {g.get('active', '?')}")
        lines.append(f"  Target sectors: {', '.join(g.get('sectors', []))}")
        lines.append(f"  Target regions: {', '.join(g.get('regions', []))}")
        lines.append(f"  TTPs: {', '.join(g.get('ttps', []))}")
        lines.append(f"  Tools: {', '.join(g.get('tools', []))}")
        lines.append(f"  Notable campaigns: {'; '.join(g.get('campaigns', []))}")
        lines.append(f"  Description: {g.get('desc', '')}")
        return "\n".join(lines)

    def run(self, confirm_fn=None):
        print(f"\n=== AEGIS APT Tracker === ({len(self.db)} groups)")
        print("Commands: search <query>, profile <name>, country <country>, targets <sector> [region], compare <g1> <g2>, list, quit\n")
        while True:
            cmd = input("[apt-tracker] > ").strip()
            if cmd.lower() in ("quit", "exit", "q"):
                break
            if cmd.lower() == "list":
                for g in self.db:
                    print(f"  {g['name']:20s} {g.get('country', ''):12s} {', '.join(g.get('aliases', [])[:2])}")
            elif cmd.lower().startswith("search "):
                results = self.search(cmd[7:])
                print(f"  {len(results)} result(s):")
                for g in results:
                    print(f"  {g['name']:20s} [{g.get('country', '')}] {g.get('desc', '')[:80]}")
            elif cmd.lower().startswith("profile "):
                g = self.profile(cmd[8:])
                if g:
                    print(self.format_profile(g))
                else:
                    print("  Group not found.")
            elif cmd.lower().startswith("country "):
                results = self.by_country(cmd[8:])
                print(f"  {len(results)} group(s) from {cmd[8:]}:")
                for g in results:
                    print(f"  {g['name']:20s} {', '.join(g.get('aliases', [])[:2])}")
            elif cmd.lower().startswith("targets "):
                parts = cmd[8:].split()
                sector = parts[0]
                region = parts[1] if len(parts) > 1 else ""
                results = self.who_targets(sector, region)
                print(f"  {len(results)} group(s) targeting {sector}:")
                for g in results:
                    print(f"  {g['name']:20s} [{g.get('country', '')}] {', '.join(g.get('campaigns', [])[:1])}")
            elif cmd.lower().startswith("compare "):
                parts = cmd[8:].split(" vs ")
                if len(parts) != 2:
                    parts = cmd[8:].split()
                if len(parts) >= 2:
                    result = self.compare(parts[0].strip(), parts[1].strip())
                    if result:
                        print(f"\n  {result['group1']['name']} vs {result['group2']['name']}")
                        print(f"  Shared TTPs: {', '.join(result['shared_ttps']) or 'None'}")
                        print(f"  Shared sectors: {', '.join(result['shared_sectors']) or 'None'}")
                    else:
                        print("  One or both groups not found.")
            else:
                print("  Commands: search, profile, country, targets, compare, list, quit")


if __name__ == "__main__":
    APTTracker().run()
