#!/usr/bin/env python3
"""AEGIS Social/OSINT Reconnaissance Module
Employee enumeration, email format detection, username generation,
breach database references, social media presence mapping.
"""
import subprocess, json, os, sys, re
from datetime import datetime

def _run(cmd, timeout=15):
    try:
        r = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=timeout)
        return r.stdout.strip(), r.stderr.strip(), r.returncode
    except:
        return "", "", 1

SOCIAL_PLATFORMS = {
    "Professional": ["linkedin.com", "glassdoor.com", "indeed.com", "angel.co", "crunchbase.com", "xing.com"],
    "Development": ["github.com", "gitlab.com", "bitbucket.org", "stackoverflow.com", "npmjs.com", "pypi.org", "hub.docker.com", "codepen.io", "replit.com", "hackernoon.com", "dev.to", "medium.com"],
    "Social Media": ["twitter.com/x.com", "facebook.com", "instagram.com", "tiktok.com", "youtube.com", "reddit.com", "pinterest.com", "tumblr.com", "mastodon.social", "threads.net", "bluesky.social"],
    "Communication": ["discord.com", "slack.com", "telegram.org", "signal.org", "keybase.io"],
    "Security/Hacking": ["hackerone.com", "bugcrowd.com", "hackthebox.com", "tryhackme.com", "ctftime.org", "exploit-db.com", "vulnhub.com"],
    "Gaming": ["twitch.tv", "steam.com", "xbox.com", "playstation.com", "epicgames.com", "roblox.com"],
    "Creative": ["behance.net", "dribbble.com", "deviantart.com", "artstation.com", "flickr.com", "500px.com"],
    "Forums": ["quora.com", "news.ycombinator.com", "lobste.rs", "slashdot.org"],
    "Cloud/Hosting": ["heroku.com", "vercel.com", "netlify.com", "pages.github.com", "cloudflare.com"],
    "Paste Sites": ["pastebin.com", "hastebin.com", "ghostbin.com", "gist.github.com", "paste.ee"],
}

EMAIL_FORMATS = [
    {"name": "first.last", "gen": lambda f, l: f"{f}.{l}"},
    {"name": "flast", "gen": lambda f, l: f"{f[0]}{l}"},
    {"name": "firstl", "gen": lambda f, l: f"{f}{l[0]}"},
    {"name": "first", "gen": lambda f, l: f},
    {"name": "last.first", "gen": lambda f, l: f"{l}.{f}"},
    {"name": "first_last", "gen": lambda f, l: f"{f}_{l}"},
    {"name": "first-last", "gen": lambda f, l: f"{f}-{l}"},
    {"name": "flastname", "gen": lambda f, l: f"{f[0]}{l}"},
    {"name": "lastname", "gen": lambda f, l: l},
    {"name": "f.last", "gen": lambda f, l: f"{f[0]}.{l}"},
]

class SocialRecon:
    name = "Social/OSINT Reconnaissance"
    description = "Employee enumeration, email format detection, username generation, breach references, social media mapping"
    category = "recon"
    mitre = ["T1589", "T1589.002", "T1591", "T1593"]

    def __init__(self, target, options=None):
        self.target = target.replace("https://", "").replace("http://", "").split("/")[0]
        self.options = options or {}
        self.findings = []
        self.actions = []
        self.employees = []

    def _add(self, severity, title, detail, evidence="", mitre=""):
        self.findings.append({
            "severity": severity, "title": title, "detail": detail,
            "evidence": evidence, "mitre": mitre,
            "timestamp": datetime.utcnow().isoformat(), "module": self.name
        })

    def _confirm(self, action, confirm_fn):
        self.actions.append(action)
        if confirm_fn:
            return confirm_fn(action)
        return True

    def email_format_detection(self, confirm_fn=None):
        detail = f"Possible email formats for @{self.target}:\n\n"
        for fmt in EMAIL_FORMATS:
            example = fmt["gen"]("john", "doe") + f"@{self.target}"
            detail += f"  {fmt['name']:20s} {example}\n"
        detail += "\nVerification methods:\n"
        detail += "  1. Check LinkedIn for employee names, then test format via SMTP VRFY/RCPT TO\n"
        detail += "  2. Check GitHub commits for email addresses matching the domain\n"
        detail += "  3. Look for email addresses in PDF metadata, job postings, press releases\n"
        detail += "  4. Use Hunter.io, Phonebook.cz, or Snov.io for email format detection\n"
        self._add("info", f"Email format candidates for {self.target}", detail, "", "T1589.002")

    def generate_emails(self, names, confirm_fn=None):
        if not names:
            return
        fmt = self.options.get("email_format", "first.last")
        gen = None
        for f in EMAIL_FORMATS:
            if f["name"] == fmt:
                gen = f["gen"]
                break
        if not gen:
            gen = EMAIL_FORMATS[0]["gen"]
        emails = []
        for name in names:
            parts = name.lower().strip().split()
            if len(parts) >= 2:
                first, last = parts[0], parts[-1]
                first = re.sub(r'[^a-z]', '', first)
                last = re.sub(r'[^a-z]', '', last)
                if first and last:
                    email = gen(first, last) + f"@{self.target}"
                    emails.append(email)
        if emails:
            self._add("info", f"Generated {len(emails)} email addresses ({fmt} format)", "\n".join(emails[:100]), "", "T1589.002")
        return emails

    def username_generation(self, names=None):
        if not names:
            names = self.options.get("employees", [])
        if not names:
            return
        usernames = set()
        for name in names:
            parts = name.lower().strip().split()
            if len(parts) < 2:
                continue
            first, last = re.sub(r'[^a-z]', '', parts[0]), re.sub(r'[^a-z]', '', parts[-1])
            if not first or not last:
                continue
            usernames.update([
                f"{first}.{last}", f"{first}{last}", f"{first[0]}{last}",
                f"{first}{last[0]}", f"{first}_{last}", f"{first}-{last}",
                f"{last}.{first}", f"{last}{first}", f"{last}{first[0]}",
            ])
        if usernames:
            self._add("info", f"Generated {len(usernames)} username candidates", "\n".join(sorted(usernames)[:100]), "", "T1589")

    def github_recon(self, confirm_fn=None):
        org = self.target.split(".")[0]
        cmd = f'curl -sS "https://api.github.com/orgs/{org}/repos?per_page=100&sort=updated" --max-time 10'
        if not self._confirm(f"Check GitHub org '{org}': {cmd}", confirm_fn):
            return
        out, _, rc = _run(cmd, timeout=15)
        if rc != 0 or not out:
            return
        try:
            repos = json.loads(out)
            if isinstance(repos, list) and repos:
                repo_info = []
                for r in repos[:30]:
                    repo_info.append(f"  {r.get('name', '?'):30s} {r.get('language', '?'):15s} stars:{r.get('stargazers_count', 0)}")
                self._add("info", f"GitHub org '{org}': {len(repos)} public repos", "\n".join(repo_info), "", "T1593.003")

                for r in repos[:5]:
                    commits_cmd = f'curl -sS "https://api.github.com/repos/{org}/{r["name"]}/commits?per_page=5" --max-time 10'
                    cout, _, crc = _run(commits_cmd, timeout=15)
                    if crc == 0 and cout:
                        try:
                            commits = json.loads(cout)
                            for c in commits:
                                author = c.get("commit", {}).get("author", {})
                                email = author.get("email", "")
                                name = author.get("name", "")
                                if email and self.target in email:
                                    self.employees.append(name)
                                    self._add("info", f"GitHub commit author: {name} <{email}>", f"Repo: {r['name']}", "", "T1589.002")
                        except:
                            pass
        except json.JSONDecodeError:
            pass

    def breach_check_reference(self):
        detail = "Breach database checking resources (manual verification required):\n\n"
        sources = [
            ("HaveIBeenPwned", "https://haveibeenpwned.com", "Check if domain emails appear in known breaches"),
            ("DeHashed", "https://dehashed.com", "Search by email, username, IP, name, phone, VIN, address"),
            ("IntelX", "https://intelx.io", "Search engine for leaked data, darknet, OSINT"),
            ("Snusbase", "https://snusbase.com", "Database search engine for leaked data"),
            ("LeakCheck", "https://leakcheck.io", "Check if credentials have been compromised"),
            ("BreachDirectory", "https://breachdirectory.org", "Free breach database search"),
            ("Phonebook.cz", "https://phonebook.cz", "Email, URL, and domain search from IntelX"),
        ]
        for name, url, desc in sources:
            detail += f"  {name:20s} {url}\n    {desc}\n\n"
        detail += f"Search for: *@{self.target} in the above databases\n"
        detail += "Note: Some services require paid subscriptions for full results\n"
        self._add("info", "Breach database references", detail, "", "T1589.002")

    def social_media_reference(self):
        detail = f"Social media presence check for '{self.target}':\n\n"
        for category, platforms in SOCIAL_PLATFORMS.items():
            detail += f"  {category}:\n"
            for p in platforms:
                detail += f"    - {p}\n"
            detail += "\n"
        detail += "Search strategies:\n"
        detail += f'  1. Google: site:linkedin.com/company "{self.target.split(".")[0]}"\n'
        detail += f'  2. Google: site:github.com "{self.target}"\n'
        detail += f'  3. Google: "{self.target}" site:pastebin.com\n'
        detail += f'  4. Twitter/X: search for @{self.target.split(".")[0]} or #{self.target.split(".")[0]}\n'
        self._add("info", f"Social media platforms to check ({sum(len(v) for v in SOCIAL_PLATFORMS.values())} platforms)", detail, "", "T1593.001")

    def document_metadata_reference(self):
        detail = "Document metadata extraction reference:\n\n"
        detail += "Tools:\n"
        detail += "  exiftool <file>           - Extract all metadata from any file\n"
        detail += "  pdfinfo <file>            - PDF metadata\n"
        detail += "  strings <file> | grep @   - Find emails in binaries\n"
        detail += "  python3 -c 'import zipfile; z=zipfile.ZipFile(\"doc.docx\"); print(z.read(\"docProps/core.xml\"))'\n\n"
        detail += "Metadata reveals:\n"
        detail += "  - Author names and usernames (Active Directory usernames in Office docs)\n"
        detail += "  - Software versions (Office version, PDF producer)\n"
        detail += "  - Creation/modification dates\n"
        detail += "  - GPS coordinates (in photos)\n"
        detail += "  - Internal file paths (revealing internal server names)\n"
        detail += "  - Printer names and network paths\n\n"
        detail += f"Google dork: site:{self.target} filetype:pdf OR filetype:doc OR filetype:xls OR filetype:ppt\n"
        self._add("info", "Document metadata extraction reference", detail, "", "T1592.004")

    def job_posting_analysis(self, confirm_fn=None):
        detail = f"Technology stack inference from job postings for {self.target}:\n\n"
        detail += "Search for job postings to identify:\n"
        detail += "  - Programming languages and frameworks in use\n"
        detail += "  - Cloud providers (AWS/Azure/GCP)\n"
        detail += "  - Security tools (SIEM, EDR, WAF vendor)\n"
        detail += "  - Development tools (CI/CD, version control)\n"
        detail += "  - Database technologies\n"
        detail += "  - Internal tool names\n\n"
        detail += "Search queries:\n"
        company = self.target.split(".")[0]
        detail += f'  site:linkedin.com/jobs "{company}"\n'
        detail += f'  site:indeed.com "{company}"\n'
        detail += f'  site:glassdoor.com "{company}" "tech stack"\n'
        detail += f'  "{company}" "we use" OR "our stack" OR "tech stack"\n'
        self._add("info", "Job posting technology inference", detail, "", "T1591.004")

    def run(self, confirm_fn=None):
        print(f"\n[AEGIS] Social/OSINT Reconnaissance: {self.target}")
        print("=" * 60)
        self.email_format_detection(confirm_fn)
        self.github_recon(confirm_fn)
        if self.employees:
            self.generate_emails(self.employees, confirm_fn)
            self.username_generation(self.employees)
        elif self.options.get("employees"):
            self.generate_emails(self.options["employees"], confirm_fn)
            self.username_generation(self.options["employees"])
        self.breach_check_reference()
        self.social_media_reference()
        self.document_metadata_reference()
        self.job_posting_analysis(confirm_fn)
        print(f"\n[AEGIS] Social recon complete: {len(self.findings)} findings")
        return self.findings

    def get_findings(self):
        return self.findings


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python3 social-recon.py <domain> [name1 name2 ...]")
        sys.exit(1)
    target = sys.argv[1]
    employees = sys.argv[2:] if len(sys.argv) > 2 else []
    def confirm(action):
        resp = input(f"\n[?] {action}\n    Execute? [y/n]: ").strip().lower()
        return resp in ("y", "yes")
    mod = SocialRecon(target, {"employees": employees})
    mod.run(confirm_fn=confirm)
    for f in mod.get_findings():
        print(f"  [{f['severity'].upper():8s}] {f['title']}")
