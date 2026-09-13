#!/usr/bin/env python3
"""Digital evidence management system with chain of custody and integrity verification"""
import json, os, sys, hashlib, shutil, time
from datetime import datetime, timezone

# =============================================================================
# EVIDENCE TEMPLATES
# =============================================================================
EVIDENCE_CATEGORIES = [
    "disk_image", "memory_dump", "log_file", "screenshot", "pcap",
    "malware_sample", "config_file", "credential", "document",
    "email", "registry_hive", "command_output", "note", "photo",
    "video", "network_capture", "binary", "script", "database",
]

CUSTODY_ACTIONS = [
    "collected", "received", "transferred", "analyzed", "copied",
    "viewed", "exported", "sealed", "unsealed", "archived",
    "restored", "verified", "tagged", "classified",
]

CLASSIFICATION_LEVELS = [
    "UNCLASSIFIED", "CUI", "CONFIDENTIAL", "SECRET", "TOP SECRET",
]

LEGAL_HOLD_TEMPLATE = """
LEGAL HOLD NOTICE
=================
Date: {date}
Hold ID: {hold_id}
Matter: {matter}

TO: {recipient}

You are hereby notified that a legal hold has been placed on all
evidence related to the following matter:

  {matter_description}

You must preserve and not delete, modify, or destroy any of the
following types of evidence:

{evidence_types}

This hold remains in effect until you receive written notice of
its release. If you have any questions, contact:

  {contact}

Failure to comply with this hold may result in legal sanctions.
"""

DECLARATION_TEMPLATE = """
DECLARATION OF DIGITAL EVIDENCE
================================
I, {examiner_name}, declare under penalty of perjury that:

1. I am a digital forensics examiner with {experience} years of experience.

2. On {collection_date}, I collected the following digital evidence
   from {source_description}:

{evidence_list}

3. The evidence was collected using the following tools and methods:
   {tools_used}

4. I maintained chain of custody throughout the collection process.
   The evidence has been stored in {storage_location}.

5. The integrity of the evidence can be verified using the following
   cryptographic hashes computed at the time of collection:

{hash_list}

6. The evidence has not been altered since collection. Integrity
   verification was last performed on {last_verified}.

Signed: {examiner_name}
Date: {declaration_date}
"""

WITNESS_TEMPLATE = """
EXPERT WITNESS STATEMENT
=========================
Case: {case_reference}
Date: {date}
Expert: {expert_name}
Qualifications: {qualifications}

SUMMARY OF ANALYSIS
--------------------
I was engaged to analyze digital evidence related to {case_description}.

METHODOLOGY
-----------
The following methodology was employed:
{methodology}

FINDINGS
--------
{findings}

OPINION
-------
Based on my analysis, it is my professional opinion that:
{opinion}

LIMITATIONS
-----------
{limitations}

Signature: {expert_name}
Date: {date}
"""


# =============================================================================
# EVIDENCE MANAGER
# =============================================================================
class EvidenceManager:
    name = "Evidence Manager"
    description = "Digital evidence management with chain of custody and integrity verification"
    category = "reporting"
    mitre = []

    def __init__(self, evidence_dir="missions/evidence"):
        self.evidence_dir = evidence_dir
        self.manifest_path = os.path.join(evidence_dir, "manifest.json")
        self.custody_log_path = os.path.join(evidence_dir, "custody_log.json")
        self.items = []
        self.custody_log = []
        self.legal_holds = []
        self.operator = os.environ.get("USER", "unknown")
        os.makedirs(evidence_dir, exist_ok=True)
        self._load()

    def _load(self):
        if os.path.exists(self.manifest_path):
            try:
                with open(self.manifest_path, "r") as f:
                    self.items = json.load(f)
            except (json.JSONDecodeError, IOError):
                self.items = []
        if os.path.exists(self.custody_log_path):
            try:
                with open(self.custody_log_path, "r") as f:
                    self.custody_log = json.load(f)
            except (json.JSONDecodeError, IOError):
                self.custody_log = []

    def _save(self):
        with open(self.manifest_path, "w") as f:
            json.dump(self.items, f, indent=2)
        with open(self.custody_log_path, "w") as f:
            json.dump(self.custody_log, f, indent=2)

    def _hash_data(self, data):
        if isinstance(data, str):
            data = data.encode("utf-8")
        return hashlib.sha256(data).hexdigest()

    def _hash_file(self, filepath):
        sha256 = hashlib.sha256()
        md5 = hashlib.md5()
        sha1 = hashlib.sha1()
        with open(filepath, "rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                sha256.update(chunk)
                md5.update(chunk)
                sha1.update(chunk)
        return {"sha256": sha256.hexdigest(), "md5": md5.hexdigest(), "sha1": sha1.hexdigest()}

    def _generate_id(self):
        return hashlib.sha256(f"{time.time()}{os.getpid()}".encode()).hexdigest()[:16]

    def _log_custody(self, evidence_id, action, details=""):
        entry = {
            "evidence_id": evidence_id,
            "action": action,
            "operator": self.operator,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "details": details,
        }
        self.custody_log.append(entry)

    def add_file(self, filepath, category="binary", finding_id=None, phase=None,
                 classification="UNCLASSIFIED", notes=""):
        if not os.path.exists(filepath):
            print(f"  File not found: {filepath}")
            return None
        evidence_id = self._generate_id()
        hashes = self._hash_file(filepath)
        filename = os.path.basename(filepath)
        dest_dir = os.path.join(self.evidence_dir, evidence_id)
        os.makedirs(dest_dir, exist_ok=True)
        dest_path = os.path.join(dest_dir, filename)
        shutil.copy2(filepath, dest_path)
        item = {
            "id": evidence_id,
            "type": "file",
            "filename": filename,
            "original_path": os.path.abspath(filepath),
            "stored_path": dest_path,
            "size": os.path.getsize(filepath),
            "hashes": hashes,
            "category": category,
            "finding_id": finding_id,
            "phase": phase,
            "classification": classification,
            "notes": notes,
            "collected_at": datetime.now(timezone.utc).isoformat(),
            "collected_by": self.operator,
            "verified": True,
            "legal_hold": False,
        }
        self.items.append(item)
        self._log_custody(evidence_id, "collected", f"File: {filename} ({hashes['sha256'][:16]}...)")
        self._save()
        print(f"  Evidence collected: {evidence_id} ({filename})")
        print(f"  SHA-256: {hashes['sha256']}")
        return evidence_id

    def add_text(self, content, title="Untitled", category="note", finding_id=None,
                 phase=None, classification="UNCLASSIFIED"):
        evidence_id = self._generate_id()
        content_hash = self._hash_data(content)
        dest_dir = os.path.join(self.evidence_dir, evidence_id)
        os.makedirs(dest_dir, exist_ok=True)
        safe_title = "".join(c for c in title if c.isalnum() or c in "._- ").strip()[:50]
        dest_path = os.path.join(dest_dir, f"{safe_title}.txt")
        with open(dest_path, "w") as f:
            f.write(content)
        item = {
            "id": evidence_id,
            "type": "text",
            "title": title,
            "stored_path": dest_path,
            "size": len(content.encode("utf-8")),
            "hashes": {"sha256": content_hash},
            "category": category,
            "finding_id": finding_id,
            "phase": phase,
            "classification": classification,
            "notes": "",
            "collected_at": datetime.now(timezone.utc).isoformat(),
            "collected_by": self.operator,
            "verified": True,
            "legal_hold": False,
        }
        self.items.append(item)
        self._log_custody(evidence_id, "collected", f"Text: {title} ({content_hash[:16]}...)")
        self._save()
        print(f"  Evidence collected: {evidence_id} ({title})")
        return evidence_id

    def add_command_output(self, command, output, finding_id=None, phase=None):
        content = f"Command: {command}\nTimestamp: {datetime.now(timezone.utc).isoformat()}\nOperator: {self.operator}\n\n--- OUTPUT ---\n{output}"
        return self.add_text(content, title=f"cmd_{command.split()[0]}", category="command_output",
                            finding_id=finding_id, phase=phase)

    def verify_integrity(self, evidence_id=None):
        items_to_check = [i for i in self.items if i["id"] == evidence_id] if evidence_id else self.items
        results = []
        for item in items_to_check:
            path = item.get("stored_path", "")
            if not os.path.exists(path):
                results.append({"id": item["id"], "status": "MISSING", "detail": f"File not found: {path}"})
                item["verified"] = False
                continue
            if item["type"] == "file":
                current_hashes = self._hash_file(path)
            else:
                with open(path, "rb") as f:
                    current_hashes = {"sha256": hashlib.sha256(f.read()).hexdigest()}
            original_sha256 = item["hashes"].get("sha256", "")
            if current_hashes["sha256"] == original_sha256:
                results.append({"id": item["id"], "status": "VERIFIED", "detail": "Integrity confirmed"})
                item["verified"] = True
            else:
                results.append({"id": item["id"], "status": "TAMPERED", "detail": f"Hash mismatch! Original: {original_sha256[:16]}... Current: {current_hashes['sha256'][:16]}..."})
                item["verified"] = False
            self._log_custody(item["id"], "verified", results[-1]["status"])
        self._save()
        return results

    def search(self, query=None, category=None, finding_id=None, classification=None, date_from=None, date_to=None):
        results = self.items
        if category:
            results = [i for i in results if i.get("category") == category]
        if finding_id:
            results = [i for i in results if i.get("finding_id") == finding_id]
        if classification:
            results = [i for i in results if i.get("classification") == classification]
        if query:
            q = query.lower()
            results = [i for i in results if q in json.dumps(i).lower()]
        if date_from:
            results = [i for i in results if i.get("collected_at", "") >= date_from]
        if date_to:
            results = [i for i in results if i.get("collected_at", "") <= date_to]
        return results

    def get_custody_chain(self, evidence_id):
        return [e for e in self.custody_log if e["evidence_id"] == evidence_id]

    def set_legal_hold(self, evidence_id, matter, hold=True):
        for item in self.items:
            if item["id"] == evidence_id:
                item["legal_hold"] = hold
                action = "Legal hold placed" if hold else "Legal hold released"
                self._log_custody(evidence_id, "sealed" if hold else "unsealed", f"{action}: {matter}")
                self._save()
                print(f"  {action} on {evidence_id}")
                return True
        return False

    def export_bundle(self, output_dir, evidence_ids=None):
        os.makedirs(output_dir, exist_ok=True)
        items_to_export = self.items if not evidence_ids else [i for i in self.items if i["id"] in evidence_ids]
        manifest = {
            "export_date": datetime.now(timezone.utc).isoformat(),
            "exported_by": self.operator,
            "item_count": len(items_to_export),
            "items": [],
        }
        for item in items_to_export:
            src = item.get("stored_path", "")
            if os.path.exists(src):
                dest = os.path.join(output_dir, item["id"], os.path.basename(src))
                os.makedirs(os.path.dirname(dest), exist_ok=True)
                shutil.copy2(src, dest)
            chain = self.get_custody_chain(item["id"])
            manifest["items"].append({**item, "custody_chain": chain})
            self._log_custody(item["id"], "exported", f"Exported to {output_dir}")
        manifest_path = os.path.join(output_dir, "evidence_manifest.json")
        with open(manifest_path, "w") as f:
            json.dump(manifest, f, indent=2)
        self._save()
        print(f"  Exported {len(items_to_export)} items to {output_dir}")
        print(f"  Manifest: {manifest_path}")
        return manifest_path

    def generate_declaration(self, examiner_name, experience_years, source_description, tools_used):
        evidence_list = ""
        hash_list = ""
        for item in self.items:
            name = item.get("filename", item.get("title", "unknown"))
            evidence_list += f"   - {name} (Category: {item['category']}, Size: {item.get('size', 0)} bytes)\n"
            hash_list += f"   {name}: SHA-256 = {item['hashes'].get('sha256', 'N/A')}\n"
        return DECLARATION_TEMPLATE.format(
            examiner_name=examiner_name,
            experience=experience_years,
            collection_date=self.items[0]["collected_at"][:10] if self.items else "N/A",
            source_description=source_description,
            evidence_list=evidence_list,
            tools_used=tools_used,
            storage_location=os.path.abspath(self.evidence_dir),
            hash_list=hash_list,
            last_verified=datetime.now(timezone.utc).isoformat(),
            declaration_date=datetime.now().strftime("%Y-%m-%d"),
        )

    def generate_legal_hold_notice(self, matter, recipient, matter_description, evidence_types, contact):
        types_str = "\n".join(f"  - {t}" for t in evidence_types)
        return LEGAL_HOLD_TEMPLATE.format(
            date=datetime.now().strftime("%Y-%m-%d"),
            hold_id=self._generate_id()[:8].upper(),
            matter=matter,
            recipient=recipient,
            matter_description=matter_description,
            evidence_types=types_str,
            contact=contact,
        )

    def generate_witness_statement(self, expert_name, qualifications, case_reference,
                                    case_description, methodology, findings, opinion, limitations):
        return WITNESS_TEMPLATE.format(
            case_reference=case_reference,
            date=datetime.now().strftime("%Y-%m-%d"),
            expert_name=expert_name,
            qualifications=qualifications,
            case_description=case_description,
            methodology=methodology,
            findings=findings,
            opinion=opinion,
            limitations=limitations,
        )

    def get_stats(self):
        categories = {}
        for item in self.items:
            cat = item.get("category", "unknown")
            categories[cat] = categories.get(cat, 0) + 1
        total_size = sum(i.get("size", 0) for i in self.items)
        verified = sum(1 for i in self.items if i.get("verified"))
        held = sum(1 for i in self.items if i.get("legal_hold"))
        return {
            "total_items": len(self.items),
            "total_size_bytes": total_size,
            "total_size_mb": round(total_size / 1048576, 2),
            "categories": categories,
            "verified": verified,
            "unverified": len(self.items) - verified,
            "legal_holds": held,
            "custody_entries": len(self.custody_log),
        }

    def run(self, confirm_fn=None):
        print("\n" + "=" * 60)
        print(" DIGITAL EVIDENCE MANAGER")
        print("=" * 60)
        stats = self.get_stats()
        print(f"\n  Items: {stats['total_items']} ({stats['total_size_mb']} MB)")
        print(f"  Verified: {stats['verified']} | Unverified: {stats['unverified']}")
        print(f"  Legal holds: {stats['legal_holds']}")
        print(f"  Custody entries: {stats['custody_entries']}")
        print("\nCommands:")
        print("  [1] Add file evidence")
        print("  [2] Add text/note evidence")
        print("  [3] List all evidence")
        print("  [4] Verify integrity")
        print("  [5] View custody chain")
        print("  [6] Search evidence")
        print("  [7] Export bundle")
        print("  [8] Generate declaration")
        print("  [q] Quit")
        while True:
            try:
                choice = input("\nEvidence> ").strip()
            except (EOFError, KeyboardInterrupt):
                break
            if choice == "q":
                break
            elif choice == "1":
                path = input("  File path: ").strip()
                cat = input(f"  Category ({', '.join(EVIDENCE_CATEGORIES[:6])}): ").strip() or "binary"
                notes = input("  Notes: ").strip()
                self.add_file(path, category=cat, notes=notes)
            elif choice == "2":
                title = input("  Title: ").strip()
                print("  Content (end with empty line):")
                lines = []
                while True:
                    line = input()
                    if not line:
                        break
                    lines.append(line)
                self.add_text("\n".join(lines), title=title)
            elif choice == "3":
                if not self.items:
                    print("  No evidence items.")
                else:
                    for item in self.items:
                        name = item.get("filename", item.get("title", "?"))
                        status = "OK" if item.get("verified") else "UNVERIFIED"
                        hold = " [HOLD]" if item.get("legal_hold") else ""
                        print(f"  {item['id'][:12]}  {item['category']:15s}  {name:30s}  {status}{hold}")
            elif choice == "4":
                results = self.verify_integrity()
                for r in results:
                    color = "" if r["status"] == "VERIFIED" else "!! "
                    print(f"  {color}{r['id'][:12]}: {r['status']} - {r['detail']}")
            elif choice == "5":
                eid = input("  Evidence ID (first 12 chars): ").strip()
                matches = [i for i in self.items if i["id"].startswith(eid)]
                if not matches:
                    print("  Not found.")
                else:
                    chain = self.get_custody_chain(matches[0]["id"])
                    for entry in chain:
                        print(f"  {entry['timestamp'][:19]}  {entry['operator']:12s}  {entry['action']:12s}  {entry.get('details', '')}")
            elif choice == "6":
                query = input("  Search term: ").strip()
                results = self.search(query=query)
                print(f"  Found {len(results)} items:")
                for item in results:
                    name = item.get("filename", item.get("title", "?"))
                    print(f"    {item['id'][:12]}  {name}")
            elif choice == "7":
                out_dir = input("  Output directory: ").strip() or "evidence_export"
                self.export_bundle(out_dir)
            elif choice == "8":
                name = input("  Examiner name: ").strip()
                exp = input("  Years of experience: ").strip()
                source = input("  Source description: ").strip()
                tools = input("  Tools used: ").strip()
                print("\n" + self.generate_declaration(name, exp, source, tools))


if __name__ == "__main__":
    em = EvidenceManager()
    em.run()
