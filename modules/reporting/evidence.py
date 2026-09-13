#!/usr/bin/env python3
"""AEGIS Evidence Manager — chain of custody, hashing, tagging, integrity verification."""
import os, sys, hashlib, json, shutil
from datetime import datetime

class EvidenceManager:
    name = "Evidence Manager"
    description = "Evidence collection with SHA-256 hashing, chain of custody, tagging, integrity verification"
    category = "reporting"

    def __init__(self, evidence_dir="./evidence"):
        self.evidence_dir = evidence_dir
        self.manifest_path = os.path.join(evidence_dir, "manifest.json")
        self.manifest = []
        os.makedirs(evidence_dir, exist_ok=True)
        if os.path.isfile(self.manifest_path):
            with open(self.manifest_path) as f:
                self.manifest = json.load(f)

    def _save_manifest(self):
        with open(self.manifest_path, 'w') as f:
            json.dump(self.manifest, f, indent=2, default=str)

    def _hash_file(self, filepath):
        h = hashlib.sha256()
        with open(filepath, 'rb') as f:
            while True:
                chunk = f.read(65536)
                if not chunk:
                    break
                h.update(chunk)
        return h.hexdigest()

    def collect(self, filepath, tags=None, finding_id=None, notes="", operator="AEGIS"):
        if not os.path.isfile(filepath):
            return {"error": f"File not found: {filepath}"}
        sha256 = self._hash_file(filepath)
        evidence_id = f"EV-{datetime.now().strftime('%Y%m%d%H%M%S')}-{sha256[:8]}"
        dest = os.path.join(self.evidence_dir, evidence_id + "_" + os.path.basename(filepath))
        shutil.copy2(filepath, dest)
        entry = {
            "id": evidence_id,
            "original_path": os.path.abspath(filepath),
            "stored_path": dest,
            "filename": os.path.basename(filepath),
            "sha256": sha256,
            "size_bytes": os.path.getsize(filepath),
            "collected_at": datetime.now().isoformat(),
            "collected_by": operator,
            "tags": tags or [],
            "finding_id": finding_id,
            "notes": notes,
            "chain_of_custody": [
                {"action": "collected", "by": operator, "at": datetime.now().isoformat(),
                 "method": "file copy", "hash_verified": True}
            ],
        }
        self.manifest.append(entry)
        self._save_manifest()
        print(f"  [EVIDENCE] Collected: {evidence_id} ({os.path.basename(filepath)}) SHA256: {sha256[:16]}...")
        return entry

    def verify(self, evidence_id):
        entry = next((e for e in self.manifest if e["id"] == evidence_id), None)
        if not entry:
            return {"error": f"Evidence not found: {evidence_id}"}
        if not os.path.isfile(entry["stored_path"]):
            return {"status": "MISSING", "id": evidence_id, "message": "Evidence file not found on disk"}
        current_hash = self._hash_file(entry["stored_path"])
        match = current_hash == entry["sha256"]
        result = {
            "id": evidence_id,
            "status": "INTACT" if match else "TAMPERED",
            "original_hash": entry["sha256"],
            "current_hash": current_hash,
            "match": match,
        }
        entry["chain_of_custody"].append({
            "action": "integrity_check",
            "by": "AEGIS",
            "at": datetime.now().isoformat(),
            "result": result["status"],
        })
        self._save_manifest()
        print(f"  [EVIDENCE] Verify {evidence_id}: {result['status']}")
        return result

    def verify_all(self):
        results = []
        for entry in self.manifest:
            r = self.verify(entry["id"])
            results.append(r)
        intact = sum(1 for r in results if r.get("status") == "INTACT")
        return {"total": len(results), "intact": intact, "tampered": len(results) - intact, "results": results}

    def tag(self, evidence_id, tags):
        entry = next((e for e in self.manifest if e["id"] == evidence_id), None)
        if not entry:
            return {"error": f"Evidence not found: {evidence_id}"}
        entry["tags"] = list(set(entry.get("tags", []) + tags))
        self._save_manifest()
        return {"id": evidence_id, "tags": entry["tags"]}

    def link_finding(self, evidence_id, finding_id):
        entry = next((e for e in self.manifest if e["id"] == evidence_id), None)
        if not entry:
            return {"error": f"Evidence not found: {evidence_id}"}
        entry["finding_id"] = finding_id
        self._save_manifest()
        return {"id": evidence_id, "finding_id": finding_id}

    def list_evidence(self, tag=None, finding_id=None):
        items = self.manifest
        if tag:
            items = [e for e in items if tag in e.get("tags", [])]
        if finding_id:
            items = [e for e in items if e.get("finding_id") == finding_id]
        return items

    def export_manifest(self, output_path=None):
        out = output_path or os.path.join(self.evidence_dir, "evidence_manifest.md")
        lines = ["# Evidence Manifest", f"Generated: {datetime.now().isoformat()}", f"Total items: {len(self.manifest)}", ""]
        lines.append("| ID | File | SHA-256 | Size | Collected | Tags |")
        lines.append("|---|---|---|---|---|---|")
        for e in self.manifest:
            lines.append(f"| {e['id']} | {e['filename']} | `{e['sha256'][:16]}...` | {e['size_bytes']} | {e['collected_at'][:19]} | {', '.join(e.get('tags', []))} |")
        lines.append("")
        lines.append("## Chain of Custody")
        for e in self.manifest:
            lines.append(f"\n### {e['id']}: {e['filename']}")
            for c in e.get("chain_of_custody", []):
                lines.append(f"- **{c['action']}** by {c['by']} at {c['at']}" + (f" ({c.get('result', '')})" if c.get('result') else ''))
        text = "\n".join(lines)
        with open(out, 'w') as f:
            f.write(text)
        return {"path": out, "size": len(text)}

    def run(self, confirm_fn=None):
        return {"evidence_count": len(self.manifest), "evidence_dir": self.evidence_dir}

    def get_findings(self):
        return []

if __name__ == "__main__":
    em = EvidenceManager()
    if len(sys.argv) > 1:
        if sys.argv[1] == "collect" and len(sys.argv) > 2:
            print(json.dumps(em.collect(sys.argv[2]), indent=2, default=str))
        elif sys.argv[1] == "verify" and len(sys.argv) > 2:
            print(json.dumps(em.verify(sys.argv[2]), indent=2))
        elif sys.argv[1] == "list":
            for e in em.list_evidence():
                print(f"  {e['id']} | {e['filename']} | {e['sha256'][:16]}... | {', '.join(e.get('tags', []))}")
        elif sys.argv[1] == "export":
            print(json.dumps(em.export_manifest(), indent=2))
        elif sys.argv[1] == "verify-all":
            print(json.dumps(em.verify_all(), indent=2))
    else:
        print("Usage: evidence.py [collect <file> | verify <id> | verify-all | list | export]")
