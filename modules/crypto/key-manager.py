#!/usr/bin/env python3
"""AEGIS Key and Certificate Manager — SSH/GPG/TLS key generation and management."""
import os, sys, subprocess, hashlib, json
from datetime import datetime

class KeyManager:
    name = "Key & Certificate Manager"
    description = "SSH/GPG key generation, TLS certificate management, CSR creation, format conversion"
    category = "crypto"
    mitre = ["T1552.004", "T1588.004"]

    def __init__(self, target=None, options=None):
        self.target = target
        self.options = options or {}
        self.findings = []
        self.actions = []

    def _log(self, msg):
        self.actions.append({"time": datetime.now().isoformat(), "action": msg})
        print(f"  [KEYMGR] {msg}")

    def _run_cmd(self, cmd, stdin_data=None, timeout=30):
        try:
            result = subprocess.run(cmd, capture_output=True, timeout=timeout,
                                    input=stdin_data.encode() if isinstance(stdin_data, str) else stdin_data)
            return result.returncode, result.stdout.decode(errors='replace'), result.stderr.decode(errors='replace')
        except FileNotFoundError:
            return -1, '', f"Command not found: {cmd[0]}"
        except subprocess.TimeoutExpired:
            return -1, '', 'Command timed out'

    def ssh_keygen(self, key_type='ed25519', bits=4096, comment='', output_path=None, confirm_fn=None):
        if confirm_fn and not confirm_fn(f"Generate SSH {key_type.upper()} key pair?"):
            return {"status": "cancelled"}
        out = output_path or os.path.expanduser(f'~/.ssh/aegis_{key_type}')
        cmd = ['ssh-keygen', '-t', key_type, '-f', out, '-N', '', '-C', comment or f'aegis@{datetime.now().strftime("%Y%m%d")}']
        if key_type == 'rsa':
            cmd.extend(['-b', str(bits)])
        rc, stdout, stderr = self._run_cmd(cmd)
        if rc == 0:
            pub_path = out + '.pub'
            pub_key = ''
            if os.path.isfile(pub_path):
                with open(pub_path) as f:
                    pub_key = f.read().strip()
            fingerprint = ''
            rc2, fp_out, _ = self._run_cmd(['ssh-keygen', '-lf', out])
            if rc2 == 0:
                fingerprint = fp_out.strip()
            self._log(f"Generated SSH {key_type} key: {out}")
            return {"status": "success", "private_key": out, "public_key": pub_path,
                    "public_key_content": pub_key, "fingerprint": fingerprint}
        return {"error": stderr}

    def gpg_keygen(self, name, email, key_type='RSA', bits=4096, confirm_fn=None):
        if confirm_fn and not confirm_fn(f"Generate GPG key for {name} <{email}>?"):
            return {"status": "cancelled"}
        batch_config = f"""
%no-protection
Key-Type: {key_type}
Key-Length: {bits}
Subkey-Type: {key_type}
Subkey-Length: {bits}
Name-Real: {name}
Name-Email: {email}
Expire-Date: 2y
%commit
"""
        rc, stdout, stderr = self._run_cmd(['gpg', '--batch', '--gen-key'], stdin_data=batch_config)
        if rc == 0:
            self._log(f"Generated GPG key for {name} <{email}>")
            rc2, keys, _ = self._run_cmd(['gpg', '--list-keys', '--keyid-format', 'long', email])
            return {"status": "success", "output": keys}
        return {"error": stderr}

    def ssl_self_signed(self, cn, days=365, bits=4096, output_dir='.', confirm_fn=None):
        if confirm_fn and not confirm_fn(f"Generate self-signed certificate for CN={cn}?"):
            return {"status": "cancelled"}
        key_path = os.path.join(output_dir, f'{cn}.key')
        cert_path = os.path.join(output_dir, f'{cn}.crt')
        cmd = ['openssl', 'req', '-x509', '-newkey', f'rsa:{bits}', '-keyout', key_path,
               '-out', cert_path, '-days', str(days), '-nodes',
               '-subj', f'/CN={cn}/O=AEGIS/C=US']
        rc, stdout, stderr = self._run_cmd(cmd)
        if rc == 0:
            self._log(f"Generated self-signed cert: {cert_path}")
            return {"status": "success", "key": key_path, "cert": cert_path, "cn": cn, "days": days}
        return {"error": stderr}

    def ssl_csr(self, cn, org='', country='US', output_dir='.', bits=4096, confirm_fn=None):
        if confirm_fn and not confirm_fn(f"Generate CSR for CN={cn}?"):
            return {"status": "cancelled"}
        key_path = os.path.join(output_dir, f'{cn}.key')
        csr_path = os.path.join(output_dir, f'{cn}.csr')
        subj = f'/CN={cn}'
        if org: subj += f'/O={org}'
        subj += f'/C={country}'
        cmd = ['openssl', 'req', '-new', '-newkey', f'rsa:{bits}', '-nodes',
               '-keyout', key_path, '-out', csr_path, '-subj', subj]
        rc, stdout, stderr = self._run_cmd(cmd)
        if rc == 0:
            self._log(f"Generated CSR: {csr_path}")
            return {"status": "success", "key": key_path, "csr": csr_path}
        return {"error": stderr}

    def ssl_ca_create(self, cn='AEGIS CA', days=3650, output_dir='.', confirm_fn=None):
        if confirm_fn and not confirm_fn(f"Create Certificate Authority: {cn}?"):
            return {"status": "cancelled"}
        key_path = os.path.join(output_dir, 'ca.key')
        cert_path = os.path.join(output_dir, 'ca.crt')
        cmd = ['openssl', 'req', '-x509', '-newkey', 'rsa:4096', '-keyout', key_path,
               '-out', cert_path, '-days', str(days), '-nodes',
               '-subj', f'/CN={cn}/O=AEGIS CA/C=US']
        rc, stdout, stderr = self._run_cmd(cmd)
        if rc == 0:
            self._log(f"Created CA: {cert_path}")
            return {"status": "success", "ca_key": key_path, "ca_cert": cert_path}
        return {"error": stderr}

    def ssl_sign_csr(self, csr_path, ca_cert, ca_key, days=365, output_path=None, confirm_fn=None):
        if confirm_fn and not confirm_fn(f"Sign CSR {csr_path} with CA?"):
            return {"status": "cancelled"}
        out = output_path or csr_path.replace('.csr', '.crt')
        cmd = ['openssl', 'x509', '-req', '-in', csr_path, '-CA', ca_cert, '-CAkey', ca_key,
               '-CAcreateserial', '-out', out, '-days', str(days)]
        rc, stdout, stderr = self._run_cmd(cmd)
        if rc == 0:
            self._log(f"Signed certificate: {out}")
            return {"status": "success", "cert": out}
        return {"error": stderr}

    def cert_info(self, cert_path):
        if not os.path.isfile(cert_path):
            return {"error": f"File not found: {cert_path}"}
        rc, stdout, stderr = self._run_cmd(['openssl', 'x509', '-in', cert_path, '-text', '-noout'])
        if rc == 0:
            self._log(f"Read certificate: {cert_path}")
            return {"status": "success", "info": stdout}
        return {"error": stderr}

    def convert_format(self, input_path, input_format, output_format, output_path=None, confirm_fn=None):
        if confirm_fn and not confirm_fn(f"Convert {input_path} from {input_format} to {output_format}?"):
            return {"status": "cancelled"}
        conversions = {
            ('pem', 'der'): ['openssl', 'x509', '-in', input_path, '-outform', 'DER', '-out'],
            ('der', 'pem'): ['openssl', 'x509', '-in', input_path, '-inform', 'DER', '-outform', 'PEM', '-out'],
            ('pem', 'pkcs12'): ['openssl', 'pkcs12', '-export', '-in', input_path, '-inkey', input_path, '-out'],
            ('pkcs12', 'pem'): ['openssl', 'pkcs12', '-in', input_path, '-out'],
        }
        key = (input_format.lower(), output_format.lower())
        if key not in conversions:
            return {"error": f"Unsupported conversion: {input_format} -> {output_format}"}
        ext_map = {'der': '.der', 'pem': '.pem', 'pkcs12': '.p12'}
        out = output_path or input_path.rsplit('.', 1)[0] + ext_map.get(output_format, '.out')
        cmd = conversions[key] + [out]
        rc, stdout, stderr = self._run_cmd(cmd)
        if rc == 0:
            self._log(f"Converted {input_format} -> {output_format}: {out}")
            return {"status": "success", "output": out}
        return {"error": stderr}

    def key_strength(self, key_path):
        if not os.path.isfile(key_path):
            return {"error": f"File not found: {key_path}"}
        rc, stdout, stderr = self._run_cmd(['openssl', 'rsa', '-in', key_path, '-text', '-noout'])
        if rc != 0:
            rc, stdout, stderr = self._run_cmd(['openssl', 'ec', '-in', key_path, '-text', '-noout'])
        if rc != 0:
            rc, stdout, stderr = self._run_cmd(['ssh-keygen', '-lf', key_path])
        if rc == 0:
            self._log(f"Key info: {key_path}")
            result = {"info": stdout.strip()}
            import re
            bits_match = re.search(r'(\d+)\s*bit', stdout)
            if bits_match:
                bits = int(bits_match.group(1))
                result["bits"] = bits
                if bits < 1024:
                    result["strength"] = "CRITICAL - Key too short"
                elif bits < 2048:
                    result["strength"] = "WEAK - Below modern standards"
                elif bits < 4096:
                    result["strength"] = "ACCEPTABLE - Consider upgrading to 4096"
                else:
                    result["strength"] = "STRONG"
            return result
        return {"error": "Could not parse key file"}

    def run(self, confirm_fn=None):
        op = self.options.get('operation', 'info')
        if op == 'ssh_keygen':
            kt = self.options.get('key_type', 'ed25519')
            return self.ssh_keygen(kt, confirm_fn=confirm_fn)
        elif op == 'self_signed':
            cn = self.target or 'localhost'
            return self.ssl_self_signed(cn, confirm_fn=confirm_fn)
        elif op == 'csr':
            cn = self.target or 'localhost'
            return self.ssl_csr(cn, confirm_fn=confirm_fn)
        elif op == 'info':
            return self.cert_info(self.target)
        elif op == 'strength':
            return self.key_strength(self.target)
        return {"error": f"Unknown operation: {op}"}

    def get_findings(self):
        return self.findings

if __name__ == "__main__":
    import argparse
    p = argparse.ArgumentParser(description="AEGIS Key Manager")
    p.add_argument("operation", choices=['ssh_keygen', 'gpg_keygen', 'self_signed', 'csr', 'ca_create', 'sign', 'info', 'convert', 'strength'])
    p.add_argument("target", nargs='?', default='')
    p.add_argument("--type", default='ed25519')
    p.add_argument("--cn", default='localhost')
    p.add_argument("--days", type=int, default=365)
    args = p.parse_args()
    km = KeyManager(args.target, {'operation': args.operation, 'key_type': args.type})
    result = km.run()
    if isinstance(result, dict):
        for k, v in result.items():
            val = str(v)[:200]
            print(f"  {k}: {val}")
    else:
        print(result)
