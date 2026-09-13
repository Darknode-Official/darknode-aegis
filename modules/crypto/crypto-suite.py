#!/usr/bin/env python3
"""AEGIS Cryptographic Operations Toolkit — hash, encrypt, encode, crack, identify."""
import hashlib, hmac, base64, os, sys, re, struct, subprocess, secrets, string, math
from datetime import datetime

class CryptoSuite:
    name = "Cryptographic Operations"
    description = "Hash generation, encryption/decryption, encoding, password generation, hash identification and cracking"
    category = "crypto"
    mitre = ["T1027", "T1140", "T1573"]

    HASH_PATTERNS = [
        (r'^[a-f0-9]{32}$', 'MD5', 'md5', 0),
        (r'^[a-f0-9]{40}$', 'SHA-1', 'sha1', 100),
        (r'^[a-f0-9]{64}$', 'SHA-256', 'sha256', 1400),
        (r'^[a-f0-9]{128}$', 'SHA-512', 'sha512', 1700),
        (r'^[a-f0-9]{32}:[a-f0-9]{32}$', 'NTLM (LM:NT)', 'ntlm', 1000),
        (r'^[a-f0-9]{32}$', 'NTLM', 'ntlm', 1000),
        (r'^\$2[aby]\$\d{2}\$.{53}$', 'bcrypt', 'bcrypt', 3200),
        (r'^\$6\$', 'SHA-512 crypt', 'sha512crypt', 1800),
        (r'^\$5\$', 'SHA-256 crypt', 'sha256crypt', 7400),
        (r'^\$1\$', 'MD5 crypt', 'md5crypt', 500),
        (r'^\$apr1\$', 'Apache MD5', 'apr1', 1600),
        (r'^\$P\$', 'phpBB/WordPress', 'phpass', 400),
        (r'^\$H\$', 'phpBB/WordPress', 'phpass', 400),
        (r'^\{SHA\}', 'LDAP SHA', 'ldap_sha', None),
        (r'^\{SSHA\}', 'LDAP SSHA', 'ldap_ssha', None),
        (r'^[a-f0-9]{16}$', 'MySQL 3.x / DES / Half MD5', 'mysql323', 200),
        (r'^\*[A-F0-9]{40}$', 'MySQL 4.1+', 'mysql41', 300),
        (r'^0x0100', 'MSSQL 2005+', 'mssql05', 132),
        (r'^[a-f0-9]{56}$', 'SHA-224', 'sha224', None),
        (r'^[a-f0-9]{96}$', 'SHA-384', 'sha384', 10800),
        (r'^\$argon2i[d]?\$', 'Argon2', 'argon2', None),
        (r'^\$scrypt\$', 'scrypt', 'scrypt', None),
        (r'^\$krb5tgs\$23\$', 'Kerberos 5 TGS-REP (RC4)', 'kerberoast', 13100),
        (r'^\$krb5asrep\$23\$', 'Kerberos 5 AS-REP', 'asrep', 18200),
        (r'^[a-f0-9]{32}:[a-f0-9]+$', 'NetNTLMv1', 'netntlmv1', 5500),
        (r'^[A-Za-z0-9+/]{27}=$', 'WPA-PBKDF2', 'wpa', 22000),
    ]

    def __init__(self, target=None, options=None):
        self.target = target
        self.options = options or {}
        self.findings = []
        self.actions = []

    def _log(self, msg):
        self.actions.append({"time": datetime.now().isoformat(), "action": msg})
        print(f"  [CRYPTO] {msg}")

    def hash_text(self, text, algorithms=None):
        if algorithms is None:
            algorithms = ['md5', 'sha1', 'sha256', 'sha512']
        results = {}
        data = text.encode('utf-8') if isinstance(text, str) else text
        for algo in algorithms:
            h = hashlib.new(algo)
            h.update(data)
            results[algo] = h.hexdigest()
        self._log(f"Hashed text with {', '.join(algorithms)}")
        return results

    def hash_file(self, filepath):
        if not os.path.isfile(filepath):
            return {"error": f"File not found: {filepath}"}
        algos = ['md5', 'sha1', 'sha256', 'sha512']
        hashers = {a: hashlib.new(a) for a in algos}
        size = 0
        with open(filepath, 'rb') as f:
            while True:
                chunk = f.read(65536)
                if not chunk:
                    break
                size += len(chunk)
                for h in hashers.values():
                    h.update(chunk)
        results = {a: h.hexdigest() for a, h in hashers.items()}
        results['size'] = size
        results['filename'] = os.path.basename(filepath)
        self._log(f"Hashed file: {filepath} ({size} bytes)")
        return results

    def hmac_hash(self, key, message, algo='sha256'):
        k = key.encode('utf-8') if isinstance(key, str) else key
        m = message.encode('utf-8') if isinstance(message, str) else message
        h = hmac.new(k, m, getattr(hashlib, algo))
        result = h.hexdigest()
        self._log(f"HMAC-{algo.upper()} computed")
        return result

    def identify_hash(self, hash_str):
        hash_str = hash_str.strip()
        matches = []
        for pattern, name, htype, hc_mode in self.HASH_PATTERNS:
            if re.match(pattern, hash_str, re.IGNORECASE):
                matches.append({
                    "type": name,
                    "hashcat_mode": hc_mode,
                    "john_format": htype,
                    "length": len(hash_str),
                })
        if not matches:
            matches.append({"type": "Unknown", "length": len(hash_str)})
        self._log(f"Identified hash: {', '.join(m['type'] for m in matches)}")
        return matches

    def encode(self, data, encoding):
        if isinstance(data, str):
            raw = data.encode('utf-8')
        else:
            raw = data
        encoders = {
            'base64': lambda d: base64.b64encode(d).decode(),
            'base32': lambda d: base64.b32encode(d).decode(),
            'hex': lambda d: d.hex(),
            'url': lambda d: ''.join(f'%{b:02X}' for b in d),
            'binary': lambda d: ' '.join(f'{b:08b}' for b in d),
            'octal': lambda d: ' '.join(f'{b:03o}' for b in d),
            'decimal': lambda d: ' '.join(str(b) for b in d),
            'rot13': lambda d: d.decode('utf-8', errors='replace').translate(
                str.maketrans('ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz',
                              'NOPQRSTUVWXYZABCDEFGHIJKLMnopqrstuvwxyzabcdefghijklm')),
        }
        if encoding not in encoders:
            return {"error": f"Unknown encoding: {encoding}. Available: {', '.join(encoders)}"}
        result = encoders[encoding](raw)
        self._log(f"Encoded data as {encoding}")
        return result

    def decode(self, data, encoding):
        decoders = {
            'base64': lambda d: base64.b64decode(d).decode('utf-8', errors='replace'),
            'base32': lambda d: base64.b32decode(d).decode('utf-8', errors='replace'),
            'hex': lambda d: bytes.fromhex(d).decode('utf-8', errors='replace'),
            'url': lambda d: re.sub(r'%([0-9A-Fa-f]{2})', lambda m: chr(int(m.group(1), 16)), d),
            'rot13': lambda d: d.translate(
                str.maketrans('ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz',
                              'NOPQRSTUVWXYZABCDEFGHIJKLMnopqrstuvwxyzabcdefghijklm')),
        }
        if encoding not in decoders:
            return {"error": f"Unknown encoding: {encoding}"}
        result = decoders[encoding](data)
        self._log(f"Decoded data from {encoding}")
        return result

    def xor_crypt(self, data, key):
        if isinstance(data, str):
            data = data.encode('utf-8')
        if isinstance(key, str):
            key = key.encode('utf-8')
        result = bytes(d ^ key[i % len(key)] for i, d in enumerate(data))
        self._log(f"XOR encrypt/decrypt with key length {len(key)}")
        return result

    def generate_password(self, length=20, uppercase=True, lowercase=True, digits=True, special=True):
        charset = ''
        if uppercase: charset += string.ascii_uppercase
        if lowercase: charset += string.ascii_lowercase
        if digits: charset += string.digits
        if special: charset += '!@#$%^&*()-_=+[]{}|;:,.<>?'
        if not charset:
            charset = string.ascii_letters + string.digits
        pw = ''.join(secrets.choice(charset) for _ in range(length))
        entropy = math.log2(len(charset)) * length
        self._log(f"Generated {length}-char password ({entropy:.1f} bits entropy)")
        return {"password": pw, "length": length, "charset_size": len(charset), "entropy_bits": round(entropy, 2)}

    def generate_random(self, num_bytes=32, output_format='hex'):
        raw = secrets.token_bytes(num_bytes)
        formats = {
            'hex': raw.hex(),
            'base64': base64.b64encode(raw).decode(),
            'bytes': repr(raw),
            'int': int.from_bytes(raw, 'big'),
        }
        result = formats.get(output_format, raw.hex())
        self._log(f"Generated {num_bytes} random bytes as {output_format}")
        return result

    def crack_hash(self, hash_str, wordlist_path, algo='md5', confirm_fn=None):
        if confirm_fn:
            msg = f"Attempt dictionary attack on hash using wordlist {wordlist_path}?"
            if not confirm_fn(msg):
                return {"status": "cancelled"}
        if not os.path.isfile(wordlist_path):
            return {"error": f"Wordlist not found: {wordlist_path}"}
        hash_str = hash_str.strip().lower()
        tried = 0
        self._log(f"Starting dictionary attack ({algo}) against {hash_str[:16]}...")
        with open(wordlist_path, 'r', errors='ignore') as f:
            for line in f:
                word = line.strip()
                if not word:
                    continue
                h = hashlib.new(algo)
                h.update(word.encode('utf-8'))
                tried += 1
                if h.hexdigest() == hash_str:
                    self._log(f"Hash cracked after {tried} attempts: {word}")
                    return {"status": "cracked", "plaintext": word, "attempts": tried}
                if tried % 100000 == 0:
                    self._log(f"  ...{tried} candidates tested")
        self._log(f"Hash not cracked ({tried} candidates exhausted)")
        return {"status": "not_found", "attempts": tried}

    def aes_encrypt(self, plaintext, password, confirm_fn=None):
        try:
            result = subprocess.run(
                ['openssl', 'enc', '-aes-256-cbc', '-pbkdf2', '-a', '-pass', f'pass:{password}'],
                input=plaintext.encode(), capture_output=True, timeout=10
            )
            if result.returncode == 0:
                self._log("AES-256-CBC encrypted via openssl")
                return result.stdout.decode().strip()
            return {"error": result.stderr.decode().strip()}
        except FileNotFoundError:
            return {"error": "openssl not found"}
        except Exception as e:
            return {"error": str(e)}

    def aes_decrypt(self, ciphertext, password):
        try:
            result = subprocess.run(
                ['openssl', 'enc', '-aes-256-cbc', '-pbkdf2', '-d', '-a', '-pass', f'pass:{password}'],
                input=ciphertext.encode(), capture_output=True, timeout=10
            )
            if result.returncode == 0:
                self._log("AES-256-CBC decrypted via openssl")
                return result.stdout.decode().strip()
            return {"error": "Decryption failed (wrong password or corrupted data)"}
        except FileNotFoundError:
            return {"error": "openssl not found"}
        except Exception as e:
            return {"error": str(e)}

    def rsa_keygen(self, bits=4096, confirm_fn=None):
        if confirm_fn and not confirm_fn(f"Generate {bits}-bit RSA key pair?"):
            return {"status": "cancelled"}
        try:
            priv = subprocess.run(['openssl', 'genrsa', str(bits)], capture_output=True, timeout=30)
            if priv.returncode != 0:
                return {"error": priv.stderr.decode()}
            pub = subprocess.run(['openssl', 'rsa', '-pubout'], input=priv.stdout, capture_output=True, timeout=10)
            self._log(f"Generated {bits}-bit RSA key pair")
            return {"private_key": priv.stdout.decode(), "public_key": pub.stdout.decode()}
        except FileNotFoundError:
            return {"error": "openssl not found"}

    def entropy(self, data):
        if isinstance(data, str):
            data = data.encode('utf-8')
        if not data:
            return 0.0
        freq = [0] * 256
        for b in data:
            freq[b] += 1
        length = len(data)
        ent = 0.0
        for count in freq:
            if count > 0:
                p = count / length
                ent -= p * math.log2(p)
        self._log(f"Entropy: {ent:.4f} bits/byte ({len(data)} bytes)")
        return round(ent, 4)

    def run(self, confirm_fn=None):
        if not self.target:
            print("Usage: provide target text/hash/file via --target")
            return
        op = self.options.get('operation', 'hash')
        if op == 'hash':
            return self.hash_text(self.target)
        elif op == 'identify':
            return self.identify_hash(self.target)
        elif op == 'file_hash':
            return self.hash_file(self.target)
        elif op == 'encode':
            enc = self.options.get('encoding', 'base64')
            return self.encode(self.target, enc)
        elif op == 'decode':
            enc = self.options.get('encoding', 'base64')
            return self.decode(self.target, enc)
        elif op == 'password':
            length = int(self.options.get('length', 20))
            return self.generate_password(length)
        elif op == 'entropy':
            return self.entropy(self.target)
        elif op == 'crack':
            wordlist = self.options.get('wordlist', '/usr/share/wordlists/rockyou.txt')
            algo = self.options.get('algo', 'md5')
            return self.crack_hash(self.target, wordlist, algo, confirm_fn)
        else:
            return {"error": f"Unknown operation: {op}"}

    def get_findings(self):
        return self.findings

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="AEGIS Crypto Suite")
    parser.add_argument("operation", choices=['hash', 'identify', 'file_hash', 'encode', 'decode', 'password', 'entropy', 'crack', 'random', 'keygen'])
    parser.add_argument("target", nargs='?', default='')
    parser.add_argument("--algo", default='sha256')
    parser.add_argument("--encoding", default='base64')
    parser.add_argument("--length", type=int, default=20)
    parser.add_argument("--wordlist", default='/usr/share/wordlists/rockyou.txt')
    parser.add_argument("--key", default='')
    parser.add_argument("--bytes", type=int, default=32)
    parser.add_argument("--bits", type=int, default=4096)
    args = parser.parse_args()
    cs = CryptoSuite(args.target, vars(args))
    if args.operation == 'random':
        print(cs.generate_random(args.bytes))
    elif args.operation == 'keygen':
        r = cs.rsa_keygen(args.bits)
        if 'error' in r:
            print(f"Error: {r['error']}")
        else:
            print(r['private_key'])
            print(r['public_key'])
    else:
        cs.options['operation'] = args.operation
        result = cs.run()
        if isinstance(result, dict):
            for k, v in result.items():
                print(f"  {k}: {v}")
        else:
            print(result)
