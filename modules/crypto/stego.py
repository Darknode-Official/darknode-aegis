#!/usr/bin/env python3
"""AEGIS Steganography Tools — hide and extract data in images and files."""
import os, sys, struct, hashlib, math, subprocess
from datetime import datetime

class Steganography:
    name = "Steganography Tools"
    description = "Hide data in images (LSB), detect steganography, extract hidden data, metadata stripping"
    category = "crypto"
    mitre = ["T1027.003", "T1001.002"]

    def __init__(self, target=None, options=None):
        self.target = target
        self.options = options or {}
        self.findings = []
        self.actions = []

    def _log(self, msg):
        self.actions.append({"time": datetime.now().isoformat(), "action": msg})
        print(f"  [STEGO] {msg}")

    def _has_tool(self, name):
        try:
            subprocess.run(['which', name], capture_output=True, timeout=5)
            return True
        except Exception:
            return False

    def lsb_embed(self, image_path, message, output_path=None, confirm_fn=None):
        try:
            from PIL import Image
        except ImportError:
            return self._steghide_embed(image_path, message, output_path, confirm_fn)

        if confirm_fn and not confirm_fn(f"Embed {len(message)} bytes into {image_path} via LSB?"):
            return {"status": "cancelled"}
        if not os.path.isfile(image_path):
            return {"error": f"File not found: {image_path}"}
        img = Image.open(image_path).convert('RGB')
        pixels = list(img.getdata())
        msg_bytes = message.encode('utf-8') if isinstance(message, str) else message
        length_header = struct.pack('>I', len(msg_bytes))
        payload = length_header + msg_bytes
        bits = []
        for byte in payload:
            for i in range(7, -1, -1):
                bits.append((byte >> i) & 1)
        capacity = len(pixels) * 3
        if len(bits) > capacity:
            return {"error": f"Message too large. Capacity: {capacity // 8} bytes, need: {len(payload)} bytes"}
        new_pixels = []
        bit_idx = 0
        for r, g, b in pixels:
            nr = (r & 0xFE) | bits[bit_idx] if bit_idx < len(bits) else r
            bit_idx += 1
            ng = (g & 0xFE) | bits[bit_idx] if bit_idx < len(bits) else g
            bit_idx += 1
            nb = (b & 0xFE) | bits[bit_idx] if bit_idx < len(bits) else b
            bit_idx += 1
            new_pixels.append((nr, ng, nb))
        out_img = Image.new('RGB', img.size)
        out_img.putdata(new_pixels)
        out = output_path or image_path.rsplit('.', 1)[0] + '_stego.png'
        out_img.save(out, 'PNG')
        self._log(f"Embedded {len(msg_bytes)} bytes into {out}")
        return {"status": "success", "output": out, "bytes_hidden": len(msg_bytes), "capacity": capacity // 8}

    def lsb_extract(self, image_path):
        try:
            from PIL import Image
        except ImportError:
            return self._steghide_extract(image_path)
        if not os.path.isfile(image_path):
            return {"error": f"File not found: {image_path}"}
        img = Image.open(image_path).convert('RGB')
        pixels = list(img.getdata())
        bits = []
        for r, g, b in pixels:
            bits.append(r & 1)
            bits.append(g & 1)
            bits.append(b & 1)
        header_bits = bits[:32]
        length = 0
        for b in header_bits:
            length = (length << 1) | b
        if length <= 0 or length > len(bits) // 8:
            return {"status": "no_data", "message": "No hidden data detected (invalid length header)"}
        msg_bits = bits[32:32 + length * 8]
        msg_bytes = bytearray()
        for i in range(0, len(msg_bits), 8):
            byte = 0
            for bit in msg_bits[i:i+8]:
                byte = (byte << 1) | bit
            msg_bytes.append(byte)
        try:
            text = msg_bytes.decode('utf-8')
            self._log(f"Extracted {len(msg_bytes)} bytes from {image_path}")
            return {"status": "found", "message": text, "bytes": len(msg_bytes)}
        except UnicodeDecodeError:
            self._log(f"Extracted {len(msg_bytes)} bytes (binary) from {image_path}")
            return {"status": "found", "data_hex": msg_bytes.hex(), "bytes": len(msg_bytes)}

    def _steghide_embed(self, image_path, message, output_path, confirm_fn):
        if not self._has_tool('steghide'):
            return {"error": "Neither PIL nor steghide available. Install: pip3 install Pillow OR sudo apt install steghide"}
        if confirm_fn and not confirm_fn(f"Use steghide to embed data into {image_path}?"):
            return {"status": "cancelled"}
        import tempfile
        with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as f:
            f.write(message if isinstance(message, str) else message.decode())
            tmp = f.name
        out = output_path or image_path.rsplit('.', 1)[0] + '_stego' + '.' + image_path.rsplit('.', 1)[-1]
        subprocess.run(['cp', image_path, out])
        result = subprocess.run(['steghide', 'embed', '-cf', out, '-ef', tmp, '-p', '', '-f'], capture_output=True)
        os.unlink(tmp)
        if result.returncode == 0:
            self._log(f"steghide embed successful: {out}")
            return {"status": "success", "output": out}
        return {"error": result.stderr.decode()}

    def _steghide_extract(self, image_path):
        if not self._has_tool('steghide'):
            return {"error": "Neither PIL nor steghide available"}
        result = subprocess.run(['steghide', 'extract', '-sf', image_path, '-p', '', '-xf', '-', '-f'], capture_output=True)
        if result.returncode == 0:
            return {"status": "found", "message": result.stdout.decode(errors='replace')}
        return {"status": "no_data", "message": result.stderr.decode()}

    def detect_stego(self, image_path):
        if not os.path.isfile(image_path):
            return {"error": f"File not found: {image_path}"}
        results = {"file": image_path, "indicators": []}
        with open(image_path, 'rb') as f:
            data = f.read()
        byte_freq = [0] * 256
        for b in data:
            byte_freq[b] += 1
        total = len(data)
        entropy = 0.0
        for count in byte_freq:
            if count > 0:
                p = count / total
                entropy -= p * math.log2(p)
        results["entropy"] = round(entropy, 4)
        results["size"] = total
        if entropy > 7.9:
            results["indicators"].append("Very high entropy (possible encrypted/compressed payload)")
        lsb_count = sum(1 for b in data if b & 1)
        lsb_ratio = lsb_count / total if total > 0 else 0
        results["lsb_ratio"] = round(lsb_ratio, 4)
        if abs(lsb_ratio - 0.5) < 0.01:
            results["indicators"].append("LSB distribution suspiciously uniform (possible LSB steganography)")
        png_end = data.find(b'\x49\x45\x4e\x44\xae\x42\x60\x82')
        if png_end >= 0 and png_end + 8 < total:
            appended = total - (png_end + 8)
            results["indicators"].append(f"Data appended after PNG IEND marker ({appended} bytes)")
            results["appended_bytes"] = appended
        jpg_end = data.rfind(b'\xff\xd9')
        if jpg_end >= 0 and jpg_end + 2 < total and data[:2] == b'\xff\xd8':
            appended = total - (jpg_end + 2)
            if appended > 10:
                results["indicators"].append(f"Data appended after JPEG EOI marker ({appended} bytes)")
                results["appended_bytes"] = appended
        if not results["indicators"]:
            results["indicators"].append("No steganography indicators detected")
        self._log(f"Stego analysis of {image_path}: {len(results['indicators'])} indicators")
        return results

    def strip_metadata(self, image_path, output_path=None, confirm_fn=None):
        if confirm_fn and not confirm_fn(f"Strip metadata from {image_path}?"):
            return {"status": "cancelled"}
        if self._has_tool('exiftool'):
            out = output_path or image_path
            result = subprocess.run(['exiftool', '-all=', '-overwrite_original', out], capture_output=True)
            self._log(f"Stripped metadata from {out}")
            return {"status": "success", "tool": "exiftool"}
        try:
            from PIL import Image
            img = Image.open(image_path)
            clean = Image.new(img.mode, img.size)
            clean.putdata(list(img.getdata()))
            out = output_path or image_path.rsplit('.', 1)[0] + '_clean.' + image_path.rsplit('.', 1)[-1]
            clean.save(out)
            self._log(f"Stripped metadata via PIL: {out}")
            return {"status": "success", "output": out, "tool": "PIL"}
        except ImportError:
            return {"error": "Neither exiftool nor PIL available"}

    def append_data(self, carrier_path, secret_data, output_path=None, confirm_fn=None):
        if confirm_fn and not confirm_fn(f"Append hidden data to {carrier_path}?"):
            return {"status": "cancelled"}
        if not os.path.isfile(carrier_path):
            return {"error": f"File not found: {carrier_path}"}
        out = output_path or carrier_path.rsplit('.', 1)[0] + '_hidden.' + carrier_path.rsplit('.', 1)[-1]
        with open(carrier_path, 'rb') as f:
            carrier = f.read()
        if isinstance(secret_data, str):
            secret_data = secret_data.encode('utf-8')
        marker = b'\x00\x00AEGIS_HIDDEN\x00\x00'
        with open(out, 'wb') as f:
            f.write(carrier)
            f.write(marker)
            f.write(struct.pack('>I', len(secret_data)))
            f.write(secret_data)
        self._log(f"Appended {len(secret_data)} bytes to {out}")
        return {"status": "success", "output": out, "hidden_bytes": len(secret_data)}

    def extract_appended(self, filepath):
        if not os.path.isfile(filepath):
            return {"error": f"File not found: {filepath}"}
        with open(filepath, 'rb') as f:
            data = f.read()
        marker = b'\x00\x00AEGIS_HIDDEN\x00\x00'
        pos = data.find(marker)
        if pos < 0:
            return {"status": "no_data", "message": "No AEGIS hidden data marker found"}
        offset = pos + len(marker)
        length = struct.unpack('>I', data[offset:offset+4])[0]
        payload = data[offset+4:offset+4+length]
        try:
            text = payload.decode('utf-8')
            return {"status": "found", "message": text, "bytes": length}
        except UnicodeDecodeError:
            return {"status": "found", "data_hex": payload.hex(), "bytes": length}

    def zero_width_encode(self, text, secret):
        zwc = {
            '0': '​',  # zero-width space
            '1': '‌',  # zero-width non-joiner
        }
        bits = ''.join(f'{b:08b}' for b in secret.encode('utf-8'))
        encoded = ''.join(zwc.get(b, '') for b in bits)
        mid = len(text) // 2
        result = text[:mid] + encoded + text[mid:]
        self._log(f"Hidden {len(secret)} chars in zero-width characters")
        return result

    def zero_width_decode(self, text):
        zwc_map = {'​': '0', '‌': '1'}
        bits = ''
        for ch in text:
            if ch in zwc_map:
                bits += zwc_map[ch]
        if len(bits) < 8:
            return {"status": "no_data"}
        msg_bytes = bytearray()
        for i in range(0, len(bits) - 7, 8):
            byte = int(bits[i:i+8], 2)
            msg_bytes.append(byte)
        try:
            return {"status": "found", "message": msg_bytes.decode('utf-8')}
        except UnicodeDecodeError:
            return {"status": "found", "data_hex": msg_bytes.hex()}

    def run(self, confirm_fn=None):
        op = self.options.get('operation', 'detect')
        if op == 'detect':
            return self.detect_stego(self.target)
        elif op == 'embed':
            msg = self.options.get('message', '')
            return self.lsb_embed(self.target, msg, confirm_fn=confirm_fn)
        elif op == 'extract':
            return self.lsb_extract(self.target)
        elif op == 'strip':
            return self.strip_metadata(self.target, confirm_fn=confirm_fn)
        elif op == 'append':
            msg = self.options.get('message', '')
            return self.append_data(self.target, msg, confirm_fn=confirm_fn)
        elif op == 'extract_appended':
            return self.extract_appended(self.target)
        return {"error": f"Unknown operation: {op}"}

    def get_findings(self):
        return self.findings

if __name__ == "__main__":
    import argparse
    p = argparse.ArgumentParser(description="AEGIS Steganography")
    p.add_argument("operation", choices=['embed', 'extract', 'detect', 'strip', 'append', 'extract_appended', 'zwencode', 'zwdecode'])
    p.add_argument("target")
    p.add_argument("--message", "-m", default="")
    p.add_argument("--output", "-o", default=None)
    args = p.parse_args()
    s = Steganography(args.target, {'operation': args.operation, 'message': args.message})
    result = s.run()
    if isinstance(result, dict):
        for k, v in result.items():
            print(f"  {k}: {v}")
    else:
        print(result)
