#!/usr/bin/env python3
"""AEGIS Packet Crafting and Protocol Analysis — build, analyze, and decode network packets."""
import struct, socket, os, sys, subprocess, hashlib
from datetime import datetime

class PacketCrafter:
    name = "Packet Crafting & Analysis"
    description = "Build TCP/UDP/ICMP/ARP/DNS packets, capture analysis, protocol decoding, checksum calculation"
    category = "network"
    mitre = ["T1046", "T1498", "T1557"]

    PROTOCOLS = {
        'tcp': 6, 'udp': 17, 'icmp': 1, 'igmp': 2, 'gre': 47, 'esp': 50, 'ah': 51,
    }
    TCP_FLAGS = {'FIN': 0x01, 'SYN': 0x02, 'RST': 0x04, 'PSH': 0x08, 'ACK': 0x10, 'URG': 0x20, 'ECE': 0x40, 'CWR': 0x80}
    ICMP_TYPES = {
        0: 'Echo Reply', 3: 'Destination Unreachable', 4: 'Source Quench', 5: 'Redirect',
        8: 'Echo Request', 9: 'Router Advertisement', 10: 'Router Solicitation',
        11: 'Time Exceeded', 12: 'Parameter Problem', 13: 'Timestamp', 14: 'Timestamp Reply',
        17: 'Address Mask Request', 18: 'Address Mask Reply',
    }

    def __init__(self, target=None, options=None):
        self.target = target
        self.options = options or {}
        self.findings = []
        self.actions = []

    def _log(self, msg):
        self.actions.append({"time": datetime.now().isoformat(), "action": msg})
        print(f"  [PACKET] {msg}")

    def _checksum(self, data):
        if len(data) % 2:
            data += b'\x00'
        s = sum(struct.unpack('!%dH' % (len(data) // 2), data))
        s = (s >> 16) + (s & 0xffff)
        s += s >> 16
        return ~s & 0xffff

    def build_ip_header(self, src_ip, dst_ip, protocol=6, ttl=64, payload_len=0):
        version_ihl = (4 << 4) | 5
        tos = 0
        total_length = 20 + payload_len
        identification = os.getpid() & 0xFFFF
        flags_offset = 0x4000
        header = struct.pack('!BBHHHBBH4s4s',
            version_ihl, tos, total_length, identification, flags_offset,
            ttl, protocol, 0,
            socket.inet_aton(src_ip), socket.inet_aton(dst_ip))
        checksum = self._checksum(header)
        header = struct.pack('!BBHHHBBH4s4s',
            version_ihl, tos, total_length, identification, flags_offset,
            ttl, protocol, checksum,
            socket.inet_aton(src_ip), socket.inet_aton(dst_ip))
        return header

    def build_tcp_packet(self, src_ip, dst_ip, src_port, dst_port, flags='SYN', seq=0, ack=0, data=b''):
        flag_val = 0
        for f in flags.split('|'):
            flag_val |= self.TCP_FLAGS.get(f.strip().upper(), 0)
        offset = 5
        tcp_header = struct.pack('!HHIIBBHHH',
            src_port, dst_port, seq, ack,
            (offset << 4), flag_val, 65535, 0, 0)
        pseudo = struct.pack('!4s4sBBH',
            socket.inet_aton(src_ip), socket.inet_aton(dst_ip),
            0, 6, len(tcp_header) + len(data))
        checksum = self._checksum(pseudo + tcp_header + data)
        tcp_header = struct.pack('!HHIIBBHHH',
            src_port, dst_port, seq, ack,
            (offset << 4), flag_val, 65535, checksum, 0)
        self._log(f"Built TCP packet {src_ip}:{src_port} -> {dst_ip}:{dst_port} [{flags}]")
        return tcp_header + data

    def build_udp_packet(self, src_ip, dst_ip, src_port, dst_port, data=b''):
        length = 8 + len(data)
        udp_header = struct.pack('!HHHH', src_port, dst_port, length, 0)
        pseudo = struct.pack('!4s4sBBH',
            socket.inet_aton(src_ip), socket.inet_aton(dst_ip), 0, 17, length)
        checksum = self._checksum(pseudo + udp_header + data)
        udp_header = struct.pack('!HHHH', src_port, dst_port, length, checksum)
        self._log(f"Built UDP packet {src_ip}:{src_port} -> {dst_ip}:{dst_port}")
        return udp_header + data

    def build_icmp_packet(self, icmp_type=8, code=0, data=b'AEGIS-PING'):
        header = struct.pack('!BBH', icmp_type, code, 0)
        ident = os.getpid() & 0xFFFF
        seq = 1
        header += struct.pack('!HH', ident, seq)
        checksum = self._checksum(header + data)
        header = struct.pack('!BBHHH', icmp_type, code, checksum, ident, seq)
        self._log(f"Built ICMP type={icmp_type} code={code}")
        return header + data

    def build_arp_packet(self, sender_mac, sender_ip, target_mac, target_ip, operation=1):
        hw_type = struct.pack('!H', 1)
        proto_type = struct.pack('!H', 0x0800)
        hw_size = struct.pack('!B', 6)
        proto_size = struct.pack('!B', 4)
        op = struct.pack('!H', operation)
        s_mac = bytes.fromhex(sender_mac.replace(':', ''))
        t_mac = bytes.fromhex(target_mac.replace(':', ''))
        s_ip = socket.inet_aton(sender_ip)
        t_ip = socket.inet_aton(target_ip)
        arp = hw_type + proto_type + hw_size + proto_size + op + s_mac + s_ip + t_mac + t_ip
        self._log(f"Built ARP {'request' if operation == 1 else 'reply'} {sender_ip} -> {target_ip}")
        return arp

    def build_dns_query(self, domain, qtype='A'):
        qtypes = {'A': 1, 'AAAA': 28, 'MX': 15, 'NS': 2, 'TXT': 16, 'SOA': 6, 'CNAME': 5, 'PTR': 12, 'SRV': 33, 'ANY': 255}
        tid = os.getpid() & 0xFFFF
        flags = 0x0100
        header = struct.pack('!HHHHHH', tid, flags, 1, 0, 0, 0)
        qname = b''
        for label in domain.split('.'):
            qname += struct.pack('!B', len(label)) + label.encode()
        qname += b'\x00'
        question = qname + struct.pack('!HH', qtypes.get(qtype.upper(), 1), 1)
        self._log(f"Built DNS query for {domain} ({qtype})")
        return header + question

    def decode_packet(self, data):
        if len(data) < 20:
            return {"error": "Packet too short"}
        result = {}
        version_ihl = data[0]
        version = version_ihl >> 4
        ihl = (version_ihl & 0x0F) * 4
        if version == 4:
            ip_header = struct.unpack('!BBHHHBBH4s4s', data[:20])
            result['ip'] = {
                'version': 4, 'ihl': ihl, 'tos': ip_header[1],
                'total_length': ip_header[2], 'id': ip_header[3],
                'ttl': ip_header[5], 'protocol': ip_header[6],
                'checksum': hex(ip_header[7]),
                'src': socket.inet_ntoa(ip_header[8]),
                'dst': socket.inet_ntoa(ip_header[9]),
            }
            proto = ip_header[6]
            payload = data[ihl:]
            if proto == 6 and len(payload) >= 20:
                tcp = struct.unpack('!HHIIBBHHH', payload[:20])
                flags = []
                for name, val in self.TCP_FLAGS.items():
                    if tcp[5] & val:
                        flags.append(name)
                result['tcp'] = {
                    'src_port': tcp[0], 'dst_port': tcp[1],
                    'seq': tcp[2], 'ack': tcp[3],
                    'flags': '|'.join(flags),
                    'window': tcp[6], 'checksum': hex(tcp[7]),
                }
            elif proto == 17 and len(payload) >= 8:
                udp = struct.unpack('!HHHH', payload[:8])
                result['udp'] = {
                    'src_port': udp[0], 'dst_port': udp[1],
                    'length': udp[2], 'checksum': hex(udp[3]),
                }
            elif proto == 1 and len(payload) >= 8:
                icmp = struct.unpack('!BBHHH', payload[:8])
                result['icmp'] = {
                    'type': icmp[0], 'code': icmp[1],
                    'type_name': self.ICMP_TYPES.get(icmp[0], 'Unknown'),
                    'checksum': hex(icmp[2]),
                    'id': icmp[3], 'seq': icmp[4],
                }
        self._log(f"Decoded packet: {len(data)} bytes")
        return result

    def hex_dump(self, data, width=16):
        lines = []
        for i in range(0, len(data), width):
            chunk = data[i:i+width]
            hex_part = ' '.join(f'{b:02x}' for b in chunk)
            ascii_part = ''.join(chr(b) if 32 <= b < 127 else '.' for b in chunk)
            lines.append(f"  {i:08x}  {hex_part:<{width*3}}  {ascii_part}")
        return '\n'.join(lines)

    def analyze_pcap(self, pcap_path, confirm_fn=None):
        if confirm_fn and not confirm_fn(f"Analyze PCAP file {pcap_path}?"):
            return {"status": "cancelled"}
        if not os.path.isfile(pcap_path):
            return {"error": f"File not found: {pcap_path}"}
        analyses = {}
        cmds = {
            "protocol_hierarchy": f"tshark -r {pcap_path} -q -z io,phs",
            "conversations": f"tshark -r {pcap_path} -q -z conv,tcp",
            "top_talkers": f"tshark -r {pcap_path} -q -z endpoints,ip",
            "dns_queries": f"tshark -r {pcap_path} -Y dns.flags.response==0 -T fields -e dns.qry.name | sort | uniq -c | sort -rn | head -20",
            "http_requests": f"tshark -r {pcap_path} -Y http.request -T fields -e http.request.method -e http.host -e http.request.uri | head -30",
        }
        for name, cmd in cmds.items():
            try:
                result = subprocess.run(cmd, shell=True, capture_output=True, timeout=30)
                analyses[name] = result.stdout.decode(errors='replace').strip()[:2000]
            except Exception as e:
                analyses[name] = f"Error: {e}"
        self._log(f"PCAP analysis complete: {pcap_path}")
        return analyses

    def run(self, confirm_fn=None):
        op = self.options.get('operation', 'decode')
        if op == 'pcap':
            return self.analyze_pcap(self.target, confirm_fn)
        return {"info": "Use specific methods: build_tcp_packet, build_udp_packet, build_icmp_packet, build_arp_packet, build_dns_query, decode_packet, analyze_pcap"}

    def get_findings(self):
        return self.findings

if __name__ == "__main__":
    pc = PacketCrafter()
    if len(sys.argv) > 1:
        if sys.argv[1] == 'pcap' and len(sys.argv) > 2:
            r = pc.analyze_pcap(sys.argv[2])
            for k, v in r.items():
                print(f"\n=== {k} ===\n{v}")
        elif sys.argv[1] == 'dns' and len(sys.argv) > 2:
            pkt = pc.build_dns_query(sys.argv[2], sys.argv[3] if len(sys.argv) > 3 else 'A')
            print(pc.hex_dump(pkt))
        elif sys.argv[1] == 'tcp':
            pkt = pc.build_tcp_packet('10.0.0.1', '10.0.0.2', 12345, 80, 'SYN')
            print(pc.hex_dump(pkt))
    else:
        print("Usage: packet-craft.py [pcap <file> | dns <domain> [type] | tcp]")
