#!/usr/bin/env python3
"""
Generate a realistic, large, reproducible PCAP for DPI benchmarking.
Creates diverse flows across multiple subnets, domains, protocols, and apps.
"""

import struct
import random
import sys
import os

class PCAPWriter:
    def __init__(self, filename, buffer_size=1024*1024):
        self.file = open(filename, 'wb', buffering=buffer_size)
        self.write_global_header()
        self.base_ts = 1700000000
        self.pkt_count = 0
        
    def write_global_header(self):
        # Magic (little-endian), version 2.4, thiszone 0, sigfigs 0, snaplen 65535, linktype Ethernet (1)
        header = struct.pack('<IHHIIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1)
        self.file.write(header)
        
    def write_packet(self, data, ts_sec, ts_usec):
        pkt_header = struct.pack('<IIII', ts_sec, ts_usec, len(data), len(data))
        self.file.write(pkt_header)
        self.file.write(data)
        self.pkt_count += 1
        
    def close(self):
        self.file.close()


def create_ethernet_header(src_mac_bytes, dst_mac_bytes, ethertype=0x0800):
    return dst_mac_bytes + src_mac_bytes + struct.pack('>H', ethertype)


def create_ip_header(src_ip_bytes, dst_ip_bytes, protocol, payload_len, ident=1):
    version_ihl = 0x45
    tos = 0
    total_len = 20 + payload_len
    flags_frag = 0x4000  # Don't fragment
    ttl = 64
    checksum = 0
    header = struct.pack('>BBHHHBBH',
                         version_ihl, tos, total_len,
                         ident, flags_frag,
                         ttl, protocol, checksum)
    return header + src_ip_bytes + dst_ip_bytes


def create_tcp_header(src_port, dst_port, seq, ack, flags, payload_len=0, window=65535):
    data_offset = 5 << 4
    checksum = 0
    urgent = 0
    return struct.pack('>HHIIBBHHH',
                       src_port, dst_port,
                       seq, ack,
                       data_offset, flags,
                       window, checksum, urgent)


def create_udp_header(src_port, dst_port, payload_len):
    length = 8 + payload_len
    checksum = 0
    return struct.pack('>HHHH', src_port, dst_port, length, checksum)


def create_tls_client_hello(sni):
    """Create a fully compliant TLS Client Hello with SNI extension."""
    sni_bytes = sni.encode('ascii')
    sni_entry = struct.pack('>BH', 0, len(sni_bytes)) + sni_bytes
    sni_list = struct.pack('>H', len(sni_entry)) + sni_entry
    sni_ext = struct.pack('>HH', 0x0000, len(sni_list)) + sni_list
    
    # Supported versions extension (TLS 1.3, TLS 1.2)
    supported_versions = struct.pack('>HHB', 0x002b, 5, 4) + struct.pack('>HH', 0x0304, 0x0303)
    
    # Combined extensions
    extensions = sni_ext + supported_versions
    extensions_data = struct.pack('>H', len(extensions)) + extensions
    
    # Client Hello body
    client_version = struct.pack('>H', 0x0303)
    random_bytes = os.urandom(32)
    session_id = struct.pack('B', 0)
    cipher_suites = struct.pack('>H', 6) + struct.pack('>HHH', 0x1301, 0x1302, 0xC02F)
    compression = struct.pack('BB', 1, 0)
    
    client_hello_body = client_version + random_bytes + session_id + cipher_suites + compression + extensions_data
    
    # Handshake header
    handshake = struct.pack('B', 0x01)
    handshake += struct.pack('>I', len(client_hello_body))[1:]  # 3-byte length
    handshake += client_hello_body
    
    # TLS record header (0x16 Handshake, 0x0301 TLS 1.0)
    record = struct.pack('B', 0x16)
    record += struct.pack('>H', 0x0301)
    record += struct.pack('>H', len(handshake))
    record += handshake
    return record


def create_http_request(host, path='/index.html'):
    return f"GET {path} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: Mozilla/5.0 (Benchmark DPI Engine)\r\nAccept: */*\r\nConnection: keep-alive\r\n\r\n".encode('ascii')


def create_dns_query(domain):
    txid = struct.pack('>H', random.randint(1, 65535))
    flags = struct.pack('>H', 0x0100)
    counts = struct.pack('>HHHH', 1, 0, 0, 0)
    question = b''
    for label in domain.split('.'):
        question += struct.pack('B', len(label)) + label.encode('ascii')
    question += struct.pack('B', 0)
    question += struct.pack('>HH', 1, 1)  # Type A, Class IN
    return txid + flags + counts + question


def ip_to_bytes(ip_str):
    return bytes(int(x) for x in ip_str.split('.'))


def generate_pcap(filename, target_packets=100000, seed=42):
    random.seed(seed)
    
    # Domain catalogue with realistic destination IPs
    tls_catalog = [
        # Google
        ('142.250.185.206', 'www.google.com'),
        ('142.250.185.110', 'www.youtube.com'),
        ('142.250.185.174', 'mail.google.com'),
        ('142.250.185.78', 'fonts.gstatic.com'),
        ('142.250.185.238', 'apis.google.com'),
        # Meta
        ('157.240.1.35', 'www.facebook.com'),
        ('157.240.1.174', 'www.instagram.com'),
        ('157.240.1.60', 'static.fbcdn.net'),
        ('157.240.2.1', 'web.whatsapp.com'),
        # Twitter/X
        ('104.244.42.65', 'twitter.com'),
        ('104.244.42.193', 'api.twitter.com'),
        # Amazon
        ('52.94.236.248', 'www.amazon.com'),
        ('54.239.28.85', 'aws.amazon.com'),
        ('52.216.100.1', 's3.amazonaws.com'),
        # Netflix
        ('23.52.167.61', 'www.netflix.com'),
        ('23.52.167.80', 'assets.nflxvideo.net'),
        # Microsoft
        ('13.107.42.14', 'www.microsoft.com'),
        ('20.190.159.0', 'login.microsoftonline.com'),
        ('40.126.31.0', 'portal.azure.com'),
        # Apple
        ('17.253.144.10', 'www.apple.com'),
        ('17.253.144.20', 'www.icloud.com'),
        # GitHub
        ('140.82.114.4', 'github.com'),
        ('140.82.114.6', 'api.github.com'),
        ('185.199.108.133', 'raw.githubusercontent.com'),
        # Discord
        ('104.16.85.20', 'discord.com'),
        ('104.16.86.20', 'gateway.discord.gg'),
        # Zoom
        ('35.186.224.25', 'zoom.us'),
        ('35.186.224.30', 'us02web.zoom.us'),
        # Telegram
        ('35.186.227.140', 'web.telegram.org'),
        ('35.186.227.150', 'api.telegram.org'),
        # TikTok
        ('99.86.0.100', 'www.tiktok.com'),
        ('99.86.0.110', 'v16.tiktokcdn.com'),
        # Spotify
        ('35.186.224.47', 'open.spotify.com'),
        ('35.186.224.50', 'api.spotify.com'),
        # Cloudflare
        ('192.0.78.24', 'www.cloudflare.com'),
        ('104.16.123.96', 'api.cloudflare.com'),
        # Other popular websites
        ('208.80.154.224', 'en.wikipedia.org'),
        ('151.101.65.140', 'www.reddit.com'),
        ('151.101.65.69', 'stackoverflow.com'),
        ('128.84.21.199', 'arxiv.org'),
        ('199.232.192.133', 'kernel.org'),
        ('108.157.14.33', 'slack.com'),
        ('151.101.1.67', 'edition.cnn.com'),
        ('108.160.165.10', 'www.linkedin.com'),
    ]
    
    http_catalog = [
        ('93.184.216.34', 'example.com'),
        ('185.199.108.153', 'httpbin.org'),
        ('188.184.21.108', 'info.cern.ch'),
        ('212.47.249.141', 'mirror.centos.org'),
        ('193.12.214.28', 'speedtest.tele2.net'),
    ]
    
    dns_catalog = [
        'www.google.com', 'www.youtube.com', 'www.facebook.com', 'twitter.com',
        'www.amazon.com', 'www.netflix.com', 'github.com', 'discord.com',
        'zoom.us', 'web.telegram.org', 'www.tiktok.com', 'open.spotify.com',
        'www.cloudflare.com', 'www.microsoft.com', 'www.apple.com', 'en.wikipedia.org',
        'www.reddit.com', 'stackoverflow.com', 'slack.com', 'www.linkedin.com',
    ]
    
    # Precompute Client Hello payloads for TLS catalog
    tls_payloads = []
    for dst_ip, domain in tls_catalog:
        tls_payloads.append((ip_to_bytes(dst_ip), create_tls_client_hello(domain), domain))
        
    http_payloads = []
    for dst_ip, host in http_catalog:
        http_payloads.append((ip_to_bytes(dst_ip), create_http_request(host), host))
        
    dns_servers = [ip_to_bytes('8.8.8.8'), ip_to_bytes('1.1.1.1'), ip_to_bytes('9.9.9.9')]
    
    # Client IP pool (realistic subnets: 192.168.1.0/24, 10.0.0.0/20, 172.16.0.0/20)
    # Plus the specific blocked IP 192.168.1.50
    client_ips = []
    for i in range(1, 255):
        client_ips.append(ip_to_bytes(f"192.168.1.{i}"))
    for i in range(1, 16):
        for j in range(1, 255):
            client_ips.append(ip_to_bytes(f"10.0.{i}.{j}"))
    blocked_client_ip = ip_to_bytes("192.168.1.50")
    
    client_mac = bytes.fromhex('001122334455')
    gateway_mac = bytes.fromhex('aabbccddeeff')
    eth_c2s = create_ethernet_header(client_mac, gateway_mac)
    eth_s2c = create_ethernet_header(gateway_mac, client_mac)
    
    writer = PCAPWriter(filename)
    
    current_sec = 1700000000
    current_usec = 100000
    pkt_id = 0
    
    def advance_time():
        nonlocal current_sec, current_usec
        current_usec += random.randint(10, 500)
        if current_usec >= 1000000:
            current_sec += current_usec // 1000000
            current_usec %= 1000000
            
    print(f"Generating {target_packets} packets into {filename}...")
    
    # We will generate traffic as multi-packet flows:
    # 1. Complete TLS flow (5 to 8 packets: SYN, SYN-ACK, ACK, Client Hello, Server Data ACK, Subsequent ACKs/Data)
    # 2. HTTP flow (4 to 6 packets: SYN, SYN-ACK, ACK, HTTP GET, Server Response ACK, subsequent)
    # 3. DNS query/response flow (2 packets)
    # 4. Background TCP control packets / generic data flows
    # 5. Packets from the blocked IP
    
    while writer.pkt_count < target_packets:
        flow_choice = random.random()
        
        # Decide if this flow comes from the blocked IP (~3% of flows)
        if random.random() < 0.03:
            src_ip = blocked_client_ip
        else:
            src_ip = random.choice(client_ips)
            
        src_port = random.randint(32768, 65530)
        seq_c = random.randint(10000, 10000000)
        seq_s = random.randint(10000, 10000000)
        
        if flow_choice < 0.65:
            # TLS Flow (HTTPS)
            dst_ip, tls_data, domain = random.choice(tls_payloads)
            dst_port = 443
            
            # Pkt 1: TCP SYN
            tcp = create_tcp_header(src_port, dst_port, seq_c, 0, 0x02)
            ip = create_ip_header(src_ip, dst_ip, 6, len(tcp))
            writer.write_packet(eth_c2s + ip + tcp, current_sec, current_usec)
            advance_time()
            if writer.pkt_count >= target_packets: break
            
            # Pkt 2: TCP SYN-ACK
            tcp = create_tcp_header(dst_port, src_port, seq_s, seq_c + 1, 0x12)
            ip = create_ip_header(dst_ip, src_ip, 6, len(tcp))
            writer.write_packet(eth_s2c + ip + tcp, current_sec, current_usec)
            advance_time()
            if writer.pkt_count >= target_packets: break
            
            # Pkt 3: TCP ACK
            tcp = create_tcp_header(src_port, dst_port, seq_c + 1, seq_s + 1, 0x10)
            ip = create_ip_header(src_ip, dst_ip, 6, len(tcp))
            writer.write_packet(eth_c2s + ip + tcp, current_sec, current_usec)
            advance_time()
            if writer.pkt_count >= target_packets: break
            
            # Pkt 4: TLS Client Hello (PSH-ACK)
            tcp = create_tcp_header(src_port, dst_port, seq_c + 1, seq_s + 1, 0x18, len(tls_data))
            ip = create_ip_header(src_ip, dst_ip, 6, len(tcp) + len(tls_data))
            writer.write_packet(eth_c2s + ip + tcp + tls_data, current_sec, current_usec)
            advance_time()
            if writer.pkt_count >= target_packets: break
            
            # Pkt 5 & 6: Data packets / ACK
            extra_pkts = random.randint(1, 3)
            for _ in range(extra_pkts):
                tcp = create_tcp_header(dst_port, src_port, seq_s + 1, seq_c + 1 + len(tls_data), 0x10)
                ip = create_ip_header(dst_ip, src_ip, 6, len(tcp))
                writer.write_packet(eth_s2c + ip + tcp, current_sec, current_usec)
                advance_time()
                if writer.pkt_count >= target_packets: break
                
        elif flow_choice < 0.85:
            # HTTP Flow
            dst_ip, http_data, host = random.choice(http_payloads)
            dst_port = 80
            
            # Pkt 1: TCP SYN
            tcp = create_tcp_header(src_port, dst_port, seq_c, 0, 0x02)
            ip = create_ip_header(src_ip, dst_ip, 6, len(tcp))
            writer.write_packet(eth_c2s + ip + tcp, current_sec, current_usec)
            advance_time()
            if writer.pkt_count >= target_packets: break
            
            # Pkt 2: TCP SYN-ACK
            tcp = create_tcp_header(dst_port, src_port, seq_s, seq_c + 1, 0x12)
            ip = create_ip_header(dst_ip, src_ip, 6, len(tcp))
            writer.write_packet(eth_s2c + ip + tcp, current_sec, current_usec)
            advance_time()
            if writer.pkt_count >= target_packets: break
            
            # Pkt 3: TCP ACK
            tcp = create_tcp_header(src_port, dst_port, seq_c + 1, seq_s + 1, 0x10)
            ip = create_ip_header(src_ip, dst_ip, 6, len(tcp))
            writer.write_packet(eth_c2s + ip + tcp, current_sec, current_usec)
            advance_time()
            if writer.pkt_count >= target_packets: break
            
            # Pkt 4: HTTP Request (PSH-ACK)
            tcp = create_tcp_header(src_port, dst_port, seq_c + 1, seq_s + 1, 0x18, len(http_data))
            ip = create_ip_header(src_ip, dst_ip, 6, len(tcp) + len(http_data))
            writer.write_packet(eth_c2s + ip + tcp + http_data, current_sec, current_usec)
            advance_time()
            if writer.pkt_count >= target_packets: break
            
        elif flow_choice < 0.95:
            # DNS Query & Response Flow
            domain = random.choice(dns_catalog)
            dns_data = create_dns_query(domain)
            dst_ip = random.choice(dns_servers)
            
            # Query
            udp = create_udp_header(src_port, 53, len(dns_data))
            ip = create_ip_header(src_ip, dst_ip, 17, len(udp) + len(dns_data))
            writer.write_packet(eth_c2s + ip + udp + dns_data, current_sec, current_usec)
            advance_time()
            if writer.pkt_count >= target_packets: break
            
            # Simulated Response
            udp_resp = create_udp_header(53, src_port, len(dns_data))
            ip_resp = create_ip_header(dst_ip, src_ip, 17, len(udp_resp) + len(dns_data))
            writer.write_packet(eth_s2c + ip_resp + udp_resp + dns_data, current_sec, current_usec)
            advance_time()
            if writer.pkt_count >= target_packets: break
            
        else:
            # Background TCP flow (e.g., SSH, generic control)
            dst_ip = random.choice(client_ips)
            dst_port = random.choice([22, 8080, 8443, 3306, 5000])
            tcp = create_tcp_header(src_port, dst_port, seq_c, 0, 0x02)
            ip = create_ip_header(src_ip, dst_ip, 6, len(tcp))
            writer.write_packet(eth_c2s + ip + tcp, current_sec, current_usec)
            advance_time()
            if writer.pkt_count >= target_packets: break
            
    writer.close()
    print(f"Successfully generated {writer.pkt_count} packets in {filename}")


if __name__ == '__main__':
    count = int(sys.argv[1]) if len(sys.argv) > 1 else 100000
    fname = sys.argv[2] if len(sys.argv) > 2 else "benchmark_100k.pcap"
    generate_pcap(fname, count)
