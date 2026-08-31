#!/usr/bin/env python3
"""
Generates 200 clean network log events containing only IPs (src/dst), ports,
and protocols with ZERO threat/bad/deny hints.
Tests automatic GeoIP location prediction.
"""

import random
from pathlib import Path

# Diverse public IP ranges across continents for GeoIP location prediction
IP_RANGE_POOL = [
    # China
    ('1.2.3.4', '1.14.0.5', '14.139.1.5', '27.115.1.5'),
    # United States
    ('8.8.8.8', '34.201.5.12', '45.33.10.8', '52.90.4.1'),
    # Russia
    ('77.88.55.66', '85.118.0.12', '91.210.1.5', '95.173.136.1'),
    # India
    ('103.21.244.5', '115.240.1.8', '117.192.0.1', '122.160.1.5'),
    # Germany
    ('142.93.1.5', '151.106.0.1', '159.69.1.5', '185.220.101.5'),
    # United Kingdom
    ('165.227.1.5', '178.62.0.1', '188.166.1.5', '191.96.1.5'),
    # France / Japan
    ('198.51.100.23', '202.12.27.33', '210.140.1.5', '217.70.1.5'),
]

TEMPLATES = [
    # Key-Value Telemetry (Clean Network Connection)
    'src={src_ip} dst={dst_ip} spt={src_port} dpt={dst_port} proto={proto} action=allow bytes={bytes_cnt} duration={duration_ms}ms msg="network session established"',

    # CEF Format (Clean Palo Alto Network Event)
    'CEF:0|Palo Alto Networks|PAN-OS|11.0|TRAFFIC|Session-Start|3|src={src_ip} dst={dst_ip} spt={src_port} dpt={dst_port} proto={proto} action=allow msg="clean connection traffic"',

    # Syslog Format (Clean SSH/Web Service Access)
    'Aug 31 12:00:00 srv-{host_id:02d} systemd[{pid}]: Successful connection from {src_ip} port {src_port} to {dst_ip} port {dst_port}',

    # Structured JSON Format (Clean Cloud Gateway Log)
    '{{"timestamp":"2026-08-31T12:00:00Z","src_ip":"{src_ip}","dst_ip":"{dst_ip}","src_port":{src_port},"dst_port":{dst_port},"action":"allow","severity":"info","proto":"{proto}","message":"standard network ingress"}}'
]

PROTOS = ['TCP', 'UDP']
DEST_PORTS = [80, 443, 22, 53, 8080, 8443, 3306]

def main():
    out_dir = Path(__file__).parent.parent / "sample_logs"
    out_dir.mkdir(exist_ok=True)
    out_file = out_dir / "sample_200_geoip.log"

    print("🌐 Generating 200 clean network events for GeoIP location prediction...")

    lines = []
    for i in range(200):
        # Pick IP pool
        ip_group = random.choice(IP_RANGE_POOL)
        src_ip = random.choice(ip_group)
        dst_ip = f"10.0.{random.randint(0, 10)}.{random.randint(1, 254)}"
        src_port = random.randint(1024, 65535)
        dst_port = random.choice(DEST_PORTS)
        proto = random.choice(PROTOS)
        template = random.choice(TEMPLATES)

        line = template.format(
            src_ip=src_ip,
            dst_ip=dst_ip,
            src_port=src_port,
            dst_port=dst_port,
            proto=proto,
            bytes_cnt=random.randint(256, 64000),
            duration_ms=random.randint(5, 450),
            host_id=random.randint(1, 10),
            pid=random.randint(1000, 9999)
        )
        lines.append(line)

    with open(out_file, "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")

    print(f"✅ Successfully generated 200 clean GeoIP events in {out_file}")

if __name__ == "__main__":
    main()
