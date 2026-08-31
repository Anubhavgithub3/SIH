#!/usr/bin/env python3
"""
High Performance 10,000 Log Generator for Universal Log Framework (ULF)
Generates 10,000 realistic multi-vendor logs (CEF, Syslog, LEEF, Key-Value, JSON)
"""

import random
import sys
from pathlib import Path

TEMPLATES = [
    # 1. CEF Format (Palo Alto / ArcSight)
    'CEF:0|Palo Alto Networks|PAN-OS|11.0|THREAT|{signature}|{sev_num}|src={src_ip} dst={dst_ip} spt={src_port} dpt={dst_port} action={action} country={country} msg="{msg}"',

    # 2. Syslog Format (Linux / SSH / Apache)
    'Aug 31 10:45:00 web-{host_id:02d} sshd[{pid}]: {action_syslog} for {user} from {src_ip} port {src_port} ssh2',

    # 3. LEEF Format (IBM QRadar)
    'LEEF:2.0|IBM|QRadar|7.5|ThreatAlert|src={src_ip} dst={dst_ip} action={action} sev={sev_num} cat={category} msg="{msg}"',

    # 4. Key-Value Telemetry (Cisco ASA / iptables)
    'src={src_ip} dst={dst_ip} spt={src_port} dpt={dst_port} proto={proto} action={action} country={country} bytes={bytes_cnt} msg="{msg}"',

    # 5. Structured JSON Format (AWS CloudWatch / Suricata)
    '{{"timestamp":"2026-08-31T12:00:00Z","src_ip":"{src_ip}","dst_ip":"{dst_ip}","src_port":{src_port},"dst_port":{dst_port},"action":"{action}","severity":"{sev_str}","country":"{country}","msg":"{msg}"}}'
]

COUNTRIES = ['CN', 'RU', 'US', 'IN', 'DE', 'BR', 'KR', 'IR', 'KP', 'GB', 'FR', 'NL']
ACTIONS = ['deny', 'block', 'allow', 'drop', 'pass', 'reject']
SEVERITIES_NUM = [1, 3, 5, 7, 9, 10]
SEVERITIES_STR = ['info', 'low', 'medium', 'high', 'critical']
USERS = ['root', 'admin', 'user1', 'system', 'postgres', 'oracle', 'ubuntu']
SIGNATURES = ['C2-Beaconing', 'SQL-Injection', 'XSS-Attack', 'SSH-BruteForce', 'Port-Scan', 'Malware-Download']
CATEGORIES = ['Authentication', 'NetworkDefense', 'ThreatIntel', 'PolicyViolation', 'SystemAccess']
PROTOS = ['TCP', 'UDP', 'ICMP']

def generate_random_ip():
    return f"{random.randint(1, 223)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}"

def generate_log_line(i):
    template = random.choice(TEMPLATES)
    src_ip = generate_random_ip()
    dst_ip = f"10.0.{random.randint(0, 50)}.{random.randint(1, 254)}"
    src_port = random.randint(1024, 65535)
    dst_port = random.choice([22, 80, 443, 8080, 3389, 53, 21])
    action = random.choice(ACTIONS)
    country = random.choice(COUNTRIES)
    sev_num = random.choice(SEVERITIES_NUM)
    sev_str = random.choice(SEVERITIES_STR)
    user = random.choice(USERS)
    sig = random.choice(SIGNATURES)
    cat = random.choice(CATEGORIES)
    proto = random.choice(PROTOS)
    msg = f"Security event {i+1} signature {sig} from {country}"
    
    action_syslog = "Failed password" if action in ['deny', 'block', 'drop', 'reject'] else "Accepted password"
    
    return template.format(
        signature=sig,
        sev_num=sev_num,
        sev_str=sev_str,
        src_ip=src_ip,
        dst_ip=dst_ip,
        src_port=src_port,
        dst_port=dst_port,
        action=action,
        country=country,
        msg=msg,
        host_id=random.randint(1, 20),
        pid=random.randint(1000, 9999),
        user=user,
        category=cat,
        proto=proto,
        bytes_cnt=random.randint(64, 15000),
        action_syslog=action_syslog
    )

def main():
    count = 10000
    if len(sys.argv) > 1:
        try:
            count = int(sys.argv[1])
        except ValueError:
            pass

    out_dir = Path(__file__).parent.parent / "sample_logs"
    out_dir.mkdir(exist_ok=True)
    out_file = out_dir / f"sample_{count}.log"

    print(f"⚡ Generating {count:,} multi-vendor security logs into {out_file}...")
    
    with open(out_file, "w", encoding="utf-8") as f:
        for i in range(count):
            f.write(generate_log_line(i) + "\n")
            
    size_mb = out_file.stat().st_size / (1024 * 1024)
    print(f"✅ Generated {count:,} logs ({size_mb:.2f} MB) successfully at {out_file}")

if __name__ == "__main__":
    main()
