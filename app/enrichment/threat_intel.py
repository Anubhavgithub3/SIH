THREAT_DB = {
    '1.2.3.4': {'reputation': 'suspicious', 'category': 'botnet', 'severity': 'high'},
    '10.10.10.10': {'reputation': 'malicious', 'category': 'scanner', 'severity': 'critical'},
    '8.8.8.8': {'reputation': 'benign', 'category': 'public_dns', 'severity': 'low'},
}


def enrich_threat_intel(event: dict) -> dict:
    event.setdefault('threat', {})
    network = event.get('network', {})
    ip_value = None
    if isinstance(network, dict):
        ip_value = network.get('source_ip') or network.get('destination_ip')
    if not ip_value:
        ip_value = event.get('source_ip') or event.get('src_ip')
    threat = THREAT_DB.get(ip_value, {'reputation': 'unknown', 'category': 'unknown', 'severity': 'unknown'})
    event['threat'].update(threat)
    return event
