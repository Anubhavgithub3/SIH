IP_DB = {
    '8.8.8.8': {'country': 'US', 'city': 'Mountain View', 'asn': 15169, 'org': 'Google LLC'},
    '1.2.3.4': {'country': 'CN', 'city': 'Hangzhou', 'asn': 4134, 'org': 'Chinanet'},
    '10.0.0.5': {'country': 'IN', 'city': 'Bengaluru', 'asn': 64513, 'org': 'Internal Network'},
}


def enrich_geoip(event: dict) -> dict:
    event.setdefault('enrichment', {})
    ip_value = None
    network = event.get('network', {})
    if isinstance(network, dict):
        ip_value = network.get('source_ip') or network.get('destination_ip')
    if not ip_value:
        ip_value = event.get('source_ip') or event.get('src_ip')
    geo = IP_DB.get(ip_value, {'country': 'unknown', 'city': 'unknown', 'asn': None, 'org': 'unknown'})
    event['enrichment'].update({'geo': geo, 'country': geo.get('country', 'unknown')})
    return event
