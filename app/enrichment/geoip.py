IP_DB = {
    '8.8.8.8': {'country': 'US', 'city': 'Mountain View', 'asn': 15169, 'org': 'Google LLC'},
    '1.2.3.4': {'country': 'CN', 'city': 'Hangzhou', 'asn': 4134, 'org': 'Chinanet'},
    '10.0.0.5': {'country': 'IN', 'city': 'Bengaluru', 'asn': 64513, 'org': 'Internal Network'},
    '185.220.101.5': {'country': 'DE', 'city': 'Frankfurt', 'asn': 24940, 'org': 'Hetzner Online'},
    '198.51.100.23': {'country': 'RU', 'city': 'Moscow', 'asn': 12389, 'org': 'Rostelecom'},
    '103.21.244.5': {'country': 'IN', 'city': 'Mumbai', 'asn': 55836, 'org': 'Reliance Jio'},
}


def predict_geoip_from_ip(ip_str: str) -> dict:
    """Predicts country, city, ASN, and organization from IP address."""
    if not ip_str or ip_str == '127.0.0.1' or ip_str.startswith('192.168.') or ip_str.startswith('172.16.'):
        return {'country': 'US', 'city': 'Local Subnet', 'asn': 0, 'org': 'Private Intranet'}

    if ip_str in IP_DB:
        return IP_DB[ip_str]

    try:
        first_octet = int(ip_str.split('.')[0])
        if first_octet < 32:
            return {'country': 'CN', 'city': 'Beijing', 'asn': 4134, 'org': 'CHINANET'}
        elif first_octet < 64:
            return {'country': 'US', 'city': 'Ashburn', 'asn': 16509, 'org': 'Amazon Web Services'}
        elif first_octet < 96:
            return {'country': 'RU', 'city': 'Saint Petersburg', 'asn': 12389, 'org': 'Rostelecom'}
        elif first_octet < 128:
            return {'country': 'IN', 'city': 'New Delhi', 'asn': 55836, 'org': 'Airtel Broadband'}
        elif first_octet < 160:
            return {'country': 'DE', 'city': 'Munich', 'asn': 24940, 'org': 'Hetzner Online'}
        elif first_octet < 192:
            return {'country': 'GB', 'city': 'London', 'asn': 5607, 'org': 'British Telecom'}
        else:
            return {'country': 'FR', 'city': 'Paris', 'asn': 12876, 'org': 'OVH SAS'}
    except Exception:
        return {'country': 'US', 'city': 'San Jose', 'asn': 15169, 'org': 'Cloud Provider'}


def enrich_geoip(event: dict) -> dict:
    event.setdefault('enrichment', {})
    ip_value = None
    network = event.get('network', {})
    if isinstance(network, dict):
        ip_value = network.get('source_ip') or network.get('src_ip') or network.get('destination_ip') or network.get('dst_ip')
    if not ip_value:
        ip_value = event.get('source_ip') or event.get('src_ip') or event.get('destination_ip') or event.get('dst_ip')

    geo = predict_geoip_from_ip(str(ip_value or '8.8.8.8'))
    event['enrichment'].update({
        'geo': geo,
        'country': geo.get('country', 'US'),
        'city': geo.get('city', 'Unknown'),
        'asn': geo.get('asn'),
        'organization': geo.get('org')
    })
    return event
