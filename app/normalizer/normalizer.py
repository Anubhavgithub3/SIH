def _coerce_int(value):
    if value is None:
        return None
    if isinstance(value, int):
        return value
    try:
        return int(value)
    except (TypeError, ValueError):
        return value


def _set_nested(mapping, field_path, value):
    keys = field_path.split('.')
    current = mapping
    if keys[0] == 'source':
        if not isinstance(mapping.get('source'), dict):
            mapping['source_details'] = mapping.get('source_details', {})
            current = mapping['source_details']
        else:
            current = mapping['source']
        for key in keys[1:-1]:
            current = current.setdefault(key, {})
        current[keys[-1]] = value
        return

    for key in keys[:-1]:
        current = current.setdefault(key, {})
    current[keys[-1]] = value


def normalize_event(raw_event: dict, source: str = "unknown") -> dict:
    if not isinstance(raw_event, dict):
        raw_event = {"message": str(raw_event)}

    resolved_source = raw_event.get('source') or source
    event_type = raw_event.get('event_type') or raw_event.get('type') or 'unknown'
    severity = raw_event.get('severity', 'INFO')
    message = raw_event.get('message', '')
    action = raw_event.get('action') or raw_event.get('event_action')

    normalized = {
        'timestamp': raw_event.get('timestamp', ''),
        'source': resolved_source,
        'host': raw_event.get('host', ''),
        'event_type': event_type,
        'severity': severity,
        'message': message,
        'event': {
            'action': action,
            'severity': severity,
            'type': event_type,
            'message': message,
        },
        'network': {},
        'user': {},
        'metadata': {},
        'raw_log': raw_event.get('raw') or raw_event.get('raw_log') or '',
    }

    mapping = {
        'src': 'network.source_ip',
        'sourceIP': 'network.source_ip',
        'src_ip': 'network.source_ip',
        'source_ip': 'network.source_ip',
        'dst': 'network.destination_ip',
        'destinationIP': 'network.destination_ip',
        'dst_ip': 'network.destination_ip',
        'destination_ip': 'network.destination_ip',
        'spt': 'network.source_port',
        'src_port': 'network.source_port',
        'source_port': 'network.source_port',
        'dpt': 'network.destination_port',
        'dst_port': 'network.destination_port',
        'destination_port': 'network.destination_port',
        'proto': 'network.protocol',
        'protocol': 'network.protocol',
        'action': 'event.action',
        'act': 'event.action',
        'severity': 'event.severity',
        'sev': 'event.severity',
        'event_type': 'event.type',
        'type': 'event.type',
        'message': 'event.message',
        'host': 'source.hostname',
        'hostname': 'source.hostname',
        'vendor': 'source.vendor',
        'product': 'source.product',
    }

    for key, value in raw_event.items():
        if key in {'timestamp', 'raw', 'raw_log', 'event_type', 'severity', 'message'}:
            continue
        field = mapping.get(key)
        if field:
            if field.startswith('network.') and value is not None and field.endswith('port'):
                value = _coerce_int(value)
            _set_nested(normalized, field, value)
        else:
            normalized['metadata'][key] = value

    if resolved_source == 'firewall' and raw_event.get('src'):
        normalized['event']['type'] = 'firewall_event'

    normalized['source_details'] = normalized.get('source_details', {})
    if not normalized['source_details'] and raw_event.get('vendor'):
        normalized['source_details']['vendor'] = raw_event.get('vendor')
    if not normalized['source_details'] and raw_event.get('product'):
        normalized['source_details']['product'] = raw_event.get('product')

    return normalized
