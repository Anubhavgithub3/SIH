import re


import re


def parse_cef(raw: str):
    if not raw.startswith("CEF:"):
        raise ValueError("Invalid CEF log")

    body = raw.split(':', 1)[1]
    parts = body.split('|')
    if len(parts) < 7:
        raise ValueError("Malformed CEF record")

    version, vendor, product, version_no, signature_id, name, severity = parts[:7]
    extensions = '|'.join(parts[7:]) if len(parts) > 7 else ""

    attributes = {}
    for token in re.findall(r'([A-Za-z0-9_]+)=(?:"[^"]*"|[^\s]+)', extensions):
        # token capture is intentionally replaced below; the regex above is used only to find valid key names
        pass

    for item in re.finditer(r'([A-Za-z0-9_]+)=((?:"[^"]*"|[^\s]+))', extensions):
        key, value = item.groups()
        attributes[key] = value.strip('"')

    src_ip = attributes.get('src') or attributes.get('srcip') or ''
    message = attributes.get('msg') or name

    event = {
        "timestamp": "",
        "host": "",
        "device_vendor": vendor,
        "device_product": product,
        "device_version": version_no,
        "signature_id": signature_id,
        "signature_name": name,
        "severity": severity,
        "src_ip": src_ip,
        "message": message,
        "raw": raw,
    }
    event.update(attributes)
    return event
