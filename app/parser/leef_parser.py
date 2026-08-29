def parse_leef(raw: str):
    if not raw.startswith("LEEF:"):
        raise ValueError("Invalid LEEF log")
    fields = raw.split('|')
    header = fields[0]
    vendor = fields[1] if len(fields) > 1 else 'unknown'
    product = fields[2] if len(fields) > 2 else 'unknown'
    event = {
        "timestamp": "",
        "host": "",
        "vendor": vendor,
        "product": product,
        "header": header,
        "raw": raw,
        "message": raw,
    }
    return event
