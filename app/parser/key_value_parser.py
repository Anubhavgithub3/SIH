def parse_key_value(log: str):
    result = {}
    for token in log.split():
        if '=' in token:
            key, value = token.split('=', 1)
            result[key.strip()] = value.strip()
    return result
