def force_bytes(data):
    if isinstance(data, bytearray):
        return data
    elif not isinstance(data, bytes):
        return bytearray(data, 'utf8')
    else:
        return bytearray(data)
