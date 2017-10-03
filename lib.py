from entropy import shannon_entropy


def entropy(data):
    return shannon_entropy(data)


def null_terminate_and_decode_utf8(str):
    return str.decode('utf-8', 'ignore').split('\x00', 1)[0]
