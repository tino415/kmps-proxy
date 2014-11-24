import re, md5, decorators, base64, time

@decorators.parse
def parse(string):
    pattern = re.compile("( |, )")
    elements = {}

    for fragment in pattern.split(string):
        pair = fragment.split("=", 1)
        if len(pair) == 2:
            if pair[1][0] == '"' and pair[1][-1] == '"':
                pair[1] = pair[1][1:-1]
            elements[pair[0]] = pair[1]
    return elements

@decorators.is_valid
def is_valid(password, digest, method):
    sh1 = md5.new(
        '{}:{}:{}'.format(
            digest['username'], digest['realm'], password
        )
    ).hexdigest()
    sh2 = md5.new('{}:{}'.format(method, digest['uri'])).hexdigest()
    response = md5.new('{}:{}:{}'.format(sh1, digest['nonce'], sh2)).hexdigest()
    return digest['response'] == response

@decorators.controll_message
def generate(server_name):
    return (
        'Digest realm="{realm}", '
        'nonce="{nonce}", opaque="", state=FALSE, algorithm=MD5'
    ).format(
        realm = server_name,
        nonce = md5.new(str(time.time())).hexdigest()
    )
