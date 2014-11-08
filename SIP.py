import socket, re, threading, select, time, base64, http_digest, decorators, copy, md5

def parse_packet(data):
    packet = Packet(via = [])
    header_pattern = re.compile("([a-zA-Z\-]+): (.+)")
    via_pattern = re.compile("Via:.+")
    body_sepparator = re.compile("[\n]{2}")

    print "Parsing\n"
    print packet.via;

    
    header, packet.body = body_sepparator.split(data.replace("\r", ""), 1)
    header_lines = header.split("\n")
    packet.status = header_lines.pop(0)

    print "Parsing\n"
    print packet.via;
    
    while len(header_lines) > 0 and via_pattern.match(header_lines[0]):
        packet.via.append(header_lines.pop(0).split(": ", 1)[1])

    print "Parsing\n"
    print packet.via;

    while len(header_lines) > 0 and header_pattern.match(header_lines[0]):
        key, value = header_lines.pop(0).split(": ", 1)
        packet.headers[key] = value

    print "Parsing\n"
    print packet.via;

    return packet

def parse_address(data):
    REGEX_PARSE = (
        "<sip:([0-9a-zA-Z]+)@([a-z.]+|[0-9.]+):?([0-9]+){0,1}>"
    )

    elements = re.search(REGEX_PARSE, data).groups()
    return Uri(account = elements[0],
                    address = elements[1],
                    port = elements[2])

def parse_via(via_string):
    via_elements = via_content.split(";")
    return dict( element.split("=") for element in via_elements )

class Server:
    
    clients = {}

    route = {}

    receive_wait = 4

    port = 5060

    ip = ''

    name = "python.server.sip"

    running = False

    @decorators.controll_message
    def __init__(self):
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    @decorators.controll_message
    def start(self):
        self.thread = threading.Thread(target = self.run)
        self.socket.bind((self.ip, self.port))
        self.thread.start()

    @decorators.controll_message
    def run(self):
        self.running = True
        while self.running:
            self.ready = select.select([self.socket], [], [], self.receive_wait)
            if self.ready[0]:
                data, address = self.socket.recvfrom(1024)
                self.receive(data)
                
    @decorators.controll_message
    def stop(self):
        self.running = False
        self.thread.join()
        self.socket.close()

    @decorators.controll_message
    def receive(self, data):
        packet = parse_packet(data)
        reg_pattern = re.compile("REGISTER")
        inv_pattern = re.compile("INVITE")
        res_pattern = re.compile("(180|CENCEL)")
        ack_pattern = re.compile("ACK")

        if ack_pattern.match(packet.status):
            return

        if self.auth(packet):

            if reg_pattern.match(packet.status):
                self.register_action(packet)
            elif inv_pattern.match(packet.status):
                self.invite_action(packet)
            elif res_pattern.match(packet.status):
                self.resend(packet)

    @decorators.controll_message
    def send(self, packet, address):
        print str(packet)
        self.socket.sendto(str(packet), address)

    @decorators.controll_message
    def send_unathorized(self, packet):
        packet.status = "SIP/2.0 401 Unauthorized"
        packet.headers['WWW-Authenticate'] = http_digest.generate(self.name)

        if 'Authorization' in packet.headers:
            del packet.headers['Authorization']

        self.send(packet, packet.get_return_address())

    def send_not_found(self, packet):
        packet.status = "SIP/2.0 404 Not Found Call processing released"
        packet.headers['Reason'] = 'Q.851 ;cause=1 ; text="Unallocated (unassigned) number'

        if 'Authorization' in packet.headers:
            del packet.headers['Authorization']

        self.send(packet, packet.get_return_address())

    @decorators.controll_message
    def auth(self, packet):
        if not packet.get_sending_client() in self.route:   
            if "Authorization" in packet.headers:
                digest = http_digest.parse(packet.headers['Authorization'])
                if not digest['username'] in self.clients:
                    self.send_unathorized(packet)
                    return False

                password = self.clients[digest['username']]
                if not http_digest.is_valid(password, digest, packet.get_tr_method()):
                    self.send_unathorized(packet)
                    return False

                return True

            else:
                self.send_unathorized(packet)
                return False
        else:
            return True

    @decorators.controll_message
    def register_action(self, packet):
        packet.status = "SIP/2.0 200 OK"

        if 'Authorization' in packet.headers:
            del packet.headers["Authorization"]
        if 'WWW-Authenticate' in packet.headers:
            del packet.headers['WWW-Authenticate']

        self.route[packet.get_sending_client()] = packet.get_return_address()
        self.send(packet, packet.get_return_address())

    @decorators.controll_message
    def invite_action(self, packet):
        target_user = packet.get_requested_client()

        if target_user in self.route:
            packet.status = "SIP/2.0 100 Triyng"
            self.send(packet, packet.get_return_address())
            packet.status = "INVITE sip:{0}@{1} SIP/2.0".format(target_user, self.route[target_user][0])
            packet.via.insert(0, self.get_via())
            packet.headers['Route'] = "<sip:{};lt>".format(self.get_address())
            self.send(packet, self.route[target_user])
        else:
            self.send_not_found(packet)

    @decorators.controll_message
    def resend(self, packet):
        target_user = packet.get_requested_client()       

        if target_user in self.route:
            self.send(packet, self.route[target_user])
        else:
            self.send_not_found(packet);

    def get_via(self):
        return 'SIP/2.0/UDP {0}:{1};branch=z9hG4bK{2}'.format(
            self.ip,
            self.port,
            md5.new(str(time.time())).hexdigest()
        )

    @decorators.controll_message
    def get_address(self):
        string = self.ip

        if self.port is not None:
            string += ":{0}".format(self.port)

        return string

class Packet:

    URI_PATTERN = re.compile("<sip:([a-zA-Z0-9]+)@[0-9a-zA-Z:\.]+>")

    def __init__(self, headers = {}, via = [], body = "" , status = False):
        self.headers = headers
        self.via = via
        self.status = status
        self.body = body

    def __str__(self):
        string = self.status + "\n"
        for via in self.via:
            print "Via found\n"
            string += "Via: {0}\n".format(via)

        for header, value in self.headers.items():
            if header != "Content-Length" and header != "Via":
                string += "{0}: {1}\n".format(header,value)

        string += "Content-Length: " + str(len(string)) + '\r\n\r\n'

        if(len(self.body) > 0):
            string += self.body + '\r\n\r\n'

        return string 

    def get_tr_method(self):
        return self.headers["CSeq"].split(" ")[1]

    def get_return_address(self, remove = False):
        if remove:
            via_string = self.via.pop(0)
        else:
            via_string = self.via[0]

        via_address = via_string.split(" ", 1)[1].split(";", 1)[0]
        via_address = via_address.split(":")
        if len(via_address) == 2:
            port = via_address[1]
        else:
            port = 5060

        return (via_address[0], int(port))

    def get_requested_client(self):
        return self.URI_PATTERN.search(self.headers['To']).groups()[0]
        
    def get_sending_client(self):
        return self.URI_PATTERN.search(self.headers['Contact']).groups()[0]
