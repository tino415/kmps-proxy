import socket, re, threading, select, time, base64, http_digest, decorators, copy, md5

header_pattern = re.compile("([a-zA-Z\-]+): (.+)")

via_pattern = re.compile("Via:.+")

body_sepparator = re.compile("[\n]{2}")

def parse_packet(data):
    packet = Packet(via = [], headers = {})

    header, packet.body = body_sepparator.split(data.replace("\r", ""), 1)
    header_lines = header.split("\n")
    packet.status = header_lines.pop(0)

    while len(header_lines) > 0 and via_pattern.match(header_lines[0]):
        packet.via.append(header_lines.pop(0).split(": ", 1)[1])

    while len(header_lines) > 0 and header_pattern.match(header_lines[0]):
        key, value = header_lines.pop(0).split(": ", 1)
        packet.headers[key] = value

    return packet

class Server:
    
    clients = {}

    route = {}

    receive_wait = 4

    port = 5060 
    ip = ''

    name = "python.server.sip"

    running = False

    def __init__(self):
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    @decorators.start
    def start(self):
        self.thread = threading.Thread(target = self.run)
        self.socket.bind((self.ip, self.port))
        self.thread.start()

    def run(self):
        self.running = True
        while self.running:
            self.ready = select.select([self.socket], [], [], self.receive_wait)
            if self.ready[0]:
                data, address = self.socket.recvfrom(1024)
                self.receive(data, address)
                
    @decorators.stop
    def stop(self):
        self.running = False
        self.thread.join()
        self.socket.close()

    @decorators.receive
    def receive(self, data, address):
        packet = parse_packet(data) 
        reg_pattern = re.compile("REGISTER")
        inv_pattern = re.compile("INVITE")
        rin_pattern = re.compile(".+Ringing.*")
        cnc_pattern = re.compile("CANCEL.*")
        ack_pattern = re.compile("ACK")
        dec_pattern = re.compile(".*Decline")
        ok_pattern = re.compile(".*OK")
        bye_pattern = re.compile("BYE")

        if ack_pattern.match(packet.status):
            return
        elif cnc_pattern.match(packet.status):
            self.cancel(packet)
        elif dec_pattern.match(packet.status):
            self.decline(packet)

        if self.auth(packet):
            if reg_pattern.match(packet.status):
                self.register(packet)
            elif inv_pattern.match(packet.status):
                self.invite(packet)
            elif rin_pattern.match(packet.status):
                self.ringing(packet)
            elif ok_pattern.match(packet.status):
                self.answer(packet)
            elif bye_pattern.match(packet.status):
                self.bye(packet)
            else:
                return False

    @decorators.send
    def send(self, packet, address):
        self.socket.sendto(str(packet), address)

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

    def send_ack(self, packet):
        target_user = packet.get_sending_client()
        packet.status = "ACK sip:{}@{} SIP/2.0".format(
            target_user,
            self.ip
        )
        self.send(packet, self.route[packet.get_requested_client()])

    @decorators.auth
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

    @decorators.register
    def register(self, packet):
        packet.status = "SIP/2.0 200 OK"

        if 'Authorization' in packet.headers:
            del packet.headers["Authorization"]
        if 'WWW-Authenticate' in packet.headers:
            del packet.headers['WWW-Authenticate']

        self.route[packet.get_sending_client()] = packet.get_return_address()
        self.send(packet, packet.get_return_address())

    @decorators.invite
    def invite(self, packet):
        target_user = packet.get_requested_client()

        if target_user in self.route:
            packet.status = "SIP/2.0 100 Triyng"
            self.send(packet, packet.get_return_address())
            packet.status = "INVITE sip:{0}@{1} SIP/2.0".format(target_user, self.route[target_user][0])
            packet.via.insert(0, self.get_via(packet))
            packet.headers['Record-Route'] = "<sip:{};lt>".format(self.get_address())
            self.send(packet, self.route[target_user])
        else:
            self.send_not_found(packet)

    def ringing(self, packet):
        if self.valid_via(packet):
            self.send(packet, packet.get_return_address())

    def cancel(self, packet):
        target_user = packet.get_requested_client()
        sending_user = packet.get_sending_client()

        if target_user in self.route:
            packet.status = "CANCEL sip:{}@{} SIP/2.0".format(sending_user, self.route[sending_user][0])
            packet.via.insert(0, self.get_via(packet))
            packet.headers['Route'] = "<sip:{};lt>".format(self.get_address())
            self.send(packet, self.route[target_user])
        else:
            self.send_not_found(packet)

    def decline(self, packet):
        if self.valid_via(packet):
            self.send(packet, packet.get_return_address())
            self.send_ack(packet)

    def answer(self, packet):
        if self.valid_via(packet):
            self.send(packet, packet.get_return_address())

    def bye(self, packet):
        target_user = packet.get_requested_client()
        if target_user in self.route:
            packet.status = "BYE sip:{}@{} SIP/2.0".format(
                target_user,
                self.route[target_user][0]
            )
            self.send(packet, self.route[target_user])

    def get_via(self,packet):
        nonce = '{}:{}:{}'.format(
            packet.get_sending_client(),
            packet.get_requested_client(),
            packet.headers['Call-ID']
        )
        return 'SIP/2.0/UDP {0}:{1};branch=z9hG4bK{2}'.format(
            self.ip,
            self.port,
            md5.new(nonce).hexdigest()
        )

    def valid_via(self, packet):
        ret_addr = packet.get_return_address()

        if ret_addr[0] == self.ip and ret_addr[1] == self.port:
            packet.via.pop(0)
            if len(packet.via) == 0: return False
            else: return True

        else: return True


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
        if 'Contact' in self.headers:
            return self.URI_PATTERN.search(self.headers['Contact']).groups()[0]
        else:
            return self.URI_PATTERN.search(self.headers['From']).groups()[0]
