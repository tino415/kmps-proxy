import SIP, http_digest

def receive_packet(packet_path = "packets/register1-s1.sip"):
	reload(SIP)
	packet = ''.join(open(packet_path).readlines())
	server = SIP.Server()
	server.receive_packet(packet)

def generate_digest():
	reload(SIP)
	server = SIP.Server()
	server.generate_http_digest()

def generate_via():
	reload(SIP)
	server = SIP.Server()

def get_top_most_via(packet_path = "packets/register1-s1.sip"):
	reload(SIP)
	packet_str =  ''.join(open(packet_path).readlines())
	packet = SIP.parse_packet(packet_str)
	print packet.get_return_address()

def register_action_1(packet_path = "packets/register1-s1.sip"):
	reload(SIP)
	packet_str = ''.join(open(packet_path).readlines())
	server = SIP.Server()
	packet = SIP.parse_packet(packet_str)
	print "STARTING TEST\n"
	server.register_action(packet)

def register_action_2(packet_path = "packets/register2-s1.sip"):
	reload(SIP)
	packet_str = ''.join(open(packet_path).readlines())
	server = SIP.Server()
	server.clients['bob'] = 'bobpassw'
	packet = SIP.parse_packet(packet_str)
	print "STARTING TEST\n"
	server.register_action(packet)

def digest_decode(packet_path = "packets/register2-s1.sip"):
	reload(http_digest)
	reload(SIP)
	packet_str = ''.join(open(packet_path).readlines())
	packet = SIP.parse_packet(packet_str)
	print "STARTING TEST\n"
	http_digest.parse(packet.headers["Authorization"])

def get_client(packet_path = "packets/register1-s1.sip"):
	reload(SIP)
	packet_str = ''.join(open(packet_path).readlines())
	packet = SIP.parse_packet(packet_str)
	account = packet.get_sending_client()
	print account

def get_return_address(packet_path = "packets/register2-s1.sip"):
	reload(SIP)
	packet_str = ''.join(open(packet_path).readlines())
	print "\nPACKET:\n"
	print packet_str
	print "\nRETURN ADDRESS\n"
	packet = SIP.parse_packet(packet_str)
	print packet.get_return_address()
	
def get_method(packet_path = "packets/register2-s1.sip"):
	reload(SIP)
	packet_str = ''.join(open(packet_path).readlines())
	packet = SIP.parse_packet(packet_str)
	print "\nCSeq:\n"
	print packet.headers["CSeq"]
	print packet.get_method()
