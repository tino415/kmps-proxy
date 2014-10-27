import SIP

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
	packet = SIP.parse_packet(packet_str)
	print "STARTING TEST\n"
	server.register_action(packet)
	
