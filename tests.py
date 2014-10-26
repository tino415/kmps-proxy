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
