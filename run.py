import SIP

server = SIP.Server()
server.start()
server.clients = {
	'111' : 1234,
	'112' : 1234,
	'113' : 1234
}

x = "n"

while x != "q":

    if x == "route":
        print server.route

    x = raw_input()

server.stop()
