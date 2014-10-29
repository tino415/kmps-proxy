import SIP

server = SIP.Server()
server.start()
server.clients = {
	'111' : 'pass1',
	'112' : 'pass1',
	'113' : 'pass1'
}

x = "n"

print "*********************************************"
print "* Python VoIP proxy by Martin Cernak lol lo *"
print "*********************************************"

while x != "q":

    if x == "route":
        print server.route

    x = raw_input()

server.stop()
