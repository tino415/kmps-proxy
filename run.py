#!/usr/bin/python
import SIP, os

server = SIP.Server()
server.ip = "192.168.50.30"
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
	elif x == "cls":
		print "clear"
		os.system('clear')
	elif x == "help":
		print "route"

	x = raw_input()

server.stop()
