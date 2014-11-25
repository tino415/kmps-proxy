#!/usr/bin/python
""" CLI interface for sip proxy"""
import os

def run(SERVER):
    print "*********************************************"
    print "* Python VoIP proxy by Martin Cernak lol lo *"
    print "*********************************************"
    x = ''
    while x != "q":
        if x == "route":
            print SERVER.route
        elif x == "cls":
            print "clear"
            os.system('clear')
        elif x == "help":
            print "route"
        elif x == "stop":
            SERVER.stop()
        elif x == "start":
            SERVER.start()
        elif x == "clients":
            print SERVER.clients
        x = raw_input()

if __name__ == "__main__":
    import SIP
    SERVER = SIP.Server(port=5061, name="sip.base.SERVER", ip="192.168.50.30")
    SERVER.start()
    SERVER.clients = {
        '111' : 'pass',
        '112' : 'pass',
    }
    run(SERVER)
    SERVER.stop()
