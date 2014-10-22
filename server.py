import socket
import threading
import select
import aspects
import re
import copy
import md5
import time
from collections import defaultdict


class Server (threading.Thread):

    @aspects.controllMessage
    def __init__ (self, ip_address, port):
        threading.Thread.__init__(self)
        self.socket = socket.socket(socket.AF_INET,
                                    socket.SOCK_DGRAM)
        self.address = "{0}:{1}".format(ip_address,port)
        self.socket.bind((ip_address, port))
        self.socket.setblocking(0)
        self.registered = {}
        self.calls = {}

    @aspects.controllMessage
    def run(self):
        self.running = True
        while self.running:
            self.ready = select.select([self.socket], [], [], 10)
            if self.ready[0]:
                data, address = self.socket.recvfrom(1024)
                self.receive_packet(data)
    
    @aspects.controllMessage
    def stop(self):
        self.running = False   
        print "Server will exist whithin 10 sec"

    @aspects.controllMessage
    def receive_packet(self,data):
        packet = SIP(data)
        method = packet.getMethod()
        print data
        if method == "REGISTER":
            self.register(packet)
        elif method == "INVITE":
            self.invite(packet)
        elif packet.status == "SIP/2.0/ 180 Ringing":
            self.ringing(packet)

    def genereate_via(self):
        return "Via: SIP/2.0/UDP {0};rport,branch=z9hG4bKPj{1}".format(
            self.address, 
            md5.new(str(time.time())).digest()
        )
            

    @aspects.controllMessage
    def register(self, packet):
        packet.status = "SIP/2.0 200 OK"
        self.registered[packet.getCallerID()] = {
            "ip"    :   packet.getCallerIP(), 
            "port"  :   packet.getCallerPort()
        }
        self.socket.sendto(str(packet), (packet.getCallerIP(), packet.getCallerPort()))

    @aspects.controllMessage
    def invite(self, packet):
        resend = copy.copy(packet)
        calle_id = packet.getCalleID()

        if calle_id not in self.registered:
            print 404
        elif resend.checkMaxForward():
            packet.status = "SPI/2.0 100 Trying"
            self.calls[packet.headers["Call-ID"]] = {
                "Caller" : packet.getCallerID(),
                "Calle"  : packet.getCalleID(),
                "Status" : "Triing"
            }
            self.socket.sendto(str(packet), (packet.getCallerIP(), packet.getCallerPort()))
            resend.via.append(self.genereate_via())
            ip = self.registered[calle_id]["ip"]
            port = self.registered[calle_id]["port"]
            self.socket.sendto(str(resend), (ip, port))

    @aspects.controllMessage
    def ringing(self, packet):
        packet.via.append(self.genereate_via())
        caller_id = packet.getCallerID()
        ip = self.registered[caller_id]["ip"]
        port = self.registered[caller_id]["port"]
        self.socket.sendto(str(packet), (ip, port))
        

class SIP:

    PARAMS = [
        "Max-Forwards",
        "From",
        "To",
        "Call-ID",
        "CSeq",
        "User-Agent",
        "Contact",
        "Expires",
        "Allow"
    ]

    IP_REGEX = (
        "@(((25[0-5]|2[0-4][0-9]|1?[0-9]{1,2})\.){3}"
        "(25[0-5]|2[0-4][0-9]|1?[0-9]{1,2}))"
    )

    PORT_REGEX = ":([0-9]{1,7})>"

    ID_REGEX = "sip:([a-zA-Z0-9]+)@.*"

    def __init__(self, data):
        lines = data.split("\n")
        self.status = lines.pop(0).replace("\r", "")

        lines = [line.replace("\r", "") for line in lines]

        self.via = []
        self.headers = {}

        while lines[0].split(" ", 1)[0] == "Via:":
            self.via.append(lines.pop(0))

        self.extract_headers(lines)


    def extract_headers(self, lines):
        for line in lines:
            line = line.split(" ", 1)
            if len(line) > 1:
                self.headers[line[0][:-1]] = line[1]
            else:
                break

    def __str__(self):
        result = self.status + "\n"

        for via in self.via:
            result = result + via + "\n"

        for param in self.PARAMS:
            if param in self.headers:
                result = result + "{0}: {1}\n".format(param, self.headers[param])

        result += "\r\n"

        return result

    def getCallerIP(self):
        if not hasattr(self, "caller_ip"):
            self.caller_ip = re.search(self.IP_REGEX, self.headers["Contact"]).group(1)

        return self.caller_ip

    def getCallerPort(self):
        if not hasattr(self, "caller_port"):
            self.caller_port = int(re.search(self.PORT_REGEX, self.headers["Contact"]).group(1))

        return self.caller_port
    def getCallerID(self):
        if not hasattr(self, "caller_id"):
            self.caller_id = re.search(self.ID_REGEX, self.headers["Contact"]).group(1)

        return self.caller_id

    def getMethod(self):
        return self.status.split(" ", 1)[0]

    def getCalleID(self):
        if not hasattr(self, "calle_id"):
            self.calle_id = re.search(self.ID_REGEX, self.headers["To"]).group(1)

        return self.calle_id

    def checkMaxForward(self):
        max_forwards = int(self.headers["Max-Forwards"])
        if(max_forwards == 0):
            return False
        else:
            max_forwards-=1
            self.headers["Max-Forwards"] = str(max_forwards)
            return True
