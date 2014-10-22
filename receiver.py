import socket

sock = socket.socket(socket.AF_INET,
                     socket.SOCK_DGRAM) 

sock.bind(("127.0.0.1", 5060))

while True:
    data, address = sock.recvfrom(1024)
    print "RECEIVED : ", data
