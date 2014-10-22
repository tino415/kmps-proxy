import socket

sock = socket.socket(socket.AF_INET,
                     socket.SOCK_DGRAM)

while True:
    sock.sendto(raw_input("Message to send: "), ("127.0.0.1", 5060))
    command = raw_input("q to end, n to next : ")
    if command == "q":
        break
