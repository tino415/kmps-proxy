import VoIPProxyServer

server = VoIPProxyServer.Server("", 5060)

server.start()

x = "n"

while x != "q":

    if x == "accounts":
        print server.registered

    if x == "calls":
        print server.calls

    x = raw_input()

server.stop()
