#!/usr/bin/python
import web, SIP, config, re, logging

def delete_line(file_path, regex):
    pattern = re.compile(regex)
    lines = open(file_path, 'r').readlines()
    f = open(file_path, 'w')
    for line in lines:
        if not pattern.match(line):
            f.write(line)
    f.close()

def add_line_before(file_path, regex, new_line):
    pattern = re.compile(regex)
    lines = open(file_path, 'r').readlines()
    f = open(file_path, 'w')
    for line in lines:
        if pattern.match(line):
            f.write(new_line)
        f.write(line)
    f.close()

def replace_line(file_path, regex, new_line):
    pattern = re.compile(regex)
    lines = open(file_path, 'r').readlines()
    f = open(file_path, 'w')
    for line in lines:
        if pattern.match(line):
            f.write(new_line)
        else:
            f.write(line)
    f.close()

class PacketHandler:
    def __init__(self, packet_buff):
        self.packets = []
        self.packet_buff = packet_buff

    def add(self, packet):
        self.packets.append(packet)
        if len(self.packets) > self.packet_buff: self.packets.pop(0)

    def __str__(self):
        return ''.join(str(packet) for packet in self.packets);


class Index:
    """ Returns main page """
    def GET(self):
        global server
        return renderer.index(
            log = ''.join(open("log.txt").readlines()),
            users = server.clients,
            registered = server.route,
            port = server.port,
            ip = server.ip,
            name = server.name
        )

class ChangeSettings:
    """ Changes server settings """
    def POST(self):
        global server
        params = web.input(port=config.port, ip=config.ip, name=config.server_name)
        server.port = int(params.port)
        server.ip = params.ip
        server.name = params.name
        replace_line("./config.py",re.compile("port = .*"),"port = {}\n".format(params.port))
        replace_line("./config.py",re.compile("ip = .*"),"ip = \"{}\"\n".format(params.ip))
        replace_line("./config.py",re.compile("name = .*"),"name = \"{}\"\n".format(params.name))
        server.stop()
        server.start()

class AddUser:
    """ Add new user to sysstem """
    def POST(self):
        global server
        params = web.input(name=None, password=None)
        if params.name != None and params.password != None:
            add_line_before(
                "./config.py", 
                re.compile( '.*\}.*'),
                "    '{}' : '{}',\n".format(params.name, params.password))
            server.clients[str(params.name)] = str(params.password)

class DeleteUser:
    """ Delete specified user """
    def POST(self):
        global server
        params = web.input(name=None)
        if params.name != None:
            del server.clients[params.name]
            if params.name in server.route:
                del server.route[params.name]
            delete_line("./config.py", re.compile(".*'{}' : .*".format(params.name)))

class GetLog:
    """ Return log to user """
    def POST(self):
        return ''.join(open("log.txt").readlines())

class Resource:
    """ Return all resources that are not generated """
    def GET(self, res_type, res_name):
        return ''.join(open("./{}/{}".format(res_type, res_name)))

if __name__ == "__main__":
    urls = (
        '/', 'Index',
        '/(js|css|fonts)/(.+)', 'Resource',
        '/change_settings', 'ChangeSettings',
        '/add_user', 'AddUser',
        '/delete_user', 'DeleteUser',
        '/get_log', 'GetLog',
    )

    renderer = web.template.render('templates/')
    app = web.application(urls, globals())
    packet_handler = PacketHandler(config.packet_buff)

    server = SIP.Server(
        port = config.port,
        ip   = config.ip,
        name = config.server_name,
        packet_handler = packet_handler
    )

    server.clients = config.clients
    server.start()
    app.run()
    server.stop()
