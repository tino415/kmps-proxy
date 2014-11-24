#!/usr/bin/python
import web, SIP, config, run

urls = (
    '/', 'Index',
    '/(js|css|fonts)/(.+)', 'Resource',
)

server = SIP.Server(
    port = config.port,
    ip   = config.ip,
    name = config.server_name
)

app = web.application(urls, globals())

class Index:
    """ Returns main page """
    def GET(self):
        return ''.join(open("./templates/index.html").readlines())

class Resource:
    """ Return all resources that are not generated """
    def GET(self, res_type, res_name):
        return ''.join(open("./{}/{}".format(res_type, res_name)))

if __name__ == "__main__":
    app.run()
