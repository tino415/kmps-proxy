import web

urls = (
    '/', 'Index',
    '/(js|css)/(.+)', 'Resource',
)

app = web.application(urls, globals())

class Index:
    def GET(self):
        return ''.join(open("./templates/index.html").readlines())

class Resource:
    def GET(self, res_type, res_name):
        return ''.join(open("./{}/{}".format(res_type, res_name)))

if __name__ == "__main__":
    app.run()
