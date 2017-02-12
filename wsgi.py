from werkzeug.contrib.fixers import ProxyFix
from index import app as application

application.wsgi_app = ProxyFix(application.wsgi_app)

if __name__ == '__main__':
    application.run()
