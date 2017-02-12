from werkzeug.contrib.fixers import ProxyFix
from index import app as application

if __name__ == '__main__':
    application.wsgi_app = ProxyFix(application.wsgi_app)
    application.run()
