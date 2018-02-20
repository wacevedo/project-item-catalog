import sys
sys.path.insert(0, '/var/www/html/catalog')
from project import app as application
application.secret_key = 'mega_secret_key'
application.debug = False
