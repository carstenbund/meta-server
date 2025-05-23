import os
import sys

# Ensure we can import mserver from parent directory
sys.path.append(os.path.dirname(os.path.dirname(__file__)))

import mserver

# Override paths using environment variables
mserver.BASE_DIR = os.environ.get('BASE_DIR', '/data')
mserver.STATIC_DIR = os.environ.get('STATIC_DIR', '/app/static')
mserver.THUMBNAILS_DIR = os.environ.get('THUMBNAILS_DIR', '/app/thumbnails')

app = mserver.app

if __name__ == '__main__':
    web_ip = os.environ.get('WEB_IP', '0.0.0.0')
    web_port = int(os.environ.get('WEB_PORT', '5000'))
    app.run(host=web_ip, port=web_port, debug=True, use_reloader=False)
