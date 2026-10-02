#!/bin/bash
# DVGA venv - fixed install order:
# 1) base pins EXCEPT the conflicting auth pkg
# 2) flask-graphql-auth with its own PyJWT resolution
# 3) force final Flask/Werkzeug line
set -x
source /home/z/my-project/gap-validation/dvga-venv/bin/activate
cd /home/z/my-project/gap-validation/targets/dvga
pip install -q \
  "aniso8601==7.0.0" "attrs" "bidict" "certifi" "click" \
  "Flask-GraphQL==2.0.1" \
  "Flask-SocketIO==5.3.2" "Flask-SQLAlchemy==3.0.2" \
  "gevent>=24.2.1" "greenlet>=3.0" "gevent-websocket==0.10.1" \
  "graphene==2.1.9" "graphene-sqlalchemy==2.3.0" \
  "graphql-core==2.3.2" "graphql-relay==2.0.1" "graphql-server-core==1.2.0" \
  "graphql-ws==0.4.4" "itsdangerous" "Jinja2" "MarkupSafe" \
  "packaging" "pluggy" "promise==2.3" "pytest" \
  "python-engineio==4.3.4" "python-socketio==5.7.2" "requests" "Rx==1.6.1" \
  "simple-websocket==0.9.0" "singledispatch" "six" \
  "SQLAlchemy==1.4.54" "tomli" "urllib3" "wsproto" \
  "zope.event" "zope.interface" 2>&1 | tail -3
pip install -q "Flask-GraphQL-Auth==1.3.3" 2>&1 | tail -3
pip install -q "Flask==2.2.5" "Werkzeug==2.2.3" "Jinja2==3.1.2" "itsdangerous==2.1.2" "click==8.1.3" 2>&1 | tail -3
pip install -q "git+https://github.com/dolevf/flask-sockets@master" 2>&1 | tail -2
pip install -q "Flask==2.2.5" "Werkzeug==2.2.3" 2>&1 | tail -2
echo "=== FINAL PKGS ==="
pip list 2>/dev/null | grep -Ei "^(flask|gevent|graphene|graphql|sqlalchemy|pyjwt|rx|promise|simple-websocket|singledispatch|aniso8601) "
