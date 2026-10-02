#!/bin/bash
# DVGA setup: create isolated venv with Python-3.12-compatible versions of DVGA's pinned deps
# Fidelity note: graphene/graphql-core pins are kept EXACT (schema depends on them).
# Only gevent/greenlet/SQLAlchemy/Flask micro-bumped for CPython 3.12 compat (API-compatible lines).
set -x
cd /home/z/my-project/gap-validation/targets/dvga
python3 -m venv /home/z/my-project/gap-validation/dvga-venv
source /home/z/my-project/gap-validation/dvga-venv/bin/activate
pip install -q --upgrade pip
pip install -q \
  "aniso8601==7.0.0" \
  "attrs" "bidict" "certifi" "charset-normalizer" "click" \
  "Flask==2.2.5" "Flask-GraphQL==2.0.1" "Flask-GraphQL-Auth==1.3.3" \
  "Flask-SocketIO==5.3.2" "Flask-SQLAlchemy==3.0.2" \
  "gevent>=24.2.1" "greenlet>=3.0" "gevent-websocket==0.10.1" \
  "graphene==2.1.9" "graphene-sqlalchemy==2.3.0" \
  "graphql-core==2.3.2" "graphql-relay==2.0.1" "graphql-server-core==1.2.0" \
  "graphql-ws==0.4.4" "h11" "idna" "itsdangerous" "Jinja2" "MarkupSafe" \
  "packaging" "pluggy" "promise==2.3" "PyJWT==2.8.0" "pytest" \
  "python-engineio==4.3.4" "python-socketio==5.7.2" "requests" "Rx==1.6.1" \
  "simple-websocket==0.9.0" "singledispatch" "six" \
  "SQLAlchemy==1.4.54" "tomli" "urllib3" "Werkzeug==2.2.3" "wsproto" \
  "zope.event" "zope.interface" 2>&1 | tail -5
# DVGA's git-hosted dep (dolevf's fork of flask-sockets)
pip install -q "git+https://github.com/dolevf/flask-sockets@master" 2>&1 | tail -3
pip list 2>/dev/null | grep -Ei "graphene|gevent|flask|sqlalchemy|graphql|jwt|socketio"
