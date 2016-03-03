#!/usr/bin/env python
# -*- coding: utf-8 -*-

import io
import os
import re
import sys
import json
import subprocess
import requests
import ipaddress
import hmac
from hashlib import sha1
from flask import Flask, request, abort
import settings
import threading

"""
Conditionally import ProxyFix from werkzeug if the USE_PROXYFIX environment
variable is set to true.  If you intend to import this as a module in your own
code, use os.environ to set the environment variable before importing this as a
module.

.. code:: python

    os.environ['USE_PROXYFIX'] = 'true'
    import flask-github-webhook-handler.index as handler

"""
if os.environ.get('USE_PROXYFIX', None) == 'true':
    from werkzeug.contrib.fixers import ProxyFix

app = Flask(__name__)
app.debug = os.environ.get('DEBUG') == 'true'

# The repos.json file should be readable by the user running the Flask app,
# and the absolute path should be given by this environment variable.
REPOS_JSON_PATH = settings.FLASK_GITHUB_WEBHOOK_REPOS_JSON


@app.route("/github_hooks", methods=['GET', 'POST'])
def index():
    if request.method == 'GET':
        return 'OK'
    elif request.method == 'POST':
        # Store the IP address of the requester
        request_ip = ipaddress.ip_address(u'{0}'.format(request.remote_addr))

        # If GHE_ADDRESS is specified, use it as the hook_blocks.
        if os.environ.get('GHE_ADDRESS', None):
            hook_blocks = [os.environ.get('GHE_ADDRESS')]
        # Otherwise get the hook address blocks from the API.
        else:
            hook_blocks = requests.get('https://api.github.com/meta').json()[
                'hooks']

        # Check if the POST request is from github.com or GHE
        for block in hook_blocks:
            if ipaddress.ip_address(request_ip) in ipaddress.ip_network(block):
                break  # the remote_addr is within the network range of github.
        else:
            abort(403)

        if request.headers.get('X-GitHub-Event') == "ping":
            return json.dumps({'msg': 'Hi!'})
        if request.headers.get('X-GitHub-Event') != "push":
            return json.dumps({'msg': "wrong event type"})

        repos = REPOS_JSON_PATH

        payload = json.loads(request.data)
        repo_meta = {
            'name': payload['repository']['name'],
            'owner': payload['repository']['owner']['name'],
        }
        repo_name = ''

        # Try to match on branch as configured in repos.json
        match = re.match(r"refs/heads/(?P<branch>.*)", payload['ref'])
        if match:
            repo_meta['branch'] = match.groupdict()['branch']
            repo_name = '{owner}/{name}/branch:{branch}'.format(**repo_meta)
            repo = repos.get(repo_name, None)

            # Fallback to plain owner/name lookup
            if not repo:
                repo_name = '{owner}/{name}'.format(**repo_meta)
                repo = repos.get(repo_name, None)

        if repo and repo.get('path', None):
            # Check if POST request signature is valid
            key = repo.get('key', None)
            if key:
                signature = request.headers.get('X-Hub-Signature').split(
                    '=')[1]
                if type(key) == unicode:
                    key = key.encode()
                mac = hmac.new(key, msg=request.data, digestmod=sha1)
                if not compare_digest(mac.hexdigest(), signature):
                    abort(403)

        if repo.get('action', None):
            for action in repo['action']:
                start_thread_action(action, repo_name)
                # error_code, output = execute_action(action)
                # text = create_text(repo_name, error_code, output)
                # if not notify_slack(text):
                #     return 'Slack error'

        return 'OK'

@app.route("/github_hooks_test", methods=['GET', 'POST'])
def index_test():
    start_thread_action(['ls'], "testrepo")

    return 'ok'

def start_thread_action(action, repo_name):
    t = threading.Thread(target=execute_action_worker, args=[action, repo_name])
    t.start()

def execute_action_worker(action, repo_name):
    error_code, output = execute_action(action)
    text = create_text(repo_name, error_code, output)
    notify_slack(text)

def execute_action(action):
    process = subprocess.Popen(action, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    process.wait()

    result = []
    for line in process.stdout:
        result.append(line)

    error_code = process.returncode
    output = unicode("".join(result), encoding="utf-8")

    return (error_code, output)

def create_text(repo_name, cmd_code, text):
    text = text.replace('&', '&amp;').replace('<', '&lt;').replace('>', '&gt;')
    return "[%s] Deployement result: *%s*\n>>>```%s```" % (repo_name, cmd_code, text)

def notify_slack(text):
    data = {
        'text': text
    }
    data = json.dumps(data)

    r = requests.post(settings.SLACK_HOOK_URL, data=data)

    return r.status_code == 200

# Check if python version is less than 2.7.7
if sys.version_info < (2, 7, 7):
    # http://blog.turret.io/hmac-in-go-python-ruby-php-and-nodejs/
    def compare_digest(a, b):
        """
        ** From Django source **

        Run a constant time comparison against two strings

        Returns true if a and b are equal.

        a and b must both be the same length, or False is
        returned immediately
        """
        if len(a) != len(b):
            return False

        result = 0
        for ch_a, ch_b in zip(a, b):
            result |= ord(ch_a) ^ ord(ch_b)
        return result == 0
else:
    compare_digest = hmac.compare_digest

if __name__ == "__main__":
    try:
        port_number = int(sys.argv[1])
    except:
        port_number = 80
    if os.environ.get('USE_PROXYFIX', None) == 'true':
        app.wsgi_app = ProxyFix(app.wsgi_app)
    app.run(host='127.0.0.1', port=port_number, debug=True)
