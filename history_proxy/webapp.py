# -*- coding: utf-8 -*-

from flask import Flask, render_template, Response, request
from flask_bootstrap import Bootstrap
from whoosh.query import Every
from whoosh.qparser import QueryParser
import signal
import os
import sys
import re
from .webapp_config import Config

def make_flask_app(pid, whoosh, index_dir):
    def signal_handler(sig, frame):
        print ""
        print "Killing the child process"
        os.kill(pid, signal.SIGQUIT)
        # wait for mitmproxy
        os.waitpid(pid, 0)
        print "Dead."
        sys.exit(0)

    signal.signal(signal.SIGINT, signal_handler)

    app = Flask('history', static_folder='webroot')
    app.config.from_object(Config)
    Bootstrap(app)

    @app.template_filter('nicer_url')
    def nicer_url(n):
        return re.sub(r'\?.+', '?...', n)

    @app.route('/')
    def index():
        results = whoosh.searcher().search(Every(), sortedby='ts', reverse=True, limit=100)
        return render_template('history.html', hits=results)

    @app.route('/search')
    def search():
        query = QueryParser("content", whoosh.schema).parse(request.args.get('q', ''))
        results = whoosh.searcher().search(query, limit=100)
        return render_template('history.html', hits=results)

    @app.route('/cert')
    def cert():
        with open(os.path.join(index_dir, "mitmproxy-ca-cert.pem")) as f:
            cert = f.read()
        return Response(cert, mimetype='application/x-x509-ca-cert')

    return app
