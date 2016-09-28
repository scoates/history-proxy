#!/usr/bin/env python
"""
"""

import re
from libmproxy import controller, proxy
from libmproxy.proxy.server import ProxyServer
from bs4 import BeautifulSoup
from bs4.element import Comment
from datetime import datetime

from whoosh.fields import Schema, TEXT, ID, DATETIME

import logging

class HistoryMaster(controller.Master):
    def __init__(self, server):
        controller.Master.__init__(self, server)

    def run(self, ix, log):
        self._ix = ix
        self._log = log

        try:
            return controller.Master.run(self)
        except KeyboardInterrupt:
            self.shutdown()

    def handle_response(self, flow):
        doc = {
            'ts': datetime.now()
        }

        # ignore the port part if it's the default port
        if ((flow.request.scheme == 'http' and flow.request.port != 80) or
                (flow.request.scheme == 'https' and flow.request.port != 443)):
            port = ':{}'.format(flow.request.port)
        else:
            port = ''

        doc['url'] = unicode('{}://{}{}{}'.format(
            flow.request.scheme,
            flow.request.host,
            port,
            flow.request.path
        ), "utf-8")

        # we only care about success
        if flow.response.code < 200 or flow.response.code >= 300:
            self._log.debug('{} is not HTTP 2xx; skipping'.format(doc['url']))
            flow.reply()
            return

        # check content type for HTML
        is_html = False
        content_type = flow.response.headers.get('content-type')
        if content_type:
            for h in content_type:
                if h.lower().startswith('text/html'):
                    is_html = True
                    break;

        # we only care about HTML
        if not is_html:
            self._log.debug('{} is not HTML; skipping'.format(doc['url']))
            flow.reply()
            return

        # only care about GET, too
        if flow.request.method != 'GET':
            self._log.debug('{} is not GET; skipping'.format(doc['url']))
            flow.reply()
            return

        # avoid reindexing localhost (self)
        if flow.request.host in ['127.0.0.1', 'localhost']:
            self._log.debug('{} is localhost; skipping'.format(doc['url']))
            flow.reply()
            return

        # if we get this far, we have a response that we probably want to index
        flow.response.decode()
        soup = BeautifulSoup(flow.response.content, "lxml")
        if soup.title and soup.title.string:
            doc['title'] = soup.title.string.strip()
        else:
            doc['title'] = u''

        texts = soup.findAll(text=True)
        visible_texts = filter(self._visible, texts)
        if visible_texts:
            doc['content'] = re.sub(r'\s+', ' ', ' '.join(visible_texts))
        else:
            doc['content'] = None

        # we only care to store non-empty docs:
        try:
            if doc['content']:
                writer = self._ix.writer()
                writer.add_document(**doc)
                writer.commit()

                self._log.info('{} -> {}'.format(doc['url'], doc['title']))
            else:
                self._log.info('{} (not indexed)'.format(doc['url']))
        except UnicodeEncodeError:
            self._log.warn('{} Unicode error in doc. Of course.'.format(doc['url']))

        # ebb
        flow.reply()

    def _visible(self, element):
        if element.parent.name in ['style', 'script', '[document]', 'head', 'title']:
            return False
        elif isinstance(element, Comment):
            return False

        if element.strip():
            return True
        return False


# def set_up_es(host, port):
#     from elasticsearch import Elasticsearch
#     return Elasticsearch([{'host': args.es_host, 'port': args.es_port}])

def set_up_proxy(port, cert_path):
    config = proxy.ProxyConfig(
        port=port,
        host='127.0.0.1',
        cadir=cert_path
    )
    server = ProxyServer(config)
    return HistoryMaster(server)


if __name__ == "__main__":

    from whoosh.index import exists_in, open_dir, create_in
    from whoosh.fields import TEXT, ID, DATETIME
    import os, sys
    import argparse

    parser = argparse.ArgumentParser()
    parser.add_argument("-p", "--port", help="proxy port", default=8080, type=int)
    parser.add_argument("-a", "--app-port", help="app port", default=8000, type=int)
    parser.add_argument("-l", "--log", dest="logLevel", help="Log level",
            choices=['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL'],
            type=str.upper, default="INFO")
    parser.add_argument("-v", "--verbose", action="store_true",
            help="Allow other libraries to log at same level")
    parser.add_argument("-i", "--index-dir", help="Search Index Directory",
            default=os.path.expanduser('~/.history_proxy'))
    args = parser.parse_args()

    log = logging.getLogger('history')
    logLevel = getattr(logging, args.logLevel)
    log.setLevel(logLevel)

    if args.verbose:
        # elasticsearch + urllib3
        logging.basicConfig(level=logLevel)
        log.warn("Verbose: set all logging levels to: {}".format(logLevel))
    else:
        logging.basicConfig()

    log.debug("Started logging with level: {}".format(logLevel))

    if exists_in(args.index_dir):
        ix = open_dir(args.index_dir)
    else:
        if not os.path.isdir(args.index_dir):
            os.mkdir(args.index_dir)
        schema = Schema(
            ts=DATETIME(sortable=True),
            url=ID(stored=True),
            title=TEXT(stored=True),
            content=TEXT(stored=True))
        ix = create_in(args.index_dir, schema)

    pid = os.fork()
    if pid == 0:
        # child
        # here's where we run mitmproxy
        log.info('Starting proxy server on port http://127.0.0.1:{}'.format(args.port))
        m = set_up_proxy(args.port, args.index_dir)
        m.run(ix, log)
        sys.exit(0)

    else:
        # and here's where we run the main server

        # ...

        from flask import Flask, jsonify, render_template, Response, request
        from flask_bootstrap import Bootstrap
        from whoosh.query import Every
        from whoosh.qparser import QueryParser
        import signal

        def signal_handler(sig, frame):
            print("")
            print("Killing the child process")
            os.kill(pid, signal.SIGQUIT)
            # wait for mitmproxy
            os.waitpid(pid, 0)
            print("Dead.")
            sys.exit(0)

        signal.signal(signal.SIGINT, signal_handler)

        app = Flask('history')
        # need to do this because otherwise it forks and messes up the child
        Bootstrap(app)

        @app.template_filter('nicer_url')
        def nicer_url(n):
            return re.sub(r'\?.+', '?...', n)

        @app.route('/')
        def index():
            results = ix.searcher().search(Every(), sortedby='ts', reverse=True, limit=100)
            return render_template('history.html', hits=results)

        @app.route('/search')
        def search():
            query = QueryParser("content", ix.schema).parse(request.args.get('q'))
            results = ix.searcher().search(query, limit=100)
            return render_template('history.html', hits=results)

        @app.route('/cert')
        def cert():
            with open(os.path.join(args.index_dir, "mitmproxy-ca-cert.pem")) as f:
                cert = f.read()
            return Response(cert, mimetype='application/x-x509-ca-cert')

        log.info('Starting app server on port http://127.0.0.1:{}'.format(args.app_port))
        # intentionally hard-bound to localhost
        app.config['LOGGER_NAME'] = 'history'
        app.config['TESTING'] = 'True'
        app.run(host='127.0.0.1', port=args.app_port)
