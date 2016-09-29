#!/usr/bin/env python
# -*- coding: utf-8 -*-

import re
from libmproxy import controller, proxy
from libmproxy.proxy.server import ProxyServer
from datetime import datetime
from timeit import default_timer as timer
from history_proxy.parsers import get_parser
from whoosh.fields import Schema, TEXT, ID, DATETIME

import logging

# from http://code.activestate.com/recipes/576684-simple-threading-decorator/
def run_async(func):
    from threading import Thread
    from functools import wraps

    @wraps(func)
    def async_func(*args, **kwargs):
        func_hl = Thread(target=func, args=args, kwargs=kwargs)
        func_hl.start()
        return func_hl

    return async_func

@run_async
def parse_index_doc(flow, log, ix):
    start = timer()
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
        log.debug('{} is not HTTP 2xx; skipping'.format(doc['url']))
        return

    # check content type for parsability
    parser = get_parser(flow.response)

    # we only care about parsable things
    if not parser:
        log.debug('{} is not parsable; skipping'.format(doc['url']))
        return

    # only care about GET, too
    if flow.request.method != 'GET':
        log.debug('{} is not GET; skipping'.format(doc['url']))
        return

    # avoid reindexing localhost (self)
    if flow.request.host in ['127.0.0.1', 'localhost']:
        log.debug('{} is localhost; skipping'.format(doc['url']))
        return

    # if we get this far, we have a response that we probably want to index
    flow.response.decode()
    parsed_doc = parser.parse(flow.response)
    doc.update(parsed_doc)

    # we only care to store non-empty docs:
    try:
        if doc['content']:
            writer = ix.writer()
            writer.add_document(**doc)
            writer.commit()

            log.info(u'{} -> {}'.format(doc['url'], doc['title']))
        else:
            log.info('{} (not indexed)'.format(doc['url']))
    except UnicodeEncodeError:
        log.warn('{} Unicode error in doc. Of course.'.format(doc['url']))

    log.debug('Parsed document + index in {} ms.'.format((timer() - start) * 1000))


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
        start = timer()
        parse_index_doc(flow, self._log, self._ix)
        flow.reply()
        self._log.debug('Replied to proxy request in {} ms.'.format((timer() - start) * 1000))


def set_up_proxy(port, cert_path):
    config = proxy.ProxyConfig(
        port=port,
        host='127.0.0.1',
        cadir=cert_path
    )
    server = ProxyServer(config)
    return HistoryMaster(server)

def main():
    from whoosh.index import exists_in, open_dir, create_in
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

        from flask import Flask, render_template, Response, request
        from flask_bootstrap import Bootstrap
        from whoosh.query import Every
        from whoosh.qparser import QueryParser
        import signal

        def signal_handler(sig, frame):
            print ""
            print "Killing the child process"
            os.kill(pid, signal.SIGQUIT)
            # wait for mitmproxy
            os.waitpid(pid, 0)
            print "Dead."
            sys.exit(0)

        signal.signal(signal.SIGINT, signal_handler)

        app = Flask('history')
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
            query = QueryParser("content", ix.schema).parse(request.args.get('q', ''))
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


if __name__ == "__main__":
    main()
