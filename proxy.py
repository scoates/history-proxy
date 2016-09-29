import argparse
import os
import logging
from history_proxy.webapp import make_flask_app
from history_proxy.mitm import run_mitm_proxy
from whoosh.index import exists_in, open_dir, create_in
from whoosh.fields import Schema, TEXT, ID, DATETIME
import sys

def get_whoosh(index_dir):
    if exists_in(index_dir):
        return open_dir(index_dir)
    else:
        if not os.path.isdir(index_dir):
            os.mkdir(index_dir)
        schema = Schema(
            ts=DATETIME(sortable=True),
            url=ID(stored=True),
            title=TEXT(stored=True),
            content=TEXT(stored=True))
        return create_in(index_dir, schema)

def main():
    parser = argparse.ArgumentParser(description='Searchable history web proxy.')
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
    log_level = getattr(logging, args.logLevel)
    log.setLevel(log_level)

    if args.verbose:
        logging.basicConfig(level=log_level)
        log.warn("Verbose: set all logging levels to: {}".format(log_level))
    else:
        logging.basicConfig()

    log.debug("Started logging with level: {}".format(log_level))

    whoosh = get_whoosh(args.index_dir)
    pid = os.fork()
    if pid == 0:
        # child
        # here's where we run mitmproxy
        log.info('Starting proxy server on port http://127.0.0.1:{}'.format(args.port))
        run_mitm_proxy(whoosh, args.port, args.index_dir, log)
        sys.exit(0)
    else:
        # and here's where we run the main server
        app = make_flask_app(pid, whoosh, args.index_dir)
        log.info('Starting app server on port http://127.0.0.1:{}'.format(args.app_port))
        # intentionally hard-bound to localhost
        app.run(host='127.0.0.1', port=args.app_port)

if __name__ == "__main__":
    main()
