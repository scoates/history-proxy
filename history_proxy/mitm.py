# -*- coding: utf-8 -*-
from datetime import datetime
from timeit import default_timer as timer
from history_proxy.parsers import get_parser
from libmproxy import controller, proxy
from libmproxy.proxy.server import ProxyServer

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
def parse_index_doc(flow, log, whoosh):
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
            writer = whoosh.writer()
            writer.add_document(**doc)
            writer.commit()

            log.info(u'{} -> {}'.format(doc['url'], doc['title']))
        else:
            log.info('{} (not indexed)'.format(doc['url']))
    except UnicodeEncodeError:
        log.warn('{} Unicode error in doc. Of course.'.format(doc['url']))

    log.debug('Parsed document + index in {} ms.'.format((timer() - start) * 1000))


class HistoryMaster(controller.Master):
    def __init__(self, server, whoosh, log):
        controller.Master.__init__(self, server)
        self._whoosh = whoosh
        self._log = log

    def run(self):
        try:
            return controller.Master.run(self)
        except KeyboardInterrupt:
            self.shutdown()

    def handle_response(self, flow):
        start = timer()
        parse_index_doc(flow, self._log, self._whoosh)
        flow.reply()
        self._log.debug('Replied to proxy request in {} ms.'.format((timer() - start) * 1000))


def run_mitm_proxy(whoosh, port, index_dir, log):
    config = proxy.ProxyConfig(
        port=port,
        host='127.0.0.1',
        cadir=index_dir
    )
    server = ProxyServer(config)
    history_master = HistoryMaster(server, whoosh, log)
    history_master.run()
