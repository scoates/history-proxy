# -*- coding: utf-8 -*-

from bs4 import BeautifulSoup
from bs4.element import Comment
import re
import cgi
import chardet

def get_parser(request):
    for parser in PARSERS:
        if parser.can_parse(request):
            return parser

def get_charset(request):
    content_type = request.headers.get('content-type', [])
    for header in content_type:
        mimetype, options = cgi.parse_header(header)
        if 'charset' in options:
            return options['charset']
    return chardet.detect(request.content)['encoding']

class RequestParser(object):
    @classmethod
    def can_parse(cls, request):
        """
            can_parse should return True if this parser can parse the given request
            ideally it will not have to decode or look at the response body to figure
            this out
        """
        raise NotImplementedError('users must define can_parse to use this base class')

    @classmethod
    def parse(cls, request):
        """
            returns a dict with `title` and `content`
        """
        raise NotImplementedError('users must define parse to use this base class')


class HTMLParser(RequestParser):
    @classmethod
    def can_parse(cls, request):
        content_type = request.headers.get('content-type', [])
        return any(mimetype.lower() == 'text/html' for mimetype, options in
                    (cgi.parse_header(header) for header in content_type))

    @staticmethod
    def element_visible(element):
        if element.parent.name in ['style', 'script', '[document]', 'head', 'title']:
            return False
        elif isinstance(element, Comment):
            return False
        if element.strip():
            return True
        return False

    @classmethod
    def parse(cls, request):
        output = {}
        soup = BeautifulSoup(request.content, "lxml")
        if soup.title and soup.title.string:
            output['title'] = soup.title.string.strip()
        else:
            output['title'] = u''

        texts = soup.findAll(text=True)
        visible_texts = [text for text in texts if cls.element_visible(text)]
        if visible_texts:
            output['content'] = re.sub(r'\s+', ' ', ' '.join(visible_texts))
        else:
            output['content'] = None

        return output


class TextParser(RequestParser):
    @classmethod
    def can_parse(cls, request):
        content_type = request.headers.get('content-type', [])
        return any(mimetype.lower() == 'text/plain' for mimetype, options in
                    (cgi.parse_header(header) for header in content_type))

    @classmethod
    def parse(cls, request):
        encoding = get_charset(request)
        return dict(
            content=request.content.decode(encoding),
            title=u'',
        )


PARSERS = [HTMLParser, TextParser]
