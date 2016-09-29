# -*- coding: utf-8 -*-
import logging

class Config(object):
    APP_NAME = 'history'
    HOST = 'localhost'

    # DEBUG = True
    TESTING = True
    TRAP_BAD_REQUEST_ERRORS = True

    SECRET_KEY = 'cISp2iz/EHDix6z4G5Jem0MOazO6mQkd5t+DX6MahMs='

    DEFAULT_LOG_LEVEL = logging.WARNING

    LOGGER_NAME = 'history'
