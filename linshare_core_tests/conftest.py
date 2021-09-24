#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Common fixtures"""


import os
import configparser
import logging
import pytest


@pytest.fixture(scope="session", name="admin_cfg")
def fixture_admin_cfg():
    """Return a object will all configuration properties for admin api"""

    log = logging.getLogger('tests.configtest')
    config_file_admin = os.getenv('CONFIG_FILE_ADMIN', None)
    if not config_file_admin:
        config_file_admin = 'linshare.admin.ini'
    log.debug("config_file_admin: %s", config_file_admin)
    config = configparser.ConfigParser()
    config.read(config_file_admin)
    return config


@pytest.fixture(scope="session", name="admin_debug_flag")
def fixture_admin_debug_flag(admin_cfg):
    """Return true if debug mode is eanbled."""
    debug = False
    if int(admin_cfg['DEFAULT']['debug']) == 1:
        debug = True
    if os.getenv('LS_TEST_DEBUG', None):
        debug = True
    return debug
