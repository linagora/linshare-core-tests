#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""Testing users endpoints of adminv5 API."""


import urllib
import logging
import pytest
# import json


def test_config(admin_cfg, base_url):
    """Just display current config."""
    print()
    print(admin_cfg['DEFAULT']['host'])
    print(admin_cfg['DEFAULT']['email'])
    print(admin_cfg['DEFAULT']['password'])
    print(base_url)


def test_find_all(request_helper, base_url):
    """Test find all users on API v5"""
    query_url = '{baseUrl}/users'.format_map({
        'baseUrl': base_url
    })
    users = request_helper.get(query_url)
    log = logging.getLogger('tests.funcs.test_find_all')
    log.debug("users: %s", users)
    assert users
    if len(users) != 0:
        for user in users:
            assert user['uuid'] != "root@localhost.localdomain"

