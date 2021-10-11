#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""Testing functionalities endpoints of userv4 API."""

import random
import string
import logging
import pytest


@pytest.fixture(scope="module", name="base_url")
def fixture_base_url(user_cfg):
    """Return base URL for all tests"""
    host = user_cfg['DEFAULT']['host']
    base_url = host + '/linshare/webservice/rest/user/v4'
    return base_url


@pytest.fixture(scope="function", name="random_name")
def fixture_random_name():
    """Create a new root workgroup (shared space) for test."""
    letters = string.ascii_letters
    return ''.join(random.choice(letters) for i in range(10))


@pytest.fixture(scope="function", name="new_root_workgroup")
def fixture_new_root_workgroup(request_helper, base_url, random_name):
    """Create a new root workgroup (shared space) for test."""
    query_url = '{baseUrl}/shared_spaces'.format_map({
        'baseUrl': base_url
    })
    payload = {
        "name": "workgroup_" + random_name,
        "nodeType": "WORK_GROUP"
    }
    data = request_helper.post(query_url, payload)
    log = logging.getLogger('tests.funcs.test_find_all_roles')
    log.debug("data: %s", data)
    assert data
    assert data['nodeType'] == 'WORK_GROUP'
    yield data
    query_url = '{baseUrl}/shared_spaces/{uuid}'.format_map({
        'baseUrl': base_url,
        'uuid': data['uuid']
        })
    data = request_helper.delete(query_url)
