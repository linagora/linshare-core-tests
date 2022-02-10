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


@pytest.fixture(scope="function", name="enable_work_group_creation")
def fixture_enable_work_group_creation(
        request_helper, user_cfg, admin_v5_base_url):
    """Enable WORK_GROUP__CREATION_RIGHT functionality."""
    # Enable workgroup creation
    admin_query_url = '{baseUrl}/domains/{domain}/functionalities/{identifier}'
    admin_query_url = admin_query_url.format_map({
        'domain': "LinShareRootDomain",
        'baseUrl': admin_v5_base_url,
        'identifier': 'WORK_GROUP__CREATION_RIGHT'
    })
    email = user_cfg['ADMIN']['email']
    password = user_cfg['ADMIN']['password']
    functionality = request_helper.get(
        admin_query_url, email=email, password=password)
    functionality['activationPolicy']['enable']['value'] = True
    request_helper.put(
        admin_query_url, functionality, email=email, password=password)

    yield True

    functionality['activationPolicy']['enable']['value'] = False
    request_helper.put(
        admin_query_url, functionality, email=email, password=password)


@pytest.fixture(scope="function", name="new_root_workgroup")
def fixture_new_root_workgroup(
        request_helper, base_url, random_name, enable_work_group_creation):
    """Create a new root workgroup (shared space) for test."""
    assert enable_work_group_creation
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
