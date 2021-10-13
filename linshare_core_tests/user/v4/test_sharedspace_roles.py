#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""Testing functionalities endpoints of userv5 API."""


import logging
import urllib
import pytest


def test_config(display_user_cfg):
    """Just display current config."""
    display_user_cfg()


@pytest.mark.skip(reason="Works locally but not in gitlab. Weird.")
def test_find_all_roles(request_helper, base_url):
    """Test user api find all shared spaces role by nodeType."""
    query_url = '{baseUrl}/shared_space_roles'.format_map({
        'baseUrl': base_url
        })
    data = request_helper.get(query_url)
    log = logging.getLogger('tests.funcs.test_find_all_roles')
    log.debug("data: %s", data)
    assert data
    if len(data) != 0:
        for role in data:
            assert role['type'] == "WORK_GROUP"


@pytest.mark.skip(reason="Works locally but not in gitlab. Weird.")
def test_find_all_ss_roles_by_node_type_drive(request_helper, base_url):
    """Test user api find all shared spaces role by nodeType."""
    encode = urllib.parse.urlencode({'nodeType': 'DRIVE'})
    query_url = '{baseUrl}/shared_space_roles?{encode}'.format_map({
        'baseUrl': base_url,
        'encode': encode
        })
    data = request_helper.get(query_url)
    log = logging.getLogger(
        'tests.funcs.test_find_all_ss_roles_by_node_type_drive')
    log.debug("data: %s", data)
    assert data
    if len(data) != 0:
        for role in data:
            assert role['type'] == "DRIVE"
