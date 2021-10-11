#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""Testing functionalities endpoints of userv5 API."""


import logging


def test_config(display_user_cfg):
    """Just display current config."""
    display_user_cfg()


def test_find_quota(request_helper, base_url, new_root_workgroup):
    """Test user api find all shared spaces role by nodeType."""
    query_url = '{baseUrl}/quota/{uuid}'.format_map({
        'baseUrl': base_url,
        'uuid': new_root_workgroup['quotaUuid']
        })
    data = request_helper.get(query_url)
    log = logging.getLogger('tests.funcs.test_find_quota')
    log.debug("data: %s", data)
    assert data
    assert len(data) == 4
    assert data['maxFileSize'] == 10000000000
    assert data['quota'] == 400000000000
    assert data['usedSpace'] == 0
    assert not data['maintenance']
