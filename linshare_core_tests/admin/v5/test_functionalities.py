#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""Testing functionalities endpoints of adminv5 API."""


import os
import json
import logging
import urllib

from deepdiff import DeepDiff


def load_data_from_file(test_file):
    """Read a json file and converter it to a python dict."""
    test_dir = os.path.dirname(os.path.abspath(__file__))
    with open(test_dir + '/' + test_file, encoding='UTF-8') as json_file:
        return json.load(json_file)


def test_config(display_admin_cfg):
    """Just display current config."""
    display_admin_cfg()


def test_find_all_functionalites(request_helper, base_url):
    """Test find all functionalities for root domain on API v5"""
    query_url = '{baseUrl}/domains/{domain}/functionalities'
    query_url = query_url.format_map({
        'domain': "LinShareRootDomain",
        'baseUrl': base_url
    })
    data = request_helper.get(query_url)
    log = logging.getLogger('tests.funcs.test_find_all_functionalites')
    log.debug("functionalities: %s", data)
    assert data
    assert len([a['identifier'] for a in data]) == 17


def test_find_all_functionalites_and_subs(request_helper, base_url):
    """Test find all functionalities for root domain on API v5"""
    encoded_url = urllib.parse.urlencode(
        {
            'subs': True
        }
    )
    query_url = '{baseUrl}/domains/{domain}/functionalities?{encode}'
    query_url = query_url.format_map({
        'domain': "LinShareRootDomain",
        'baseUrl': base_url,
        'encode': encoded_url}
    )
    data = request_helper.get(query_url)
    log = logging.getLogger('tests.funcs.test_find_all_functionalites_and_sub')
    log.debug("functionalities: %s", data)
    assert data
    assert len([a['identifier'] for a in data]) == 45
    assert not DeepDiff(
        data,
        load_data_from_file("test_functionalities.all.json")
    )


def test_find_functionality_share_expiration(request_helper, base_url):
    """Test find all functionalities for root domain on API v5"""
    query_url = '{baseUrl}/domains/{domain}/functionalities/{identifier}'
    query_url = query_url.format_map({
        'domain': "LinShareRootDomain",
        'baseUrl': base_url,
        'identifier': 'SHARE_EXPIRATION'
    })
    data = request_helper.get(query_url)
    log = logging.getLogger('tests.funcs.test_find_functionality')
    log.debug("functionalities: %s", data)
    assert data
    assert not DeepDiff(
        data,
        load_data_from_file("test_functionalities.share_expiration.json")
    )
