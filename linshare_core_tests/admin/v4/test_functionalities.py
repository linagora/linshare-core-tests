#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""Testing functionalities endpoints of adminv5 API."""


import logging
import urllib


def test_config(admin_cfg, base_url):
    """Just display current config."""
    print()
    print(admin_cfg['DEFAULT']['host'])
    print(admin_cfg['DEFAULT']['email'])
    print(admin_cfg['DEFAULT']['password'])
    print(base_url)


def test_find_all_functionalites(request_helper, base_url):
    """Test find all functionalities for root domain on API v4"""
    encoded_url = urllib.parse.urlencode({'domainId': "LinShareRootDomain"})
    query_url = '{baseUrl}/functionalities?{encode}'
    query_url = query_url.format_map({
        'baseUrl': base_url,
        'encode': encoded_url}
    )
    data = request_helper.get(query_url)
    log = logging.getLogger('tests.funcs.test_find_all_functionalites')
    log.debug("functionalities: %s", data)
    assert data
    assert len([a['identifier'] for a in data]) == 17


def test_find_all_functionalites_and_subs(request_helper, base_url):
    """Test find all functionalities for root domain on API v4"""
    encoded_url = urllib.parse.urlencode(
        {
            'domainId': "LinShareRootDomain",
            'subs': True
        }
    )
    query_url = '{baseUrl}/functionalities?{encode}'
    query_url = query_url.format_map({
        'baseUrl': base_url,
        'encode': encoded_url}
    )
    data = request_helper.get(query_url)
    log = logging.getLogger('tests.funcs.test_find_all_functionalites_and_sub')
    log.debug("functionalities: %s", data)
    assert data
    assert len([a['identifier'] for a in data]) == 45
