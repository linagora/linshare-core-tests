#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""Testing functionalities endpoints of adminv5 API."""


import logging
import urllib


def test_config(display_admin_cfg):
    """Just display current config."""
    display_admin_cfg()


def test_find_all_functionalites(request_helper, base_url, admin_cfg):
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
    funct_count = int(admin_cfg['FUNCTIONALITIES']['count'])
    assert funct_count == len([a['identifier'] for a in data])


def test_find_all_functionalites_and_subs(request_helper, base_url, admin_cfg):
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
    funct_count = int(admin_cfg['FUNCTIONALITIES']['count_with_nested'])
    assert data
    assert funct_count == len([a['identifier'] for a in data])
