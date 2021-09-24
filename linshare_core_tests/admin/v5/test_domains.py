#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""Testing functionalities endpoints of adminv5 API."""


import urllib
import logging


def test_config(admin_cfg, base_url):
    """Just display current config."""
    print()
    print(admin_cfg['DEFAULT']['host'])
    print(admin_cfg['DEFAULT']['email'])
    print(admin_cfg['DEFAULT']['password'])
    print(base_url)


def test_find_all(request_helper, base_url):
    """Getting all domains from LinShare"""
    query_url = '{baseUrl}/domains'.format_map({
        'baseUrl': base_url
    })
    data = request_helper.get(query_url)
    log = logging.getLogger('tests.domains.test_find_all')
    log.debug("domains: %s", data)
    assert data


def test_create(request_helper, base_url):
    """Trying to create a top domain"""
    log = logging.getLogger('tests.domains.test_find_all')
    payload = {
        "name": "MyNewDomain",
        "parent": {"uuid": "LinShareRootDomain"},
        "type": "TOPDOMAIN"
    }
    query_url = '{baseUrl}/domains'.format_map({
        'baseUrl': base_url
    })
    data = request_helper.post(query_url, payload)
    log.debug("domains: %s", data)
    assert data
    assert data['name'] == 'MyNewDomain'
    assert data['creationDate']
    assert data['domainPolicy']
    assert data['domainPolicy']['uuid'] == 'DefaultDomainPolicy'


def test_create_with_dedicated_domain_policy(request_helper, base_url):
    """Trying to create a top domain with its own domain policy"""
    log = logging.getLogger('tests.domains.test_find_all')
    encoded_url = urllib.parse.urlencode(
        {
            'dedicatedDomainPolicy': True
        }
    )
    query_url = '{baseUrl}/domains?{encode}'
    query_url = query_url.format_map({
        'baseUrl': base_url,
        'encode': encoded_url
    })
    payload = {
        "name": "MyNewDomain",
        "parent": {"uuid": "LinShareRootDomain"},
        "type": "TOPDOMAIN"
    }
    data = request_helper.post(query_url, payload)
    log.debug("domains: %s", data)
    assert data
    assert data['name'] == 'MyNewDomain'
    assert data['creationDate']
    assert data['domainPolicy']
    assert data['domainPolicy']['name'] == 'MyNewDomain'