#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""Testing functionalities endpoints of adminv5 API."""


import urllib
import logging


def test_config(display_admin_cfg):
    """Just display current config."""
    display_admin_cfg()


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


def test_create_with_add_to_domain_policy(request_helper, base_url):
    """Trying to create a top domain with its own domain policy,
    Then create a neste domain (subdomain) and make this domain use the
    previously created domain policy. This second domain is also added
    to the policy to allow domains to communicate between each other.
    """
    log = logging.getLogger('tests.test_create_with_add_to_domain_policy')
    encoded_url = urllib.parse.urlencode(
        {
            'dedicatedDomainPolicy': True
        }
    )
    query_url = '{baseUrl}/domains?{encode}'
    query = query_url.format_map({
        'baseUrl': base_url,
        'encode': encoded_url
    })
    payload = {
        "name": "MyNewDomain",
        "parent": {"uuid": "LinShareRootDomain"},
        "type": "TOPDOMAIN"
    }
    data = request_helper.post(query, payload)
    log.debug("domains: %s", data)
    assert data
    assert data['name'] == 'MyNewDomain'
    assert data['creationDate']
    assert data['domainPolicy']
    assert data['domainPolicy']['name'] == 'MyNewDomain'
    encoded_url = urllib.parse.urlencode(
        {
            'addItToDomainPolicy': data['domainPolicy']['uuid'],
        }
    )
    query_url = '{baseUrl}/domains?{encode}'
    query = query_url.format_map({
        'baseUrl': base_url,
        'encode': encoded_url
    })
    payload = {
        "name": "MyNewNestedDomain",
        "parent": {"uuid": data['uuid']},
        "domainPolicy": {"uuid": data['domainPolicy']['uuid']},
        "type": "SUBDOMAIN"
    }
    data2 = request_helper.post(query, payload)
    log.debug("domains: %s", data2)
    assert data2
    assert data2['name'] == 'MyNewNestedDomain'
    assert data2['creationDate']
    assert data2['domainPolicy']
    assert data2['domainPolicy']['name'] == 'MyNewDomain'
