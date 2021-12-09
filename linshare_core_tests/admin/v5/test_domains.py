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


def test_delete(request_helper, base_url):
    """Deleting a domain"""
    # Given
    payload = {
        "name": "ToBeDeleted",
        "parent": {"uuid": "LinShareRootDomain"},
        "type": "TOPDOMAIN"
    }
    query_url = '{baseUrl}/domains'.format_map({
        'baseUrl': base_url
    })
    domain = request_helper.post(query_url, payload)

    # When
    query_url = '{baseUrl}/domains/{uuid}'.format_map({
        'baseUrl': base_url,
        'uuid': domain['uuid']
    })
    deleted = request_helper.delete(query_url)

    # Then
    assert deleted


def test_delete_should_fail_when_null_uuid_and_payload(
        request_helper, base_url):
    """Deleting a domain should fail on null uuid and payload"""
    query_url = '{baseUrl}/domains'.format_map({
        'baseUrl': base_url
    })
    request_helper.delete(query_url, expected_status=400)


def test_delete_should_fail_when_root_domain(request_helper, base_url):
    """Deleting a domain should fail on root domain"""
    query_url = '{baseUrl}/domains/{uuid}'.format_map({
        'baseUrl': base_url,
        'uuid': 'LinShareRootDomain'
    })
    request_helper.delete(
        query_url, expected_status=403, busines_err_code=13021)


def test_delete_should_fail_when_parent_domain(request_helper, base_url):
    """Deleting a parent domain should fail"""
    query_url = '{baseUrl}/domains'.format_map({
        'baseUrl': base_url
    })
    payload = {
        "name": "MyNewDomain",
        "parent": {"uuid": "LinShareRootDomain"},
        "type": "TOPDOMAIN"
    }
    parent = request_helper.post(query_url, payload)
    query_url = '{baseUrl}/domains'.format_map({
        'baseUrl': base_url
    })
    payload = {
        "name": "MyNewNestedDomain",
        "parent": {"uuid": parent['uuid']},
        "type": "SUBDOMAIN"
    }
    request_helper.post(query_url, payload)

    query_url = '{baseUrl}/domains/{uuid}'.format_map({
        'baseUrl': base_url,
        'uuid': parent['uuid']
    })
    request_helper.delete(
        query_url, expected_status=403, busines_err_code=13021)


def test_delete_should_fail_when_unknown(request_helper, base_url):
    """Deleting a domain should fail on unknown domain"""
    query_url = '{baseUrl}/domains/{uuid}'.format_map({
        'baseUrl': base_url,
        'uuid': 'unknown'
    })
    request_helper.delete(query_url, expected_status=404)
