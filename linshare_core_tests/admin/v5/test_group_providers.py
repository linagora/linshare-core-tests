#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""Testing group providers endpoints of adminv5 API."""


import urllib
import logging
import pytest
# import json


def test_config(admin_cfg, base_url):
    """Just display current config."""
    print()
    print(admin_cfg['DEFAULT']['host'])
    print(admin_cfg['DEFAULT']['email'])
    print(admin_cfg['DEFAULT']['password'])
    print(base_url)


def test_create(request_helper, base_url):
    """Test admin create group provider."""
    log = logging.getLogger('tests.group.providers.test_create')
    payload = {
            "name": "new connection",
            "bindDn":  "cn=linshare,dc=linshare,dc=org",
            "url": "ldap://172.17.0.1:1389",
            "bindPassword":"linshare"
        }
    query_url = '{baseUrl}/remote_servers'.format_map({
            'baseUrl' : base_url})
    ldap_server = request_helper.post(query_url, payload)
    assert ldap_server
    payload = {
        "description": "Test domain workgroup filter",
        "name": "Group filter name",
        "searchAllGroupsQuery": "ldap.search(baseDn, \"(&(objectClass=groupOfNames)(cn=workgroup-*))\");",
        "searchGroupQuery": "ldap.search(baseDn, \"(&(objectClass=groupOfNames)(cn=workgroup-\" + pattern + \"))\");",
        "searchPageSize": 100,
        "groupMemberAttribute": "member",
        "groupNameAttribute": "cn",
        "groupPrefixToRemove": "workgroup-",
        "memberFirstNameAttribute": "givenname",
        "memberLastNameAttribute": "sn",
        "memberMailAttribute": "mail"
        }
    query_url = '{baseUrl}/group_filters'.format_map({
            'baseUrl' : base_url})
    group_filter = request_helper.post(query_url, payload)
    assert group_filter
    """Create domain"""
    query_url = '{base_url}/domains'.format_map({
            'base_url': base_url,
            })
    payload = {
        "parent": {"uuid": "LinShareRootDomain"},
        "type": "TOPDOMAIN",
        "name": "TopDomainDriveProvider",
        "description": "Description of top domain 'test group provider'"
    }
    domain = request_helper.post(query_url, payload)
    assert domain
    query_url = '{base_url}/domains/{uuid}/group_providers'.format_map({
        'base_url': base_url,
        'uuid': domain['uuid']
    })
    payload = {
        "domain": {
            "uuid": domain['uuid'],
            "name": domain['name']
        },
        "ldapServer": {
            "uuid": ldap_server['uuid'],
            "name": ldap_server['name']
        },
        "groupFilter": {
            "uuid": group_filter['uuid'],
            "name": group_filter['name']
        },
        "baseDn": "ou=Groups,dc=linshare,dc=org",
        "type": "LDAP_PROVIDER"
    }
    group_provider = request_helper.post(query_url, payload)
    log.debug("group provider created: %s", group_provider)
    assert group_provider
    assert group_provider['baseDn'] == "ou=Groups,dc=linshare,dc=org"
    assert group_provider['type'] == "LDAP_PROVIDER"
    return group_provider


def test_find_all(request_helper, base_url):
        """Test admin find all created group providers"""
        entity = test_create(request_helper, base_url)
        query_url = '{baseUrl}/domains/{uuid}/group_providers'.format_map({
            'baseUrl': base_url,
            'uuid': entity['domain']['uuid']
            })
        data = request_helper.get(query_url)
        log = logging.getLogger('tests.funcs.test_find_all')
        log.debug("group providers: %s", data)
        assert data


def test_find(request_helper, base_url):
    """Test find existing group provider on API v5"""
    entity = test_create(request_helper, base_url)
    query_url = '{baseUrl}/domains/{uuid}/group_providers/{group_provider_uuid}'.format_map({
        'baseUrl': base_url,
        'uuid': entity['domain']['uuid'],
        'group_provider_uuid': entity['uuid']
    })
    data = request_helper.get(query_url)
    assert data


def test_delete(request_helper, base_url):
    """Test admin delete domain group provider."""
    log = logging.getLogger('tests.group.providers.test_delete')
    entity = test_create(request_helper, base_url)
    query_url = '{baseUrl}/domains/{uuid}/group_providers/{group_provider_uuid}'.format_map({
        'baseUrl': base_url,
        'uuid': entity['domain']['uuid'],
        'group_provider_uuid': entity['uuid']
    })
    data = request_helper.delete(query_url)
    log.debug("group provider deleted: %s", data)
    assert data


def test_delete_payload(request_helper, base_url):
    """Test admin delete domain group provider."""
    log = logging.getLogger('tests.group.providers.test_delete')
    entity = test_create(request_helper, base_url)
    query_url = '{baseUrl}/domains/{uuid}/group_providers'.format_map({
        'baseUrl': base_url,
        'uuid': entity['domain']['uuid'],
    })
    data = request_helper.delete(query_url, entity)
    log.debug("group provider deleted: %s", data)
    assert data


def test_update(request_helper, base_url):
    """Test admin update domain group provider."""
    log = logging.getLogger('tests.group.providers.test_update')
    entity = test_create(request_helper, base_url)
    query_url = '{baseUrl}/domains/{uuid}/group_providers'.format_map({
        'baseUrl': base_url,
        'uuid': entity['domain']['uuid']
    })
    payload = {
        "uuid" : entity['uuid'],
        "ldapServer": {
            "uuid": entity['ldapServer']['uuid'],
            "name": entity['ldapServer']['name']
            },
        "groupFilter": {
            "uuid": entity['groupFilter']['uuid'],
            "name": "Updated ldapServer name"
        },
        "baseDn": entity['baseDn'],
        "type": entity['type']
    }
    data = request_helper.put(query_url, entity)
    log.debug("group provider update: %s", data)
    assert data
    assert data['groupFilter']['name'] == entity['groupFilter']['name']
