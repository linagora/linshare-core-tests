#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""Testing drive providers endpoints of adminv5 API."""


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
    """Test admin create drive provider."""
    log = logging.getLogger('tests.drive.providers.test_create')
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
        "description": "Test domain drive filter",
        "name": "drive filter name",
        "searchAllGroupsQuery": "ldap.search(baseDn, \"(&(objectClass=groupOfNames)(cn=drive-*))\");",
        "searchGroupQuery": "ldap.search(baseDn, \"(&(objectClass=groupOfNames)(cn=drive-\" + pattern + \"))\");",
        "searchPageSize": 100,
        "groupMemberAttribute": "member",
        "groupNameAttribute": "cn",
        "groupPrefixToRemove": "drive-",
        "memberFirstNameAttribute": "givenname",
        "memberLastNameAttribute": "sn",
        "memberMailAttribute": "mail",
        "type": "LDAP"
    }
    query_url = '{baseUrl}/drive_filters'.format_map({
            'baseUrl' : base_url})
    drive_filter = request_helper.post(query_url, payload)
    assert drive_filter
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
    query_url = '{base_url}/domains/{uuid}/drive_providers'.format_map({
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
        "driveFilter": {
            "uuid": drive_filter['uuid'],
            "name": drive_filter['name']
        },
        "baseDn": "ou=Groups,dc=linshare,dc=org",
        "type": "LDAP_PROVIDER"
    }
    drive_provider = request_helper.post(query_url, payload)
    log.debug("drive provider created: %s", drive_provider)
    assert drive_provider
    assert drive_provider['baseDn'] == "ou=Groups,dc=linshare,dc=org"
    assert drive_provider['type'] == "LDAP_PROVIDER"
    return drive_provider


def test_find_all(request_helper, base_url):
        """Test admin find all created drive providers"""
        entity = test_create(request_helper, base_url)
        query_url = '{baseUrl}/domains/{uuid}/drive_providers'.format_map({
            'baseUrl': base_url,
            'uuid': entity['domain']['uuid']
            })
        data = request_helper.get(query_url)
        log = logging.getLogger('tests.funcs.test_find_all')
        log.debug("drive providers: %s", data)
        assert data


def test_find(request_helper, base_url):
    """Test find existing driver provider on API v5"""
    entity = test_create(request_helper, base_url)
    query_url = '{baseUrl}/domains/{uuid}/drive_providers/{drive_provider_uuid}'.format_map({
        'baseUrl': base_url,
        'uuid': entity['domain']['uuid'],
        'drive_provider_uuid': entity['uuid']
    })
    data = request_helper.get(query_url)
    assert data


def test_delete(request_helper, base_url):
    """Test admin delete domain drive provider."""
    log = logging.getLogger('tests.drive.providers.test_delete')
    entity = test_create(request_helper, base_url)
    query_url = '{baseUrl}/domains/{uuid}/drive_providers/{drive_provider_uuid}'.format_map({
        'baseUrl': base_url,
        'uuid': entity['domain']['uuid'],
        'drive_provider_uuid': entity['uuid']
    })
    data = request_helper.delete(query_url)
    log.debug("drive provider deleted: %s", data)
    assert data


def test_delete_payload(request_helper, base_url):
    """Test admin delete domain drive provider."""
    log = logging.getLogger('tests.drive.providers.test_delete')
    entity = test_create(request_helper, base_url)
    query_url = '{baseUrl}/domains/{uuid}/drive_providers'.format_map({
        'baseUrl': base_url,
        'uuid': entity['domain']['uuid'],
    })
    data = request_helper.delete(query_url, entity)
    log.debug("drive provider deleted: %s", data)
    assert data


def test_update(request_helper, base_url):
    """Test admin update domain drive provider."""
    log = logging.getLogger('tests.drive.providers.test_update')
    entity = test_create(request_helper, base_url)
    query_url = '{baseUrl}/domains/{uuid}/drive_providers'.format_map({
        'baseUrl': base_url,
        'uuid': entity['domain']['uuid']
    })
    payload = {
        "uuid" : entity['uuid'],
        "ldapServer": {
            "uuid": entity['ldapServer']['uuid'],
            "name": entity['ldapServer']['name']
            },
        "driveFilter": {
            "uuid": entity['driveFilter']['uuid'],
            "name": "Updated ldapServer name"
        },
        "baseDn": entity['baseDn'],
        "type": entity['type']
    }
    data = request_helper.put(query_url, entity)
    log.debug("drive provider update: %s", data)
    assert data
    assert data['driveFilter']['name'] == entity['driveFilter']['name']
