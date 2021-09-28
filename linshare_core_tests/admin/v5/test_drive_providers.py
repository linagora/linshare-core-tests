#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""Testing drive providers endpoints of adminv5 API."""


import urllib
import logging
import pytest
# import json


def create_remote_server(request_helper, base_url):
    """Helper to create remote server."""
    payload = {
            "name": "new connection",
            "bindDn":  "cn=linshare,dc=linshare,dc=org",
            "url": "ldap://172.17.0.1:1389",
            "bindPassword":"linshare"
        }
    query_url = '{baseUrl}/remote_servers'.format_map({
            'baseUrl' : base_url})
    remote_server = request_helper.post(query_url, payload)
    assert remote_server
    assert remote_server['url'] == "ldap://172.17.0.1:1389"
    assert remote_server['bindDn'] == "cn=linshare,dc=linshare,dc=org"
    return remote_server


def create_drive_filter(request_helper, base_url):
    """Helper to create drive filter."""
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
    assert drive_filter['type'] == "LDAP"
    assert drive_filter['groupPrefixToRemove'] == "drive-"
    return drive_filter


def create_domain(request_helper, base_url):
    """Helper to create domain."""
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
    assert domain['type'] == "TOPDOMAIN"
    assert domain['name'] == "TopDomainDriveProvider"
    return domain


def create_drive_provider(request_helper, base_url):
    """helper to create drive provider."""
    ldap_server = create_remote_server(request_helper, base_url)
    drive_filter = create_drive_filter(request_helper, base_url)
    domain = create_domain(request_helper, base_url)
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
    assert drive_provider
    return drive_provider


def test_create(request_helper, base_url):
    """Test admin create drive provider."""
    log = logging.getLogger('tests.drive.providers.test_create')
    ldap_server = create_remote_server(request_helper, base_url)
    drive_filter = create_drive_filter(request_helper, base_url)
    domain = create_domain(request_helper, base_url)
    drive_provider = create_drive_provider(request_helper, base_url)
    log.debug("drive provider created: %s", drive_provider)
    assert drive_provider
    assert drive_provider['baseDn'] == "ou=Groups,dc=linshare,dc=org"
    assert drive_provider['type'] == "LDAP_PROVIDER"


def test_find_all(request_helper, base_url):
    """Test admin find all created drive providers"""
    entity = create_drive_provider(request_helper, base_url)
    query_url = '{baseUrl}/domains/{uuid}/drive_providers'.format_map({
        'baseUrl': base_url,
        'uuid': entity['domain']['uuid']
        })
    drive_providers = request_helper.get(query_url)
    log = logging.getLogger('tests.drive.providers.test_find_all')
    log.debug("drive providers: %s", drive_providers)
    if(len(drive_providers) != 0):
        assert drive_providers
        for drive_provider in drive_providers:
            assert drive_provider['baseDn'] == "ou=Groups,dc=linshare,dc=org"
            assert drive_provider['type'] == "LDAP_PROVIDER"


def test_find(request_helper, base_url):
    """Test find existing driver provider on API v5"""
    entity = create_drive_provider(request_helper, base_url)
    query_url = '{baseUrl}/domains/{uuid}/drive_providers/{drive_provider_uuid}'.format_map({
        'baseUrl': base_url,
        'uuid': entity['domain']['uuid'],
        'drive_provider_uuid': entity['uuid']
    })
    data = request_helper.get(query_url)
    assert data
    assert data['baseDn'] == entity['baseDn']
    assert data['type'] == entity['type']


def test_delete(request_helper, base_url):
    """Test admin delete domain drive provider."""
    log = logging.getLogger('tests.drive.providers.test_delete')
    entity = create_drive_provider(request_helper, base_url)
    query_url = '{baseUrl}/domains/{uuid}/drive_providers/{drive_provider_uuid}'.format_map({
        'baseUrl': base_url,
        'uuid': entity['domain']['uuid'],
        'drive_provider_uuid': entity['uuid']
    })
    data = request_helper.delete(query_url)
    assert data
    log.debug("drive provider deleted: %s", data)
    query_url = '{baseUrl}/domains/{uuid}/drive_providers/{drive_provider_uuid}'.format_map({
        'baseUrl': base_url,
        'uuid': entity['domain']['uuid'],
        'drive_provider_uuid': entity['uuid']
    })
    request_helper.get(query_url, expected_status=404)


def test_delete_payload(request_helper, base_url):
    """Test admin delete domain drive provider."""
    log = logging.getLogger('tests.drive.providers.test_delete')
    entity = create_drive_provider(request_helper, base_url)
    query_url = '{baseUrl}/domains/{uuid}/drive_providers'.format_map({
        'baseUrl': base_url,
        'uuid': entity['domain']['uuid'],
    })
    data = request_helper.delete(query_url, entity)
    log.debug("drive provider deleted: %s", data)
    assert data
    query_url = '{baseUrl}/domains/{uuid}/drive_providers/{drive_provider_uuid}'.format_map({
        'baseUrl': base_url,
        'uuid': entity['domain']['uuid'],
        'drive_provider_uuid': entity['uuid']
    })
    request_helper.get(query_url, expected_status=404)


def test_update(request_helper, base_url):
    """Test admin update domain drive provider."""
    log = logging.getLogger('tests.drive.providers.test_update')
    entity = create_drive_provider(request_helper, base_url)
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
