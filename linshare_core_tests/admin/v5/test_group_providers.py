#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""Testing group providers endpoints of adminv5 API."""


import logging


def create_remote_server(request_helper, base_url):
    """Helper to create remote server."""
    payload = {
        "name": "new connection",
        "bindDn": "cn=linshare,dc=linshare,dc=org",
        "url": "ldap://172.17.0.1:1389",
        "serverType": "LDAP",
        "bindPassword": "linshare"
    }
    query_url = '{baseUrl}/remote_servers'.format_map({'baseUrl': base_url})
    remote_server = request_helper.post(query_url, payload)
    assert remote_server
    assert remote_server['url'] == "ldap://172.17.0.1:1389"
    assert remote_server['bindDn'] == "cn=linshare,dc=linshare,dc=org"
    return remote_server


def create_group_filter(request_helper, base_url):
    """Helper to create group filter."""
    search_gq = (
            "ldap.search(baseDn, "
            "\"(&(objectClass=groupOfNames)(cn=drive-*))\");"
    )
    search_q = (
            "ldap.search(baseDn, "
            "\"(&(objectClass=groupOfNames)(cn=drive-\" + pattern + \"))\");"
    )
    payload = {
        "description": "Test domain workgroup filter",
        "name": "Group filter name",
        "searchAllGroupsQuery": search_gq,
        "searchGroupQuery": search_q,
        "searchPageSize": 100,
        "groupMemberAttribute": "member",
        "groupNameAttribute": "cn",
        "groupPrefixToRemove": "workgroup-",
        "memberFirstNameAttribute": "givenname",
        "memberLastNameAttribute": "sn",
        "memberMailAttribute": "mail"
    }
    query_url = '{baseUrl}/group_filters'.format_map({'baseUrl': base_url})
    group_filter = request_helper.post(query_url, payload)
    assert group_filter['type'] == "LDAP"
    assert group_filter['groupPrefixToRemove'] == "workgroup-"
    return group_filter


def create_domain(request_helper, base_url):
    """Helper to create domain."""
    query_url = '{base_url}/domains'.format_map({
        'base_url': base_url,
    })
    payload = {
        "parent": {"uuid": "LinShareRootDomain"},
        "type": "TOPDOMAIN",
        "name": "TopDomainGroupProvider",
        "description": "Description of top domain 'test group provider'"
    }
    domain = request_helper.post(query_url, payload)
    assert domain['type'] == "TOPDOMAIN"
    assert domain['name'] == "TopDomainGroupProvider"
    return domain


def create_group_provider(request_helper, base_url):
    """helper to create group provider."""
    ldap_server = create_remote_server(request_helper, base_url)
    group_filter = create_group_filter(request_helper, base_url)
    domain = create_domain(request_helper, base_url)
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
    assert group_provider
    assert group_provider['baseDn'] == "ou=Groups,dc=linshare,dc=org"
    assert group_provider['type'] == "LDAP_PROVIDER"
    return group_provider


def test_create(request_helper, base_url):
    """Test admin create group provider."""
    log = logging.getLogger('tests.group.providers.test_create')
    group_provider = create_group_provider(request_helper, base_url)
    log.debug("group provider created: %s", group_provider)
    assert group_provider


def test_find_all(request_helper, base_url):
    """Test admin find all created group providers"""
    entity = create_group_provider(request_helper, base_url)
    query_url = '{baseUrl}/domains/{uuid}/group_providers'.format_map({
        'baseUrl': base_url,
        'uuid': entity['domain']['uuid']
    })
    group_providers = request_helper.get(query_url)
    log = logging.getLogger('tests.group.providers.test_find_all')
    log.debug("group providers: %s", group_providers)
    if len(group_providers) != 0:
        assert group_providers
        for group_provider in group_providers:
            assert group_provider['baseDn'] == "ou=Groups,dc=linshare,dc=org"
            assert group_provider['type'] == "LDAP_PROVIDER"


def test_find(request_helper, base_url):
    """Test find existing group provider on API v5"""
    entity = create_group_provider(request_helper, base_url)
    query_url = '{baseUrl}/domains/{uuid}/group_providers/{provider_uuid}'
    query_url = query_url.format_map({
        'baseUrl': base_url,
        'uuid': entity['domain']['uuid'],
        'provider_uuid': entity['uuid']
    })
    data = request_helper.get(query_url)
    assert data
    assert data['baseDn'] == entity['baseDn']
    assert data['type'] == entity['type']


def test_delete(request_helper, base_url):
    """Test admin delete domain group provider."""
    log = logging.getLogger('tests.group.providers.test_delete')
    entity = create_group_provider(request_helper, base_url)
    query_url = '{baseUrl}/domains/{uuid}/group_providers/{provider_uuid}'
    query_url = query_url.format_map({
        'baseUrl': base_url,
        'uuid': entity['domain']['uuid'],
        'provider_uuid': entity['uuid']
    })
    data = request_helper.delete(query_url)
    log.debug("group provider deleted: %s", data)
    assert data
    query_url = '{baseUrl}/domains/{uuid}/group_providers/{provider_uuid}'
    query_url = query_url.format_map({
        'baseUrl': base_url,
        'uuid': entity['domain']['uuid'],
        'provider_uuid': entity['uuid']
    })
    request_helper.get(query_url, expected_status=404)


def test_delete_payload(request_helper, base_url):
    """Test admin delete domain group provider."""
    log = logging.getLogger('tests.group.providers.test_delete')
    entity = create_group_provider(request_helper, base_url)
    query_url = '{baseUrl}/domains/{uuid}/group_providers'.format_map({
        'baseUrl': base_url,
        'uuid': entity['domain']['uuid'],
    })
    data = request_helper.delete(query_url, entity)
    log.debug("group provider deleted: %s", data)
    assert data
    query_url = '{baseUrl}/domains/{uuid}/group_providers/{provider_uuid}'
    query_url = query_url.format_map({
        'baseUrl': base_url,
        'uuid': entity['domain']['uuid'],
        'provider_uuid': entity['uuid']
    })
    request_helper.get(query_url, expected_status=404)


def test_update(request_helper, base_url):
    """Test admin update domain group provider."""
    log = logging.getLogger('tests.group.providers.test_update')
    entity = create_group_provider(request_helper, base_url)
    query_url = '{baseUrl}/domains/{uuid}/group_providers'.format_map({
        'baseUrl': base_url,
        'uuid': entity['domain']['uuid']
    })
    data = request_helper.put(query_url, entity)
    log.debug("group provider update: %s", data)
    assert data
    assert data['groupFilter']['name'] == entity['groupFilter']['name']
