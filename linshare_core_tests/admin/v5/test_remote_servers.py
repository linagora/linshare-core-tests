#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""Testing RemoteServers endpoints of adminv5 API."""


def test_find_all_remote_servers(request_helper, base_url):
    """Test admin find all remote servers."""
    query_url = '{baseUrl}/remote_servers'.format_map({
        'baseUrl': base_url
    })
    servers = request_helper.get(query_url)
    assert servers
    assert len(servers) >= 1


def test_create_remote_server(request_helper, base_url, admin_cfg):
    """Test admin create remote server."""
    local_ldap_user_dn = admin_cfg['DEFAULT']['local_ldap_user_dn']
    local_ldap_url = admin_cfg['DEFAULT']['local_ldap_url']
    local_ldap_password = admin_cfg['DEFAULT']['local_ldap_password']
    payload = {
        "name": "new connection",
        "serverType": "LDAP",
        "bindDn": local_ldap_user_dn,
        "url": local_ldap_url,
        "bindPassword": local_ldap_password,
        "description": "description"
    }
    query_url = '{baseUrl}/remote_servers'.format_map({
        'baseUrl': base_url
    })
    created_server = request_helper.post(query_url, payload)

    query_url = '{baseUrl}/remote_servers/{uuid}'.format_map({
        'baseUrl': base_url,
        'uuid': created_server['uuid']
    })
    server = request_helper.get(query_url)

    assert server
    assert server['uuid']
    assert server['name'] == "new connection"
    assert server['url'] == local_ldap_url
    assert server['bindDn'] == local_ldap_user_dn
    assert server['bindPassword'] == local_ldap_password
    assert server['serverType'] == "LDAP"
    assert server['creationDate']
    assert server['modificationDate']


def test_create_remote_server_without_binddn_and_pwd(
        request_helper, base_url, admin_cfg):
    """Test admin create remote server."""
    payload = {
        "name": "new connection",
        "serverType": "LDAP",
        "url": admin_cfg['DEFAULT']['local_ldap_url']
    }
    query_url = '{baseUrl}/remote_servers'.format_map({
        'baseUrl': base_url
    })
    created_server = request_helper.post(query_url, payload)

    query_url = '{baseUrl}/remote_servers/{uuid}'.format_map({
        'baseUrl': base_url,
        'uuid': created_server['uuid']
    })
    server = request_helper.get(query_url)

    assert server
    assert server['uuid']
    assert server['name'] == "new connection"
    assert server['url'] == admin_cfg['DEFAULT']['local_ldap_url']
    assert server['serverType'] == "LDAP"
    assert server['creationDate']
    assert server['modificationDate']


def test_find_remote_servers(request_helper, base_url, remote_server):
    """Test admin find remote server."""
    query_url = '{baseUrl}/remote_servers/{uuid}'.format_map({
        'baseUrl': base_url,
        'uuid': remote_server['uuid']
    })
    server = request_helper.get(query_url)
    assert server


def test_delete_remote_server_with_payload(
        request_helper, base_url, admin_cfg):
    """Test admin delete remote server."""
    # Given
    payload = {
        "name": "new connection",
        "serverType": "LDAP",
        "bindDn": admin_cfg['DEFAULT']['local_ldap_user_dn'],
        "url": admin_cfg['DEFAULT']['local_ldap_url'],
        "bindPassword": admin_cfg['DEFAULT']['local_ldap_password']
    }
    query_url = '{baseUrl}/remote_servers'.format_map({
        'baseUrl': base_url
    })
    server = request_helper.post(query_url, payload)

    # When
    query_url = '{baseUrl}/remote_servers'.format_map({
        'baseUrl': base_url
    })
    payload = {
        "name": "new connection",
        'uuid': server['uuid'],
        "serverType": "LDAP",
        "bindDn": admin_cfg['DEFAULT']['local_ldap_user_dn'],
        "url": admin_cfg['DEFAULT']['local_ldap_url'],
        "bindPassword": admin_cfg['DEFAULT']['local_ldap_password']
    }
    request_helper.delete(query_url, payload)

    # Then
    query_url = '{baseUrl}/remote_servers/{uuid}'.format_map({
        'baseUrl': base_url,
        'uuid': server['uuid']
    })
    request_helper.get(query_url, expected_status=404)


def test_delete_remote_server_no_payload(
        request_helper, base_url, admin_cfg):
    """Test admin delete remote server no payload."""
    # Given
    payload = {
        "name": "new connection",
        "serverType": "LDAP",
        "bindDn": admin_cfg['DEFAULT']['local_ldap_user_dn'],
        "url": admin_cfg['DEFAULT']['local_ldap_url'],
        "bindPassword": admin_cfg['DEFAULT']['local_ldap_password']
    }
    query_url = '{baseUrl}/remote_servers'.format_map({
        'baseUrl': base_url
    })
    server = request_helper.post(query_url, payload)

    # When
    query_url = '{baseUrl}/remote_servers/{uuid}'.format_map({
        'baseUrl': base_url,
        'uuid': server['uuid']
    })
    request_helper.delete(query_url)

    # Then
    query_url = '{baseUrl}/remote_servers/{uuid}'.format_map({
        'baseUrl': base_url,
        'uuid': server['uuid']
    })
    request_helper.get(query_url, expected_status=404)


def test_update_remote_servers(request_helper, base_url, remote_server):
    """Test admin update remote server."""
    query_url = '{baseUrl}/remote_servers/{uuid}'.format_map({
        'baseUrl': base_url,
        'uuid': remote_server['uuid']
    })
    payload = {
        "name": "updated connection name",
        "serverType": "LDAP",
        "bindDn": remote_server['bindDn'],
        "url": remote_server['url'],
        "bindPassword": 'test'
    }
    request_helper.put(query_url, payload)

    query_url = '{baseUrl}/remote_servers/{uuid}'.format_map({
        'baseUrl': base_url,
        'uuid': remote_server['uuid']
    })
    server = request_helper.get(query_url)

    assert server
    assert server['name'] == payload['name']
    assert server['bindPassword'] == payload['bindPassword']
    assert remote_server['modificationDate'] != server['modificationDate']


def test_update_remote_servers_without_binddn_and_pwd(
        request_helper, base_url, remote_server):
    """Test admin update remote server."""
    query_url = '{baseUrl}/remote_servers/{uuid}'.format_map({
        'baseUrl': base_url,
        'uuid': remote_server['uuid']
    })
    payload = {
        "name": "updated connection name",
        "serverType": "LDAP",
        "url": remote_server['url'],
    }
    request_helper.put(query_url, payload)

    query_url = '{baseUrl}/remote_servers/{uuid}'.format_map({
        'baseUrl': base_url,
        'uuid': remote_server['uuid']
    })
    server = request_helper.get(query_url)

    assert server
    assert server['name'] == payload['name']
