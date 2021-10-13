#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""Testing RemoteServers endpoints of adminv5 API."""


def create_remote_server(request_helper, base_url, admin_cfg):
    """Create a remote server."""
    payload = {
        "name": "new remote server",
        "bindDn": admin_cfg['DEFAULT']['local_ldap_user_dn'],
        "url": admin_cfg['DEFAULT']['local_ldap_url'],
        "bindPassword": admin_cfg['DEFAULT']['local_ldap_password']
    }
    query_url = '{baseUrl}/remote_servers'.format_map({
        'baseUrl': base_url
    })
    server = request_helper.post(query_url, payload)
    assert server
    return server


def test_find_all_remote_servers(request_helper, base_url):
    """Test admin find all remote servers."""
    query_url = '{baseUrl}/remote_servers'.format_map({
        'baseUrl': base_url
    })
    request_helper.get(query_url)


def test_create_remote_server(request_helper, base_url, admin_cfg):
    """Test admin create remote server."""
    payload = {
        "name": "new connection",
        "bindDn": admin_cfg['DEFAULT']['local_ldap_user_dn'],
        "url": admin_cfg['DEFAULT']['local_ldap_url'],
        "bindPassword": admin_cfg['DEFAULT']['local_ldap_password']
    }
    query_url = '{baseUrl}/remote_servers'.format_map({
        'baseUrl': base_url
    })
    server = request_helper.post(query_url, payload)
    assert server['name'] == payload['name']


def test_create_remote_server_without_binddn_and_pwd(
        request_helper, base_url, admin_cfg):
    """Test admin create remote server."""
    payload = {
        "name": "new connection",
        "url": admin_cfg['DEFAULT']['local_ldap_url']
    }
    query_url = '{baseUrl}/remote_servers'.format_map({
        'baseUrl': base_url
    })
    server = request_helper.post(query_url, payload)
    assert server['name'] == payload['name']


def test_find_remote_servers(request_helper, base_url, admin_cfg):
    """Test admin find remote server."""
    remote_server = create_remote_server(request_helper, base_url, admin_cfg)
    query_url = '{baseUrl}/remote_servers/{uuid}'.format_map({
        'baseUrl': base_url,
        'uuid': remote_server['uuid']
    })
    request_helper.get(query_url)


def test_delete_remote_server_with_payload(
        request_helper, base_url, admin_cfg):
    """Test admin delete remote server."""
    remote_server = create_remote_server(request_helper, base_url, admin_cfg)
    query_url = '{baseUrl}/remote_servers/{uuid}'.format_map({
        'baseUrl': base_url,
        'uuid': remote_server['uuid']
    })
    payload = {
        "name": "new connection",
        "bindDn": remote_server['bindDn'],
        "url": remote_server['url'],
    }
    request_helper.delete(query_url, payload)


def test_delete_remote_server_no_payload(request_helper, base_url, admin_cfg):
    """Test admin delete remote server no payload."""
    remote_server = create_remote_server(request_helper, base_url, admin_cfg)
    query_url = '{baseUrl}/remote_servers/{uuid}'.format_map({
        'baseUrl': base_url,
        'uuid': remote_server['uuid']
    })
    request_helper.delete(query_url)


def test_update_remote_servers(request_helper, base_url, admin_cfg):
    """Test admin update remote server."""
    remote_server = create_remote_server(request_helper, base_url, admin_cfg)
    query_url = '{baseUrl}/remote_servers/{uuid}'.format_map({
        'baseUrl': base_url,
        'uuid': remote_server['uuid']
    })
    payload = {
        "name": "updated connection name",
        "bindDn": remote_server['bindDn'],
        "url": remote_server['url'],
        "bindPassword": 'test'
    }
    server = request_helper.put(query_url, payload)
    assert server['name'] == payload['name']
    assert server['bindPassword'] == payload['bindPassword']


def test_update_remote_servers_without_binddn_and_pwd(
        request_helper, base_url, admin_cfg):
    """Test admin update remote server."""
    remote_server = create_remote_server(request_helper, base_url, admin_cfg)
    query_url = '{baseUrl}/remote_servers/{uuid}'.format_map({
        'baseUrl': base_url,
        'uuid': remote_server['uuid']
    })
    payload = {
        "name": "updated connection name",
        "url": remote_server['url'],
    }
    server = request_helper.put(query_url, payload)
    assert server['name'] == payload['name']
    assert not hasattr(server, "bindPassword")
