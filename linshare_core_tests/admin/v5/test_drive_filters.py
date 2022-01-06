#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""Testing drive filters endpoints of adminv5 API."""


import urllib
import logging
import pytest
# import json


def test_config(display_admin_cfg):
    """Just display current config."""
    display_admin_cfg()


def test_find_all(request_helper, base_url):
    """Test find all drive model filters for root domain on API v5"""
    encoded_url = urllib.parse.urlencode({'model': "true"})
    query_url = '{baseUrl}/drive_filters?{encode}'.format_map({
        'baseUrl': base_url,
        'encode': encoded_url
    })
    data = request_helper.get(query_url)
    log = logging.getLogger('tests.funcs.test_find_all')
    log.debug("drive filters: %s", data)
    assert data
    assert len(data) == 1


def test_find(request_helper, base_url):
    """Test find existing driver filter (model)  for root domain on API v5"""
    # using default model uuid.
    query_url = '{baseUrl}/drive_filters/{uuid}'.format_map({
        'baseUrl': base_url,
        'uuid': 'c59078f1-2366-4360-baa0-6c089202e9a6'
    })
    data = request_helper.get(query_url)
    log = logging.getLogger('tests.funcs.test_find_all')
    log.debug("drive filters: %s", data)
    # print("data: ", json.dumps(data, sort_keys=True, indent=2))
    assert data
    # 16 fields
    assert len(data) == 16


def test_create(request_helper, base_url):
    """Test admin create domain drive filter."""
    # pylint: disable=line-too-long
    log = logging.getLogger('tests.domains.test_create')

    # python string but splitted in multiple lines.
    search_all_group_query = (
        "ldap.search(baseDn, "
        "\"(&(objectClass=groupOfNames)(cn=drive-*))\");"
    )
    search_group_query = (
        "ldap.search(baseDn, "
        "\"(&(objectClass=groupOfNames)(cn=drive-\" + pattern + \"))\");"
    )
    payload = {
        "description": "Test domain drive filter",
        "name": "Drive filter name",
        "searchAllGroupsQuery": search_all_group_query,
        "searchGroupQuery": search_group_query,
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
        'baseUrl': base_url
    })
    data = request_helper.post(query_url, payload)
    log.debug("drive filter created: %s", data)
    assert data
    assert data['name'] == payload['name']
    # assert data['creationDate']
    # 16 fields
    assert len(data) == 16
    return data


def test_delete(request_helper, base_url):
    """Test admin delete domain drive filter."""
    log = logging.getLogger('tests.domains.test_delete')

    # Since these tests are not pure function, we can reuse them here.
    entity = test_create(request_helper, base_url)
    query_url = '{baseUrl}/drive_filters/{uuid}'.format_map({
        'baseUrl': base_url,
        'uuid': entity['uuid']
    })
    data = request_helper.delete(query_url)
    log.debug("drive filter deleted: %s", data)
    assert data
    # 16 fields
    assert len(data) == 16


def test_delete_payload(request_helper, base_url):
    """Test admin delete domain drive filter."""
    log = logging.getLogger('tests.domains.test_delete')

    # Since these tests are not pure function, we can reuse them here.
    entity = test_create(request_helper, base_url)
    query_url = '{baseUrl}/drive_filters'.format_map({
        'baseUrl': base_url
    })
    data = request_helper.delete(query_url, entity)
    log.debug("drive filter deleted: %s", data)
    assert data
    # 16 fields
    assert len(data) == 16


def test_update(request_helper, base_url):
    """Test admin update domain drive filter."""
    log = logging.getLogger('tests.domains.test_update')

    # Since these tests are not pure function, we can reuse them here.
    entity = test_create(request_helper, base_url)
    query_url = '{baseUrl}/drive_filters'.format_map({
        'baseUrl': base_url
    })
    entity['name'] = "NEw drive filter name"
    # entity['description'] = ""
    entity['memberMailAttribute'] = "foo"
    data = request_helper.put(query_url, entity)
    log.debug("drive filter update: %s", data)
    assert data
    # 16 fields
    assert len(data) == 16
    assert data['name'] == entity['name']


@pytest.mark.xfail(reason="Bad server implementation")
def test_update_empty_description(request_helper, base_url):
    """Test admin update domain drive filter."""
    log = logging.getLogger('tests.domains.test_update')

    # Since these tests are not pure function, we can reuse them here.
    entity = test_create(request_helper, base_url)
    query_url = '{baseUrl}/drive_filters'.format_map({
        'baseUrl': base_url
    })
    entity['name'] = "NEw drive filter name"
    entity['description'] = ""
    data = request_helper.put(query_url, entity)
    log.debug("drive filter update: %s", data)
    assert data
    # 16 fields
    assert len(data) == 16
    assert data['name'] == entity['name']
    assert data['description'] == ""
