#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""Testing GroupFilters endpoints of adminv5 API."""


import urllib


def test_find_all_default_models_domain_group_filters(
        request_helper, base_url):
    """Test admin find all default domain group filters models"""
    encoded_url = urllib.parse.urlencode({'model': "true"})
    query_url = '{baseUrl}/group_filters?{encode}'.format_map({
        'baseUrl': base_url,
        'encode': encoded_url
    })
    group_filters = request_helper.get(query_url)
    assert len(group_filters) == 1


def test_find_all_created_domain_created_group_filters(
        request_helper, base_url):
    """Test admin find all domain group filters"""
    query_url = '{baseUrl}/group_filters'.format_map({
        'baseUrl': base_url
    })
    request_helper.get(query_url)


def create_domain_group_filter(request_helper, base_url):
    """Create domain group filter."""
    payload = {
        "description": "Test domain workgroup filter",
        "name": "Group filter name",
        "searchAllGroupsQuery":
            "ldap.search(baseDn, "
            "\"(&(objectClass=groupOfNames)(cn=workgroup-*))\");",
        "searchGroupQuery":
            "ldap.search(baseDn, "
            "\"(&(objectClass=groupOfNames)"
            "(cn=workgroup-\" + pattern + \"))\");",
        "searchPageSize": 100,
        "groupMemberAttribute": "member",
        "groupNameAttribute": "cn",
        "groupPrefixToRemove": "workgroup-",
        "memberFirstNameAttribute": "givenname",
        "memberLastNameAttribute": "sn",
        "memberMailAttribute": "mail"
    }
    query_url = '{baseUrl}/group_filters'.format_map({
        'baseUrl': base_url
    })
    return request_helper.post(query_url, payload)


def test_create_domain_group_filter(request_helper, base_url):
    """Test admin create domain group filter."""
    group_filter = create_domain_group_filter(request_helper, base_url)
    assert group_filter['name'] == "Group filter name"


def test_find_domain_group_filter(request_helper, base_url):
    """Test admin find domain group filter."""
    group_filter = create_domain_group_filter(request_helper, base_url)
    query_url = '{baseUrl}/group_filters/{group_filter_uuid}'.format_map({
        'baseUrl': base_url,
        'group_filter_uuid': group_filter['uuid']
    })
    request_helper.get(query_url)


def test_update_domain_group_filter(request_helper, base_url):
    """Test admin update domain group filter."""
    group_filter = create_domain_group_filter(request_helper, base_url)
    query_url = '{baseUrl}/group_filters/{group_filter_uuid}'.format_map({
        'baseUrl': base_url,
        'group_filter_uuid': group_filter['uuid']
    })
    payload = {
        "description": group_filter["description"],
        "name": "Updated group filter name",
        "searchAllGroupsQuery": group_filter["searchAllGroupsQuery"],
        "searchGroupQuery": group_filter["searchGroupQuery"],
        "searchPageSize": group_filter["searchPageSize"],
        "groupMemberAttribute": group_filter["groupMemberAttribute"],
        "groupNameAttribute": group_filter["groupNameAttribute"],
        "groupPrefixToRemove": group_filter["groupPrefixToRemove"],
        "memberFirstNameAttribute": group_filter["memberFirstNameAttribute"],
        "memberLastNameAttribute": group_filter["memberLastNameAttribute"],
        "memberMailAttribute": group_filter["memberMailAttribute"]
    }
    group_filter = request_helper.put(query_url, payload)
    assert group_filter['name'] == payload['name']


def test_delete_domain_group_filter_with_payload(request_helper, base_url):
    """Test admin delete domain group filter."""
    group_filter = create_domain_group_filter(request_helper, base_url)
    query_url = '{baseUrl}/group_filters/{group_filter_uuid}'.format_map({
        'baseUrl': base_url,
        'group_filter_uuid': group_filter['uuid']
    })
    payload = {
        "name": group_filter['name'],
        "description": group_filter['description'],
        "type": group_filter['type']
    }
    request_helper.delete(query_url, payload)


def test_delete_domain_group_filter_no_payload(request_helper, base_url):
    """Test admin delete domain group filter."""
    group_filter = create_domain_group_filter(request_helper, base_url)
    query_url = '{baseUrl}/group_filters/{group_filter_uuid}'.format_map({
        'baseUrl': base_url,
        'group_filter_uuid': group_filter['uuid']
    })
    request_helper.delete(query_url)
