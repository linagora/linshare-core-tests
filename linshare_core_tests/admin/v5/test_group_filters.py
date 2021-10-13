#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""Testing GroupFilters endpoints of adminv5 API."""


import urllib
import pytest


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
        request_helper, base_url, new_group_filter):
    """Test admin find all domain group filters"""
    query_url = '{baseUrl}/group_filters'.format_map({
        'baseUrl': base_url
    })
    group_filters = request_helper.get(query_url)
    assert len(group_filters) >= 1
    found = False
    for iterate in group_filters:
        if iterate['name'] == new_group_filter['name']:
            found = True
    if not found:
        pytest.fail("group_filter not found")


@pytest.mark.xfail(
    reason="memberFirstNameAttribute & memberLastNameAttribute "
           "are switch together in our code")
def test_create_domain_group_filter(request_helper, base_url):
    """Test admin create domain group filter."""
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
    query_url = '{baseUrl}/group_filters'.format_map({
        'baseUrl': base_url
    })
    group_filter = request_helper.post(query_url, payload)

    query_url = '{baseUrl}/group_filters/{groupFilterUuid}'.format_map({
        'baseUrl': base_url,
        'groupFilterUuid': group_filter['uuid']
    })
    group_filter = request_helper.get(query_url)
    assert group_filter
    assert group_filter['description'] == 'Test domain workgroup filter'
    assert group_filter['name'] == "Group filter name"
    assert group_filter['searchAllGroupsQuery'] == search_gq
    assert group_filter['searchGroupQuery'] == search_q
    assert group_filter['searchPageSize'] == 100
    assert group_filter['groupMemberAttribute'] == 'member'
    assert group_filter['groupNameAttribute'] == 'cn'
    assert group_filter['groupPrefixToRemove'] == 'workgroup-'
    assert group_filter['memberFirstNameAttribute'] == 'givenname'
    assert group_filter['memberLastNameAttribute'] == 'sn'
    assert group_filter['memberMailAttribute'] == 'mail'


def test_find_domain_group_filter(request_helper, base_url, new_group_filter):
    """Test admin find domain group filter."""
    query_url = '{baseUrl}/group_filters/{groupFilterUuid}'.format_map({
        'baseUrl': base_url,
        'groupFilterUuid': new_group_filter['uuid']
    })
    group_filter = request_helper.get(query_url)
    assert group_filter
    assert group_filter['description'] == new_group_filter['description']
    assert group_filter['name'] == new_group_filter['name']
    # pylint: disable=line-too-long
    assert group_filter['searchAllGroupsQuery'] == new_group_filter['searchAllGroupsQuery']  # noqa: E501 # Line length & assert statement
    assert group_filter['searchGroupQuery'] == new_group_filter['searchGroupQuery']  # noqa: E501 # Line length & assert statement
    assert group_filter['searchPageSize'] == new_group_filter['searchPageSize']  # noqa: E501 # Line length & assert statement
    assert group_filter['groupMemberAttribute'] == new_group_filter['groupMemberAttribute']  # noqa: E501 # Line length & assert statement
    assert group_filter['groupNameAttribute'] == new_group_filter['groupNameAttribute']  # noqa: E501 # Line length & assert statement
    assert group_filter['groupPrefixToRemove'] == new_group_filter['groupPrefixToRemove']  # noqa: E501 # Line length & assert statement
    assert group_filter['memberFirstNameAttribute'] == new_group_filter['memberFirstNameAttribute']  # noqa: E501 # Line length & assert statement
    assert group_filter['memberLastNameAttribute'] == new_group_filter['memberLastNameAttribute']  # noqa: E501 # Line length & assert statement
    assert group_filter['memberMailAttribute'] == new_group_filter['memberMailAttribute']  # noqa: E501 # Line length & assert statement


def test_update_domain_group_filter(
        request_helper, base_url, new_group_filter):
    """Test admin update domain group filter."""
    query_url = '{baseUrl}/group_filters/{groupFilterUuid}'.format_map({
        'baseUrl': base_url,
        'groupFilterUuid': new_group_filter['uuid']
    })
    payload = {
        "description": new_group_filter["description"],
        "name": "Updated group filter name",
        "searchAllGroupsQuery": new_group_filter["searchAllGroupsQuery"],
        "searchGroupQuery": new_group_filter["searchGroupQuery"],
        "searchPageSize": new_group_filter["searchPageSize"],
        "groupMemberAttribute": new_group_filter["groupMemberAttribute"],
        "groupNameAttribute": new_group_filter["groupNameAttribute"],
        "groupPrefixToRemove": new_group_filter["groupPrefixToRemove"],
        "memberFirstNameAttribute":
            new_group_filter["memberFirstNameAttribute"],
        "memberLastNameAttribute": new_group_filter["memberLastNameAttribute"],
        "memberMailAttribute": new_group_filter["memberMailAttribute"]
    }
    request_helper.put(query_url, payload)

    group_filter = request_helper.get(query_url)
    assert group_filter['name'] == payload['name']


def test_delete_domain_group_filter_with_payload(request_helper, base_url):
    """Test admin delete domain group filter."""
    # Given
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
    query_url = '{baseUrl}/group_filters'.format_map({
        'baseUrl': base_url
    })
    group_filter = request_helper.post(query_url, payload)

    # When
    query_url = '{baseUrl}/group_filters/{groupFilterUuid}'.format_map({
        'baseUrl': base_url,
        'groupFilterUuid': group_filter['uuid']
    })
    payload = {
        "name": group_filter['name'],
        "description": group_filter['description'],
        "type": group_filter['type']
    }
    request_helper.delete(query_url, payload)

    # Then
    query_url = '{baseUrl}/group_filters/{groupFilterUuid}'.format_map({
        'baseUrl': base_url,
        'groupFilterUuid': group_filter['uuid']
    })
    request_helper.get(query_url, expected_status=400, busines_err_code=55000)


def test_delete_domain_group_filter_no_payload(request_helper, base_url):
    """Test admin delete domain group filter."""
    # Given
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
    query_url = '{baseUrl}/group_filters'.format_map({
        'baseUrl': base_url
    })
    group_filter = request_helper.post(query_url, payload)

    # When
    query_url = '{baseUrl}/group_filters/{groupFilterUuid}'.format_map({
        'baseUrl': base_url,
        'groupFilterUuid': group_filter['uuid']
    })
    request_helper.delete(query_url)

    # Then
    query_url = '{baseUrl}/group_filters/{groupFilterUuid}'.format_map({
        'baseUrl': base_url,
        'groupFilterUuid': group_filter['uuid']
    })
    request_helper.get(query_url, expected_status=400, busines_err_code=55000)
