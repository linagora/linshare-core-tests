#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""Testing user profile endpoints of userv5 API."""


def test_config(display_user_cfg):
    """Just display current config."""
    display_user_cfg()


def test_find_user_profile_internal(request_helper, base_url):
    """Test find user profile API v5 - internal user"""
    query_url = '{baseUrl}/me/profile'
    query_url = query_url.format_map({
        'baseUrl': base_url
    })
    data = request_helper.get(query_url)
    assert data
    assert not data['canCreateGuest']
    assert data['uuid']
    assert data['firstName'] == 'Peter'
    assert data['lastName'] == 'WILSON'
    assert data['mail'] == 'peter.wilson@linshare.org'
    assert data['creationDate']
    assert data['modificationDate']
    assert data['locale'] == 'ENGLISH'
    assert data['personalSpaceEnabled']
    assert data['accountType'] == 'INTERNAL'


def test_find_user_profile_guest(request_helper, base_url, new_guest):
    """Test find user profile API v5 - guest"""
    query_url = '{baseUrl}/me/profile'
    query_url = query_url.format_map({
        'baseUrl': base_url
    })
    data = request_helper.get(
        query_url, email=new_guest['mail'], password='MyGuest@Password123')
    assert data
    assert data['expirationDate']
    assert not data['restricted']
    assert data['author']
    assert data['author']['firstName'] == 'Peter'
    assert data['author']['lastName'] == 'WILSON'
    assert data['author']['mail'] == 'peter.wilson@linshare.org'
    assert data['author']['uuid']
    assert data['uuid']
    assert data['firstName'] == 'Guest'
    assert data['lastName'] == 'My'
    assert data['mail'] == 'guest1@linshare.org'
    assert data['creationDate']
    assert data['modificationDate']
    assert data['locale'] == 'ENGLISH'
    assert not data['personalSpaceEnabled']
    assert data['accountType'] == 'GUEST'
