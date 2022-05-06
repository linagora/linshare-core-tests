#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""Testing guests endpoints of userv4 API."""


import urllib


def test_config(display_user_cfg):
    """Just display current config."""
    display_user_cfg()


def test_create_guest(
        request_helper, base_url, new_user, user_cfg, enable_guest_creation):
    """Test create guest"""
    payload = {
        "firstName": "firstName",
        "lastName": "lastName",
        "mail": user_cfg['DEFAULT']['email_external1'],
        "restricted": False,
        "externalMailLocale": 'ENGLISH'
    }
    query_url = '{baseUrl}/guests'.format_map({
        'baseUrl': base_url,
    })
    guest = request_helper.post(query_url, payload)
    assert guest
    assert guest['mail'] == payload['mail']
    query_url = '{baseUrl}/guests/{uuid}'.format_map({
        'baseUrl': base_url,
        'uuid': guest['uuid']
    })
    request_helper.delete(query_url)


def test_update_guest(
        request_helper, base_url, new_user, user_cfg, enable_guest_creation):
    """Test update guest"""
    payload = {
        "firstName": "firstName",
        "lastName": "lastName",
        "mail": user_cfg['DEFAULT']['email_external4'],
        "restricted": False,
        "externalMailLocale": 'ENGLISH'
    }
    query_url = '{baseUrl}/guests'.format_map({
        'baseUrl': base_url,
    })
    guest = request_helper.post(query_url, payload)
    assert guest
    assert guest['mail'] == payload['mail']
    payload = {
        "uuid": guest['uuid'],
        "firstName": "UpdatedFirstnameName",
        "lastName": "UpdatedLastnameName",
    }
    guest = request_helper.put(query_url, payload)
    assert guest['firstName'] == "UpdatedFirstnameName"
    assert guest['lastName'] == "UpdatedLastnameName"
    query_url = '{baseUrl}/guests/{uuid}'.format_map({
        'baseUrl': base_url,
        'uuid': guest['uuid']
    })
    request_helper.delete(query_url)


def test_delete_guest(
        request_helper, base_url, new_user, user_cfg, enable_guest_creation):
    """Test delete guest"""
    payload = {
        "firstName": "firstName",
        "lastName": "lastName",
        "mail": user_cfg['DEFAULT']['email_external4'],
        "restricted": False,
        "externalMailLocale": 'ENGLISH'
    }
    query_url = '{baseUrl}/guests'.format_map({
        'baseUrl': base_url,
    })
    guest = request_helper.post(query_url, payload)
    assert guest
    assert guest['mail'] == payload['mail']
    payload = {
        "uuid": guest['uuid']
    }
    guest = request_helper.delete(query_url, payload)
    assert guest
    query_url = '{baseUrl}/guests/{uuid}'.format_map({
        'baseUrl': base_url,
        'uuid': guest['uuid']
    })
    request_helper.get(query_url, expected_status=404)


def test_find_all(
        request_helper, base_url, new_user, user_cfg, enable_guest_creation):
    """Test findAll guests"""
    peter_guest = create_peter_guest(
        request_helper, base_url, new_user, user_cfg, enable_guest_creation)
    amy_guest = create_amy_guest(
        request_helper, base_url, new_user, user_cfg, enable_guest_creation)
    query_url = '{baseUrl}/guests'.format_map({
        'baseUrl': base_url,
    })
    all_guests = request_helper.get(query_url)
    assert len(all_guests) == 2
    encoded_url = urllib.parse.urlencode({'mine': "true"})
    query_url = '{baseUrl}/guests?{encode}'.format_map({
        'baseUrl': base_url,
        'encode': encoded_url
    })
    my_guests = request_helper.get(query_url)
    assert len(my_guests) == 1
    assert my_guests[0]['mail'] == peter_guest['mail']
    query_url = '{baseUrl}/guests/{uuid}'.format_map({
        'baseUrl': base_url,
        'uuid': peter_guest['uuid']
    })
    request_helper.delete(query_url)
    query_url = '{baseUrl}/guests/{uuid}'.format_map({
        'baseUrl': base_url,
        'uuid': amy_guest['uuid']
    })
    request_helper.delete(
        query_url, email=new_user['mail'], password='secret')


def create_peter_guest(
        request_helper, base_url, new_user, user_cfg, enable_guest_creation):
    payload = {
        "firstName": "firstName",
        "lastName": "lastName",
        "mail": user_cfg['DEFAULT']['email_external2'],
        "restricted": False,
        "externalMailLocale": 'ENGLISH'
    }
    query_url = '{baseUrl}/guests'.format_map({
        'baseUrl': base_url,
    })
    peter_guest = request_helper.post(query_url, payload)
    assert peter_guest
    assert peter_guest['mail'] == payload['mail']
    return peter_guest


def create_amy_guest(
        request_helper, base_url, new_user, user_cfg, enable_guest_creation):
    payload = {
        "firstName": "firstName",
        "lastName": "lastName",
        "mail": user_cfg['DEFAULT']['email_external3'],
        "restricted": False,
        "externalMailLocale": 'ENGLISH'
    }
    query_url = '{baseUrl}/guests'.format_map({
        'baseUrl': base_url,
    })
    amy_guest = request_helper.post(
        query_url, payload, email=new_user['mail'], password='secret')
    assert amy_guest
    assert amy_guest['mail'] == payload['mail']
    return amy_guest
