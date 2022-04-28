#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""Testing guest moderators endpoints of userv5 API."""


def test_config(display_user_cfg):
    """Just display current config."""
    display_user_cfg()


def test_create_moderator(
        request_helper, base_url, new_user, user_cfg,
        enable_guest_creation, new_guest):
    """Test create moderator"""
    query_url = '{baseUrl}/guests/{uuid}/moderators'.format_map({
        'baseUrl': base_url,
        'uuid': new_guest['uuid']
    })
    payload = {
        "role": "SIMPLE",
        "account": {
            "uuid": new_user['uuid']
        },
        "guest": {
            "uuid": new_guest['uuid']
        }
    }
    moderator = request_helper.post(query_url, payload)
    assert moderator
    assert moderator['account']['uuid'] == new_user['uuid']
    assert moderator['guest']['uuid'] == new_guest['uuid']


def test_update_moderator(
        request_helper, base_url, new_user, user_cfg,
        enable_guest_creation, new_guest):
    """Test update moderator"""
    query_url = '{baseUrl}/guests/{uuid}/moderators'.format_map({
        'baseUrl': base_url,
        'uuid': new_guest['uuid']
    })
    payload = {
        "role": "SIMPLE",
        "account": {
            "uuid": new_user['uuid']
        },
        "guest": {
            "uuid": new_guest['uuid']
        }
    }
    moderator = request_helper.post(query_url, payload)
    assert moderator
    assert moderator['role'] == "SIMPLE"
    assert moderator['account']['uuid'] == new_user['uuid']
    assert moderator['guest']['uuid'] == new_guest['uuid']
    payload = {
        "uuid": moderator['uuid'],
        "role": "ADMIN",
        "account": {
            "uuid": new_user['uuid']
        },
        "guest": {
            "uuid": new_guest['uuid']
        }
    }
    moderator = request_helper.put(query_url, payload)
    assert moderator
    assert moderator['role'] == "ADMIN"


def test_update_moderator_no_uuid_in_payload(
        request_helper, base_url, new_user, user_cfg,
        enable_guest_creation, new_guest):
    """Test update moderator"""
    query_url = '{baseUrl}/guests/{uuid}/moderators'.format_map({
        'baseUrl': base_url,
        'uuid': new_guest['uuid']
    })
    payload = {
        "role": "SIMPLE",
        "account": {
            "uuid": new_user['uuid']
        },
        "guest": {
            "uuid": new_guest['uuid']
        }
    }
    moderator = request_helper.post(query_url, payload)
    assert moderator
    assert moderator['role'] == "SIMPLE"
    assert moderator['account']['uuid'] == new_user['uuid']
    assert moderator['guest']['uuid'] == new_guest['uuid']
    payload = {
        "role": "ADMIN",
        "account": {
            "uuid": new_user['uuid']
        },
        "guest": {
            "uuid": new_guest['uuid']
        }
    }
    query_url = '{baseUrl}/guests/{uuid}/moderators/{mod_uuid}'.format_map({
        'baseUrl': base_url,
        'uuid': new_guest['uuid'],
        'mod_uuid': moderator['uuid']
    })
    moderator = request_helper.put(query_url, payload)
    assert moderator
    assert moderator['role'] == "ADMIN"


def test_delete_moderator_with_payload(
        request_helper, base_url, new_user, user_cfg,
        enable_guest_creation, new_guest):
    """Test delete moderator"""
    query_url = '{baseUrl}/guests/{uuid}/moderators'.format_map({
        'baseUrl': base_url,
        'uuid': new_guest['uuid']
    })
    payload = {
        "role": "SIMPLE",
        "account": {
            "uuid": new_user['uuid']
        },
        "guest": {
            "uuid": new_guest['uuid']
        }
    }
    moderator = request_helper.post(query_url, payload)
    assert moderator
    assert moderator['role'] == "SIMPLE"
    assert moderator['account']['uuid'] == new_user['uuid']
    assert moderator['guest']['uuid'] == new_guest['uuid']
    payload = {
        "uuid": moderator['uuid']
    }
    moderator = request_helper.delete(query_url, payload)
    assert moderator
    assert moderator['account']['uuid'] == new_user['uuid']
    assert moderator['guest']['uuid'] == new_guest['uuid']
    query_url = '{baseUrl}/guests/{uuid}/moderators/{mod_uuid}'.format_map({
        'baseUrl': base_url,
        'uuid': new_guest['uuid'],
        'mod_uuid': moderator['uuid']
    })
    request_helper.get(query_url, expected_status=404)


def test_delete_moderator_no_payload(
        request_helper, base_url, new_user, user_cfg,
        enable_guest_creation, new_guest):
    """Test delete moderator"""
    query_url = '{baseUrl}/guests/{uuid}/moderators'.format_map({
        'baseUrl': base_url,
        'uuid': new_guest['uuid']
    })
    payload = {
        "role": "SIMPLE",
        "account": {
            "uuid": new_user['uuid']
        },
        "guest": {
            "uuid": new_guest['uuid']
        }
    }
    moderator = request_helper.post(query_url, payload)
    assert moderator
    assert moderator['role'] == "SIMPLE"
    assert moderator['account']['uuid'] == new_user['uuid']
    assert moderator['guest']['uuid'] == new_guest['uuid']
    query_url = '{baseUrl}/guests/{uuid}/moderators/{mod_uuid}'.format_map({
        'baseUrl': base_url,
        'uuid': new_guest['uuid'],
        'mod_uuid': moderator['uuid']
    })
    moderator = request_helper.delete(query_url)
    assert moderator
    assert moderator['account']['uuid'] == new_user['uuid']
    assert moderator['guest']['uuid'] == new_guest['uuid']
    request_helper.get(query_url, expected_status=404)


def test_create_moderator_on_creatin_guest(
        request_helper, base_url, user_cfg,
        enable_guest_creation, new_guest):
    """Test create moderator on guest creation"""
    query_url = '{baseUrl}/guests/{uuid}/moderators'.format_map({
        'baseUrl': base_url,
        'uuid': new_guest['uuid']
    })
    data = request_helper.get(query_url)
    assert data
    assert len(data) == 1
    assert data[0]['guest']['email'] == new_guest['mail']
