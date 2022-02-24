#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""Testing functionalities endpoints of userv5 API."""

import pytest


@pytest.fixture(scope="module", name="base_url")
def fixture_base_url(user_cfg):
    """Return base URL for all tests"""
    host = user_cfg['DEFAULT']['host']
    base_url = host + '/linshare/webservice/rest/user/v5'
    return base_url


@pytest.fixture(scope="module", name="test_base_url")
def fixture_test_base_url(user_cfg):
    """Return base URL for all tests"""
    host = user_cfg['DEFAULT']['host']
    base_url = host + '/linshare/webservice/rest/test/user/v5'
    return base_url


@pytest.fixture(scope="function", name="enable_guest_creation")
def fixture_enable_guest_creation(
        request_helper, user_cfg, admin_v5_base_url):
    """Enable GUESTS functionality."""
    # Enable guests creation
    admin_query_url = '{baseUrl}/domains/{domain}/functionalities/{identifier}'
    admin_query_url = admin_query_url.format_map({
        'domain': "MyDomain",
        'baseUrl': admin_v5_base_url,
        'identifier': 'GUESTS'
    })
    email = user_cfg['ADMIN']['email']
    password = user_cfg['ADMIN']['password']
    functionality = request_helper.get(
        admin_query_url, email=email, password=password)
    functionality['activationPolicy']['enable']['value'] = True
    request_helper.put(
        admin_query_url, functionality, email=email, password=password)

    yield True

    functionality['activationPolicy']['enable']['value'] = False
    request_helper.put(
        admin_query_url, functionality, email=email, password=password)


@pytest.fixture(scope="function", name="new_guest")
def fixture_create_guest(
        request_helper, enable_guest_creation, base_url, test_base_url):
    """Create a Guest."""
    assert enable_guest_creation
    query_url = '{baseUrl}/guests'.format_map({
        'baseUrl': base_url
    })
    payload = {
        "firstName": "Guest",
        "lastName": "My",
        "mail": "guest1@linshare.org",
        "externalMailLocale": "ENGLISH"
    }
    guest = request_helper.post(query_url, payload)
    assert guest
    assert guest['uuid']

    query_url = '{baseUrl}/guest/{uuid}/password'.format_map({
        'baseUrl': test_base_url,
        'uuid': guest['uuid']
    })
    payload = {
        "uuid": guest['uuid'],
        "password": "MyGuest@Password123"
    }
    request_helper.put(query_url, payload)

    yield guest

    query_url = '{baseUrl}/guests/{uuid}'.format_map({
        'baseUrl': base_url,
        'uuid': guest['uuid']
    })
    request_helper.delete(query_url, guest)


@pytest.fixture(scope="function", name="new_restricted_contact")
def fixture_create_restricted_contact(
        request_helper, user_cfg, new_guest, admin_v5_base_url):
    """Create a restricted contact."""
    query_url = '{baseUrl}/users/{uuid}/restricted_contacts'.format_map({
        'baseUrl': admin_v5_base_url,
        'uuid': new_guest['uuid']
    })
    payload = {
        "firstName": "Guest",
        "lastName": "My",
        "mail": "guest1@linshare.org",
        "domain": {
            "uuid": new_guest['domain'],
            "name": new_guest['domain']
        }
    }
    email = user_cfg['ADMIN']['email']
    password = user_cfg['ADMIN']['password']
    restricted_contact = request_helper.post(query_url, payload,
                                             email=email, password=password)
    assert restricted_contact
    assert restricted_contact['uuid']

    yield restricted_contact

    query_url = '{baseUrl}/users/{uuid}/restricted_contacts/{ruuid}'
    query_url = query_url.format_map({
        'baseUrl': admin_v5_base_url,
        'uuid': new_guest['uuid'],
        'ruuid': restricted_contact['uuid']
    })
    request_helper.delete(query_url, restricted_contact,
                          email=email, password=password)


@pytest.fixture(scope="function", name="new_upload_request")
def fixture_create_upload_request(request_helper, base_url):
    """Create an upload request."""
    query_url = '{base_url}/upload_request_groups'.format_map({
        'base_url': base_url
    })
    payload = {
        "label": "upload request group",
        "canDelete": True,
        "canClose": True,
        "contactList": ["ext1@linshare.org", "ext2@linshare.org"],
        "body": "test body",
        "enableNotification": True
    }
    upload_request = request_helper.post(query_url, payload)
    assert upload_request

    yield upload_request


@pytest.fixture(scope="function", name="new_guest_upload_request")
def fixture_create_guest_upload_request(request_helper, base_url, new_guest):
    """Create a guest upload request."""
    query_url = '{base_url}/upload_request_groups'.format_map({
        'base_url': base_url
    })
    payload = {
        "label": "upload request group",
        "canDelete": True,
        "canClose": True,
        "contactList": ["extguest1@linshare.org", "extguest2@linshare.org", "extother@linshare.org"],
        "body": "test body",
        "enableNotification": True
    }
    upload_request = request_helper.post(query_url, payload,
                     email=new_guest['mail'], password='MyGuest@Password123')
    assert upload_request

    yield upload_request
