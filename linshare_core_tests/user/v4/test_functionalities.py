#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""Testing functionalities endpoints of userv5 API."""


import logging
import pytest


def test_config(display_user_cfg):
    """Just display current config."""
    display_user_cfg()


@pytest.mark.skip(reason="Works locally but not in gitlab. Weird.")
def test_find_all_functionalites(request_helper, base_url):
    """Test find all functionalities for user API v4"""
    query_url = '{baseUrl}/functionalities'
    query_url = query_url.format_map({
        'baseUrl': base_url
    })
    data = request_helper.get(query_url)
    log = logging.getLogger('tests.funcs.test_find_all_functionalites')
    log.debug("functionalities: %s", data)
    assert data
    assert len([a['identifier'] for a in data]) == 47


@pytest.mark.xfail(reason="Bad server configuration")
def test_find_functionality_integer_type(request_helper, base_url):
    """Test find a functionality Integer type for a giving user API V4"""
    query_url = '{baseUrl}/functionalities/{identifier}'.format_map({
        'baseUrl': base_url,
        'identifier': 'UPLOAD_REQUEST__MAXIMUM_FILE_COUNT'
        })
    data = request_helper.get(query_url)
    log = logging.getLogger('tests.funcs.test_find_functionality_integer_type')
    log.debug("functionalities: %s", data)
    assert data
    request_helper.assert_json_payload(
        ['type', 'identifier', 'enable', 'canOverride', 'value', 'maxValue'],
        data
    )
    assert data["canOverride"]
    assert data["enable"]
    assert data["maxValue"] == 20
    assert data["value"] == 15


@pytest.mark.xfail(
        reason="Expected field 'maxValue' was not found in the response")
def test_find_functionality_unit_type(request_helper, base_url):
    """Test find a functionality Unit type for a giving user API V4"""
    query_url = '{baseUrl}/functionalities/{identifier}'.format_map({
        'baseUrl': base_url,
        'identifier': 'UPLOAD_REQUEST__DELAY_BEFORE_ACTIVATION'
        })
    data = request_helper.get(query_url)
    log = logging.getLogger('tests.funcs.test_find_functionality_unit_type')
    log.debug("functionalities: %s", data)
    assert data
    request_helper.assert_json_payload(
        [
            'type', 'identifier', 'enable', 'canOverride', 'value', 'unit',
            'maxUnit', 'maxValue', 'units'
        ],
        data
    )
    assert data["canOverride"]
    assert data["enable"]
    assert data["maxValue"] == 20
    assert data["value"] == 15


@pytest.mark.skip(reason="Works locally but not in gitlab. Weird.")
def test_find_functionality_string_type(request_helper, base_url):
    """Test find a functionality String type for a giving user API V4"""
    query_url = '{baseUrl}/functionalities/{identifier}'.format_map({
        'baseUrl': base_url,
        'identifier': 'ANONYMOUS_URL__NOTIFICATION_URL'
        })
    data = request_helper.get(query_url)
    log = logging.getLogger('tests.funcs.test_find_functionality_string_type')
    log.debug("functionalities: %s", data)
    assert data
    request_helper.assert_json_payload(
        ['type', 'identifier', 'enable', 'canOverride', 'value'],
        data
    )
    assert not data["canOverride"]
    assert data["enable"]
    assert data["value"] == "http://linshare-ui-user.local/"


@pytest.mark.skip(reason="Works locally but not in gitlab. Weird.")
def test_find_functionality_boolean_type(request_helper, base_url):
    """Test find a functionality Boolean type for a giving user API V4"""
    query_url = '{baseUrl}/functionalities/{identifier}'.format_map({
        'baseUrl': base_url,
        'identifier': 'ANONYMOUS_URL__NOTIFICATION'
        })
    data = request_helper.get(query_url)
    log = logging.getLogger('boolean_type')
    log.debug("functionalities: %s", data)
    assert data
    request_helper.assert_json_payload(
        ['type', 'identifier', 'enable', 'canOverride', 'value'],
        data
    )
    assert not data["canOverride"]
    assert data["enable"]
    assert data["value"]


@pytest.mark.skip(reason="Works locally but not in gitlab. Weird.")
def test_find_functionality_lang_type(request_helper, base_url):
    """Test find a functionality Boolean type for a giving user API V4"""
    query_url = '{baseUrl}/functionalities/{identifier}'.format_map({
        'baseUrl': base_url,
        'identifier': 'UPLOAD_REQUEST__NOTIFICATION_LANGUAGE'
        })
    data = request_helper.get(query_url)
    log = logging.getLogger('lang_type')
    log.debug("functionalities: %s", data)
    assert data
    request_helper.assert_json_payload(
        ['type', 'identifier', 'enable', 'canOverride', 'value', 'units'],
        data
    )
    assert data["canOverride"]
    assert data["enable"]
    assert data["value"]