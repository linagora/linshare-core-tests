#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""Testing functionalities endpoints of adminv5 API."""


import os
import json
import logging
import urllib

from deepdiff import DeepDiff


def load_data_from_file(test_file):
    """Read a json file and converter it to a python dict."""
    test_dir = os.path.dirname(os.path.abspath(__file__))
    with open(test_dir + '/' + test_file, encoding='UTF-8') as json_file:
        return json.load(json_file)


def test_config(display_admin_cfg):
    """Just display current config."""
    display_admin_cfg()


def test_find_all_functionalites(request_helper, base_url):
    """Test find all functionalities for root domain on API v5"""
    query_url = '{baseUrl}/domains/{domain}/functionalities'
    query_url = query_url.format_map({
        'domain': "LinShareRootDomain",
        'baseUrl': base_url
    })
    data = request_helper.get(query_url)
    log = logging.getLogger('tests.funcs.test_find_all_functionalites')
    log.debug("functionalities: %s", data)
    assert data
    assert len([a['identifier'] for a in data]) == 17


def test_find_all_functionalites_and_subs(request_helper, base_url):
    """Test find all functionalities for root domain on API v5"""
    encoded_url = urllib.parse.urlencode(
        {
            'subs': True
        }
    )
    query_url = '{baseUrl}/domains/{domain}/functionalities?{encode}'
    query_url = query_url.format_map({
        'domain': "LinShareRootDomain",
        'baseUrl': base_url,
        'encode': encoded_url}
    )
    data = request_helper.get(query_url)
    log = logging.getLogger('tests.funcs.test_find_all_functionalites_and_sub')
    log.debug("functionalities: %s", data)
    assert data
    assert len([a['identifier'] for a in data]) == 45
    assert not DeepDiff(
        load_data_from_file("test_functionalities.all.json"),
        data
    )


def test_find_functionality_share_expiration(request_helper, base_url):
    """Test find all functionalities for root domain on API v5"""
    query_url = '{baseUrl}/domains/{domain}/functionalities/{identifier}'
    query_url = query_url.format_map({
        'domain': "LinShareRootDomain",
        'baseUrl': base_url,
        'identifier': 'SHARE_EXPIRATION'
    })
    data = request_helper.get(query_url)
    log = logging.getLogger('tests.funcs.test_find_functionality')
    log.debug("functionalities: %s", data)
    assert data
    assert not DeepDiff(
        load_data_from_file("test_functionalities.share_expiration.json"),
        data
    )


def test_update_functionality_share_expiration_ap(request_helper, base_url):
    """Test of activation policy updates"""
    query_url = '{baseUrl}/domains/{domain}/functionalities/{identifier}'
    query_url = query_url.format_map({
        'domain': "LinShareRootDomain",
        'baseUrl': base_url,
        'identifier': 'SHARE_EXPIRATION'
    })
    orig = request_helper.get(query_url)
    log = logging.getLogger('tests.funcs')
    log.debug("functionalities: %s", orig)
    assert orig
    # changing some values
    orig['activationPolicy']['allowOverride']['value'] = False
    orig['activationPolicy']['enable']['value'] = False
    # sending data to the server
    output = request_helper.put(query_url, orig)
    log.debug("output:type:: %s", type(output))
    assert output
    # changing the sent payload with what we are expecting.
    orig['activationPolicy']['allowOverride']['overriden'] = True
    orig['activationPolicy']['enable']['overriden'] = True
    # comparing sent payload with payload sent back by the update method
    # before / after
    assert not DeepDiff(orig, output)
    # comparing update payload with get payload
    new = request_helper.get(query_url)
    assert not DeepDiff(new, output)


def test_update_functionality_share_expiration_cp_false(
        request_helper, base_url):
    """Test of configuration policy updates"""
    query_url = '{baseUrl}/domains/{domain}/functionalities/{identifier}'
    query_url = query_url.format_map({
        'domain': "LinShareRootDomain",
        'baseUrl': base_url,
        'identifier': 'SHARE_EXPIRATION'
    })
    orig = request_helper.get(query_url)
    log = logging.getLogger('tests.funcs')
    log.debug("functionalities: %s", orig)
    assert orig
    # changing some values
    orig['configurationPolicy']['allowOverride']['value'] = False
    orig['configurationPolicy']['enable']['value'] = False
    # sending data to the server
    output = request_helper.put(query_url, orig)
    log.debug("output:type:: %s", type(output))
    assert output
    # changing the sent payload with what we are expecting.
    orig['configurationPolicy']['allowOverride']['overriden'] = True
    orig['configurationPolicy']['enable']['overriden'] = True
    # comparing sent payload with payload sent back by the update method
    # before / after
    assert not DeepDiff(orig, output)
    # comparing update payload with get payload
    new = request_helper.get(query_url)
    assert not DeepDiff(new, output)


def test_update_functionality_share_expiration_cp_true(
        request_helper, base_url):
    """Test of configuration policy updates"""
    query_url = '{baseUrl}/domains/{domain}/functionalities/{identifier}'
    query_url = query_url.format_map({
        'domain': "LinShareRootDomain",
        'baseUrl': base_url,
        'identifier': 'SHARE_EXPIRATION'
    })
    orig = request_helper.get(query_url)
    log = logging.getLogger('tests.funcs')
    log.debug("functionalities: %s", orig)
    assert orig
    # changing some values
    orig['configurationPolicy']['allowOverride']['value'] = True
    orig['configurationPolicy']['enable']['value'] = True
    # sending data to the server
    output = request_helper.put(query_url, orig)
    log.debug("output:type:: %s", type(output))
    assert output
    # changing the sent payload with what we are expecting.
    orig['configurationPolicy']['allowOverride']['overriden'] = False
    orig['configurationPolicy']['enable']['overriden'] = False
    # comparing sent payload with payload sent back by the update method
    # before / after
    assert not DeepDiff(orig, output)
    # comparing update payload with get payload
    new = request_helper.get(query_url)
    assert not DeepDiff(new, output)


def test_update_functionality_share_expiration_dp(request_helper, base_url):
    """Test of delegation policy updates"""
    query_url = '{baseUrl}/domains/{domain}/functionalities/{identifier}'
    query_url = query_url.format_map({
        'domain': "LinShareRootDomain",
        'baseUrl': base_url,
        'identifier': 'SHARE_EXPIRATION'
    })
    orig = request_helper.get(query_url)
    log = logging.getLogger('tests.funcs')
    log.debug("functionalities: %s", orig)
    assert orig
    # changing some values
    orig['delegationPolicy']['allowOverride']['value'] = False
    orig['delegationPolicy']['enable']['value'] = False
    # sending data to the server
    output = request_helper.put(query_url, orig)
    log.debug("output:type:: %s", type(output))
    assert output
    # changing the sent payload with what we are expecting.
    orig['delegationPolicy']['allowOverride']['overriden'] = True
    orig['delegationPolicy']['enable']['overriden'] = True
    # comparing sent payload with payload sent back by the update method
    # before / after
    assert not DeepDiff(orig, output)
    # comparing update payload with get payload
    new = request_helper.get(query_url)
    assert not DeepDiff(new, output)


def test_update_functionality_share_expiration_parameters(
        request_helper, base_url):
    """Test of parameters updates"""
    query_url = '{baseUrl}/domains/{domain}/functionalities/{identifier}'
    query_url = query_url.format_map({
        'domain': "LinShareRootDomain",
        'baseUrl': base_url,
        'identifier': 'SHARE_EXPIRATION'
    })
    orig = request_helper.get(query_url)
    log = logging.getLogger('tests.funcs')
    log.debug("functionalities: %s", orig)
    assert orig
    # changing some values
    orig['parameter']['defaut']['value'] = 6
    orig['parameter']['defaut']['unit'] = "WEEK"
    orig['parameter']['maximum']['value'] = 9
    orig['parameter']['maximum']['unit'] = "WEEK"
    # sending data to the server
    output = request_helper.put(query_url, orig)
    log.debug("output:type:: %s", type(output))
    assert output
    # changing the sent payload with what we are expecting.
    orig['parameter']['defaut']['parentValue'] = 6
    orig['parameter']['defaut']['parentUnit'] = "WEEK"
    orig['parameter']['maximum']['parentValue'] = 9
    orig['parameter']['maximum']['parentUnit'] = "WEEK"
    # comparing sent payload with payload sent back by the update method
    # before / after
    assert not DeepDiff(orig, output)
    # comparing update payload with get payload
    new = request_helper.get(query_url)
    assert not DeepDiff(new, output)


def test_update_functionality_guest_expiration_parameters(
        request_helper, base_url):
    """Test of parameters updates"""
    query_url = '{baseUrl}/domains/{domain}/functionalities/{identifier}'
    query_url = query_url.format_map({
        'domain': "LinShareRootDomain",
        'baseUrl': base_url,
        'identifier': 'GUESTS__EXPIRATION'
    })
    orig = request_helper.get(query_url)
    log = logging.getLogger('tests.funcs')
    log.debug("functionalities: %s", orig)
    assert orig
    # changing some values
    orig['parameter']['defaut']['value'] = 6
    orig['parameter']['defaut']['unit'] = "WEEK"
    orig['parameter']['maximum']['value'] = -1
    orig['parameter']['maximum']['unit'] = "WEEK"
    # sending data to the server
    output = request_helper.put(
        query_url, orig,
        expected_status=400,
        busines_err_code=14001
    )
    log.debug("output:type:: %s", type(output))
    assert output


def test_find_functionality_upload_request__protected_by_password(
        request_helper, base_url):
    """Testing find of a Boolean Functionality"""
    query_url = '{baseUrl}/domains/{domain}/functionalities/{identifier}'
    query_url = query_url.format_map({
        'domain': "LinShareRootDomain",
        'baseUrl': base_url,
        'identifier': 'UPLOAD_REQUEST__PROTECTED_BY_PASSWORD'
    })
    data = request_helper.get(query_url)
    log = logging.getLogger('tests.funcs.test_find_functionality')
    log.debug("functionalities: %s", data)
    assert data
    # before / after
    assert not DeepDiff(
        load_data_from_file(
            "test_functionalities.upload_request__protected_by_password.json"),
        data
    )


def test_update_functionality_upload_request__protected_by_password(
        request_helper, base_url):
    """Testing update of a Boolean Functionality"""
    query_url = '{baseUrl}/domains/{domain}/functionalities/{identifier}'
    query_url = query_url.format_map({
        'domain': "LinShareRootDomain",
        'baseUrl': base_url,
        'identifier': 'UPLOAD_REQUEST__PROTECTED_BY_PASSWORD'
    })
    orig = request_helper.get(query_url)
    log = logging.getLogger('tests.funcs')
    log.debug("functionalities: %s", orig)
    assert orig
    # changing some values
    orig['delegationPolicy']['allowOverride']['value'] = False
    orig['delegationPolicy']['enable']['value'] = False
    orig['parameter']['defaut']['value'] = True
    # sending data to the server
    output = request_helper.put(query_url, orig)
    log.debug("output:type:: %s", type(output))
    assert output
    # changing the sent payload with what we are expecting.
    orig['delegationPolicy']['allowOverride']['overriden'] = True
    orig['delegationPolicy']['enable']['overriden'] = False
    # Parent value is equal to current value on the root domain.
    orig['parameter']['defaut']['parentValue'] = True
    # comparing sent payload with payload sent back by the update method
    # before / after
    assert not DeepDiff(orig, output)
    # comparing update payload with get payload
    new = request_helper.get(query_url)
    assert not DeepDiff(new, output)
