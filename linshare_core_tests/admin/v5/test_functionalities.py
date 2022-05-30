#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""Testing functionalities endpoints of adminv5 API."""


import os
import json
import logging
import urllib
import pytest

from deepdiff import DeepDiff


def load_data_from_file(test_file):
    """Read a json file and converter it to a python dict."""
    test_dir = os.path.dirname(os.path.abspath(__file__))
    with open(test_dir + '/' + test_file, encoding='UTF-8') as json_file:
        return json.load(json_file)


def test_config(display_admin_cfg):
    """Just display current config."""
    display_admin_cfg()


def test_find_all_functionalites(request_helper, base_url, admin_cfg):
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
    funct_count = int(admin_cfg['FUNCTIONALITIES']['count'])
    assert funct_count == len([a['identifier'] for a in data])


def test_find_all_functionalities_and_subs(
        request_helper, base_url, admin_cfg):
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
    funct_count = int(admin_cfg['FUNCTIONALITIES']['count_with_nested'])
    assert data
    assert funct_count == len([a['identifier'] for a in data])
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


@pytest.fixture(scope="class", name="reset")
def fixture_reset(base_url, request_helper):
    """Using test_functionalities.all.json file to restore initial state of
    functionalities after update tests."""
    yield
    for func in load_data_from_file("test_functionalities.all.json"):
        log = logging.getLogger('tests.funcs')
        query_url = '{baseUrl}/domains/{domain}/functionalities/{identifier}'
        query_url = query_url.format_map({
            'domain': "LinShareRootDomain",
            'baseUrl': base_url,
            'identifier': func['identifier']
        })
        log.debug("reset functionality: %s", func)
        request_helper.put(query_url, func)


class TestWithUpdates:
    """Group all update tests together."""
    # pylint: disable=unused-argument
    # pylint: disable=no-self-use

    def test_update_functionality_share_expiration_ap(
            self, reset, request_helper, base_url):
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
            self, reset, request_helper, base_url):
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
            self, reset, request_helper, base_url):
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

    def test_update_functionality_share_expiration_dp(
            self, reset, request_helper, base_url):
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

    def test_update_functionality_share_expiration_parameters_date(
            self, reset, request_helper, base_url):
        """Test of parameters updates,  time unit"""
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

    def test_update_functionality_share_expiration_parameters_unlimited(
            self, reset, request_helper, base_url):
        """Test of updates of unlimited parameter,  time unit"""
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
        orig['parameter']['unlimited']['value'] = True
        # sending data to the server
        output = request_helper.put(query_url, orig)
        log.debug("output:type:: %s", type(output))
        assert output
        # changing the sent payload with what we are expecting.
        orig['parameter']['unlimited']['parentValue'] = True
        # comparing sent payload with payload sent back by the update method
        # before / after
        assert not DeepDiff(orig, output)
        # comparing update payload with get payload
        new = request_helper.get(query_url)
        assert not DeepDiff(new, output)

    def test_update_functionality_guest_expiration_parameters(
            self, reset, request_helper, base_url):
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

    def test_update_functionality_upload_request__protected_by_password(
            self, reset, request_helper, base_url):
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

    def test_update_functionality_completion(
            self, reset, request_helper, base_url):
        """Testing update of a Integer Functionality"""
        query_url = '{baseUrl}/domains/{domain}/functionalities/{identifier}'
        query_url = query_url.format_map({
            'domain': "LinShareRootDomain",
            'baseUrl': base_url,
            'identifier': 'COMPLETION'
        })
        orig = request_helper.get(query_url)
        log = logging.getLogger('tests.funcs')
        log.debug("orig: %s", orig)
        log.debug("orig: %s", json.dumps(orig, sort_keys=True, indent=2))
        assert orig
        # changing some values
        orig['configurationPolicy']['allowOverride']['value'] = False
        orig['configurationPolicy']['enable']['value'] = False
        # orig['parameter']['defaut']['value'] = True
        # sending data to the server
        output = request_helper.put(query_url, orig)
        log.debug("output: %s", output)
        assert output
        log.debug("output: %s", json.dumps(output, sort_keys=True, indent=2))
        # changing the sent payload with what we are expecting.
        orig['configurationPolicy']['allowOverride']['overriden'] = True
        orig['configurationPolicy']['enable']['overriden'] = True
        # Parent value is equal to current value on the root domain.
        # orig['parameter']['defaut']['parentValue'] = True
        log.debug(
            "orig patched: %s", json.dumps(orig, sort_keys=True, indent=2))
        # comparing sent payload with payload sent back by the update method
        # before / after
        assert not DeepDiff(orig, output)
        # comparing update payload with get payload
        new = request_helper.get(query_url)
        assert not DeepDiff(new, output)

    def test_update_functionality_upload_request__maximum_deposit_size(
            self, reset, request_helper, base_url):
        """Testing update of a File size Functionality"""
        query_url = '{baseUrl}/domains/{domain}/functionalities/{identifier}'
        query_url = query_url.format_map({
            'domain': "LinShareRootDomain",
            'baseUrl': base_url,
            'identifier': 'UPLOAD_REQUEST__MAXIMUM_DEPOSIT_SIZE'
        })
        orig = request_helper.get(query_url)
        log = logging.getLogger('tests.funcs')
        log.debug("orig: %s", orig)
        log.debug("orig: %s", json.dumps(orig, sort_keys=True, indent=2))
        assert orig
        # changing some values
        orig['configurationPolicy']['allowOverride']['value'] = False
        orig['configurationPolicy']['enable']['value'] = False
        # changing some values
        orig['parameter']['defaut']['value'] = 6
        orig['parameter']['defaut']['unit'] = "GIGA"
        orig['parameter']['maximum']['value'] = 7
        orig['parameter']['maximum']['unit'] = "GIGA"
        # sending data to the server
        output = request_helper.put(query_url, orig)
        log.debug("output: %s", output)
        assert output
        log.debug("output: %s", json.dumps(output, sort_keys=True, indent=2))
        # changing the sent payload with what we are expecting.
        orig['configurationPolicy']['allowOverride']['overriden'] = True
        orig['configurationPolicy']['enable']['overriden'] = True
        # Parent value is equal to current value on the root domain.
        orig['parameter']['defaut']['parentValue'] = 6
        orig['parameter']['maximum']['parentValue'] = 7
        orig['parameter']['defaut']['parentUnit'] = "GIGA"
        orig['parameter']['maximum']['parentUnit'] = "GIGA"
        log.debug(
            "orig patched: %s", json.dumps(orig, sort_keys=True, indent=2))
        # comparing sent payload with payload sent back by the update method
        # before / after
        assert not DeepDiff(orig, output)
        # comparing update payload with get payload
        new = request_helper.get(query_url)
        assert not DeepDiff(new, output)


@pytest.mark.domain_data("MyDomainForFunc")
def test_delete_functionality_upload_request__maximum_deposit_size(
        domain, request_helper, base_url):
    """Testing reset of a File size Functionality"""
    query_url = '{baseUrl}/domains/{domain}/functionalities/{identifier}'
    query = query_url.format_map({
        'domain': domain['uuid'],
        'baseUrl': base_url,
        'identifier': 'UPLOAD_REQUEST__MAXIMUM_DEPOSIT_SIZE'
    })
    orig = request_helper.get(query)
    log = logging.getLogger('tests.funcs')
    log.debug("orig: %s", orig)
    log.debug("orig: %s", json.dumps(orig, sort_keys=True, indent=2))
    assert orig
    # changing some values
    orig['configurationPolicy']['allowOverride']['value'] = False
    orig['configurationPolicy']['enable']['value'] = False
    # changing some values
    orig['parameter']['defaut']['value'] = 6
    orig['parameter']['defaut']['unit'] = "GIGA"
    orig['parameter']['maximum']['value'] = 7
    orig['parameter']['maximum']['unit'] = "GIGA"
    # sending data to the server
    output = request_helper.put(query, orig)
    log.debug("output: %s", output)
    assert output
    log.debug("output: %s", json.dumps(output, sort_keys=True, indent=2))
    # changing the sent payload with what we are expecting.
    orig['configurationPolicy']['allowOverride']['overriden'] = True
    orig['configurationPolicy']['enable']['overriden'] = True
    orig['parameter']['defaut']['overriden'] = True
    orig['parameter']['maximum']['overriden'] = True
    log.debug(
        "orig patched: %s", json.dumps(orig, sort_keys=True, indent=2))
    # comparing sent payload with payload sent back by the update method
    # before / after
    assert not DeepDiff(orig, output)

    # getting parent func from server
    query = query_url.format_map({
        'domain': 'LinShareRootDomain',
        'baseUrl': base_url,
        'identifier': 'UPLOAD_REQUEST__MAXIMUM_DEPOSIT_SIZE'
    })
    parent_func = request_helper.get(query)

    query = query_url.format_map({
        'domain': domain['uuid'],
        'baseUrl': base_url,
        'identifier': 'UPLOAD_REQUEST__MAXIMUM_DEPOSIT_SIZE'
    })
    nested_func = request_helper.delete(query)
    nested_func['domain']['uuid'] = 'LinShareRootDomain'
    nested_func['domain']['name'] = 'LinShareRootDomain'
    assert not DeepDiff(parent_func, nested_func)
