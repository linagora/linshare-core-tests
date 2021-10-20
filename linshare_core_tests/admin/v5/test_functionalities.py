#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""Testing functionalities endpoints of adminv5 API."""


import logging
import urllib
import pytest

from deepdiff import DeepDiff


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


@pytest.mark.skip(reason="WIP")
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
    assert data['identifier'] == 'SHARE_EXPIRATION'
    orig = {
        "activationPolicy": {
            "allowOverride": {
                "overriden": False,
                "parentValue": True,
                "value": True
            },
            "enable": {
                "overriden": False,
                "parentValue": True,
                "value": True
            },
            "hidden": False,
            "readonly": False
        },
        "configurationPolicy": {
            "allowOverride": {
                "overriden": False,
                "parentValue": True,
                "value": True
            },
            "enable": {
                "overriden": False,
                "parentValue": True,
                "value": True
            },
            "hidden": False,
            "readonly": False
        },
        "delegationPolicy": {
            "allowOverride": {
                "overriden": False,
                "parentValue": True,
                "value": True
            },
            "enable": {
                "overriden": False,
                "parentValue": True,
                "value": True
            },
            "hidden": False,
            "readonly": False
        },
        "domain": {
            "name": "LinShareRootDomain",
            "uuid": "LinShareRootDomain"
        },
        "hidden": False,
        "identifier": "SHARE_EXPIRATION",
        "parameter": {
            "defaut": {
                "overriden": False,
                "parentUnit": "MONTH",
                "parentValue": 3,
                "unit": "MONTH",
                "units": [
                    "DAY",
                    "WEEK",
                    "MONTH"
                ],
                "value": 3
            },
            "hidden": False,
            "maximum": {
                "overriden": False,
                "parentUnit": "MONTH",
                "parentValue": 4,
                "unit": "MONTH",
                "units": [
                    "DAY",
                    "WEEK",
                    "MONTH"
                ],
                "value": 4
            },
            "readonly": False,
            "type": "UNIT_SIZE_ALL",
            "unlimited": {
                "parentValue": False,
                "supported": True,
                "value": False
            }
        },
        "readonly": False,
        "type": "UNIT"
    }
    assert not DeepDiff(data, orig)
