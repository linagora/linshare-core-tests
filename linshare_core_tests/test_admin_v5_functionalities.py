#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""Testing functionalities endpoints of adminv5 API."""


import logging
import urllib
import json
import pytest
import requests

from requests.auth import HTTPBasicAuth


@pytest.fixture(scope="module", name="base_url")
def fixture_base_url(admin_cfg):
    """Return base URL for all tests"""
    host = admin_cfg['DEFAULT']['host']
    base_url = host + '/linshare/webservice/rest/admin/v5'
    return base_url


class RequestHelper:
    """A tiny helper to call the API"""

    def __init__(self, email, password, verify=True, headers=None):
        self.email = email
        self.password = password
        self.verify = verify
        self.headers = headers
        self.log = logging.getLogger('tests.funcs.requesthelper')

    def get(self, query_url):
        req = requests.get(
            query_url,
            headers=self.headers,
            auth=HTTPBasicAuth(self.email, self.password),
            verify=self.verify
        )
        self.log.debug("status_code : %s", req.status_code)
        assert req.status_code == 200
        data = req.json()
        self.log.debug("data : %s", json.dumps(req.json(), sort_keys=True,
                       indent=2))
        return data

    def head(self, query_url):
        """HEAD request Returns HTTP Response"""
        req = requests.head(
            query_url,
            headers=self.headers,
            auth=HTTPBasicAuth(self.email, self.password),
            verify=self.verify
        )
        assert req.status_code == 200
        self.log.debug("status_code : %s", req.status_code)

    def post(self, query_url, payload, headers=None, expected_status=200,
             busines_err_code=None):
        """Do POST request"""
        if not headers:
            headers = self.headers
        if headers['Content-Type'] != 'application/json':
            body = payload
        else:
            body = json.dumps(payload)
        req = requests.post(
            query_url,
            headers=headers,
            data=body,
            auth=HTTPBasicAuth(self.email, self.password),
            verify=self.verify)
        self.log.debug("status_code : %s", req.status_code)
        self.log.debug("result : %s", req.text)
        self.assertEqual(req.status_code, expected_status)
        data = req.json()
        self.log.debug("data : %s", json.dumps(data, sort_keys=True, indent=2))
        if busines_err_code:
            assert data['errCode'] == busines_err_code
        return data

    def request_delete(self, query_url, payload=None):
        """Do DELETE request"""
        data = None
        if payload:
            data = json.dumps(payload)
        req = requests.delete(
            query_url,
            data=data,
            headers=self.headers,
            auth=HTTPBasicAuth(self.email, self.password),
            verify=self.verify)
        self.log.debug("status_code : %s", req.status_code)
        self.log.debug("result : %s", req.text)
        self.assertEqual(req.status_code, 200)
        data = req.json()
        self.log.debug("data : %s", json.dumps(data, sort_keys=True, indent=2))
        return data

    def request_put(self, query_url, payload=None, expected_status=200,
                    busines_err_code=None):
        """Do PUT request"""
        req = requests.put(
            query_url,
            data=json.dumps(payload),
            headers=self.headers,
            auth=HTTPBasicAuth(self.email, self.password),
            verify=self.verify)
        self.log.debug("status_code : %s", req.status_code)
        self.log.debug("result : %s", req.text)
        self.assertEqual(req.status_code, expected_status)
        data = req.json()
        self.log.debug("data : %s", json.dumps(data, sort_keys=True, indent=2))
        if busines_err_code:
            assert data['errCode'] == busines_err_code
            return data

    def request_patch(self, query_url, payload):
        req = requests.patch(
            query_url,
            data=json.dumps(payload),
            headers=self.headers,
            auth=HTTPBasicAuth(self.email, self.password),
            verify=self.verify)
        self.log.debug("status_code : %s", req.status_code)
        self.log.debug("result : %s", req.text)
        self.assertEqual(req.status_code, 200)
        data = req.json()
        self.log.debug("data : %s", json.dumps(data, sort_keys=True, indent=2))
        return data


@pytest.fixture(scope="module", name="request_helper")
def fixture_request_helper(admin_cfg):
    """Get RequestHelper"""
    helper = RequestHelper(
        admin_cfg['DEFAULT']['email'],
        admin_cfg['DEFAULT']['password'],
        verify=int(admin_cfg['DEFAULT']['no_verify']) == 0,
        headers={
            'Accept': 'application/json',
            'Content-Type': 'application/json'
        }
    )
    return helper


def test_config(admin_cfg, base_url):
    """Just display current config."""
    print()
    print(admin_cfg['DEFAULT']['host'])
    print(admin_cfg['DEFAULT']['email'])
    print(admin_cfg['DEFAULT']['password'])
    print(base_url)


def test_find_all_functionalites(request_helper, base_url):
    """Test find all functionalities for root domain on API v4"""
    encoded_url = urllib.parse.urlencode({'domainId': "LinShareRootDomain"})
    query_url = '{baseUrl}/domains/{domain}/functionalities?{encode}'
    query_url = query_url.format_map({
        'domain': "LinShareRootDomain",
        'baseUrl': base_url,
        'encode': encoded_url}
    )
    data = request_helper.get(query_url)
    self.log.debug("functionalities: %s", data)
    assert data
    assert len([a['identifier'] for a in data]) == 17


def test_find_all_functionalites_and_subs(request_helper, base_url):
    """Test find all functionalities for root domain on API v4"""
    encoded_url = urllib.parse.urlencode(
        {
            'domainId': "LinShareRootDomain",
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
    self.log.debug("functionalities: %s", data)
    assert data
    assert len([a['identifier'] for a in data]) == 45
