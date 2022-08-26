#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Common fixtures"""


import os
import configparser
import logging
import json
import pytest
import requests

from requests.auth import HTTPBasicAuth


@pytest.fixture(name="display_user_cfg")
def fixture_display_user_cfg(user_cfg, base_url):
    """Just display current config."""
    def display():
        print()
        print(user_cfg['DEFAULT']['host'])
        print(user_cfg['DEFAULT']['email'])
        print(user_cfg['DEFAULT']['password'])
        print("base URL:", base_url)
    return display


@pytest.fixture(scope="session", name="user_cfg")
def fixture_user_cfg():
    """Return a object will all configuration properties for user api"""

    log = logging.getLogger('tests.configtest')
    config_file_user = os.getenv('CONFIG_FILE_USER', None)
    if not config_file_user:
        config_file_user = 'linshare.user.ini'
    log.debug("config_file_user: %s", config_file_user)
    config = configparser.ConfigParser()
    config.read(config_file_user)
    return config


@pytest.fixture(scope="module", name="admin_v5_base_url")
def fixture_admin_v5_base_url(user_cfg):
    """Return Admin v5 base URL for all tests"""
    host = user_cfg['DEFAULT']['host']
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

    # pylint: disable=too-many-arguments
    def get(self, query_url, expected_status=200,
            busines_err_code=None, email=None, password=None):
        """GET HTTP method"""
        if not email:
            email = self.email
        if not password:
            password = self.password
        req = requests.get(
            query_url,
            headers=self.headers,
            auth=HTTPBasicAuth(email, password),
            verify=self.verify
        )
        self.log.debug("status_code : %s", req.status_code)
        self.log.debug("payload : %s", req.text)
        assert req.status_code == expected_status
        data = req.json()
        if busines_err_code:
            assert data['errCode'] == busines_err_code
        self.log.debug("data : %s", json.dumps(req.json(), sort_keys=True,
                       indent=2))
        return data
    # pylint: enable=too-many-arguments

    def head(self, query_url):
        """HEAD HTTP method"""
        req = requests.head(
            query_url,
            headers=self.headers,
            auth=HTTPBasicAuth(self.email, self.password),
            verify=self.verify
        )
        self.log.debug("status_code : %s", req.status_code)
        self.log.debug("payload : %s", req.text)
        assert req.status_code == 200

    def post(self, query_url, payload, headers=None, expected_status=200,
             busines_err_code=None, email=None, password=None):
        """POST HTTP method"""
        # pylint: disable=too-many-arguments
        if not email:
            email = self.email
        if not password:
            password = self.password
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
            auth=HTTPBasicAuth(email, password),
            verify=self.verify)
        self.log.debug("status_code : %s", req.status_code)
        self.log.debug("payload : %s", req.text)
        assert req.status_code == expected_status
        data = req.json()
        self.log.debug("data : %s", json.dumps(data, sort_keys=True, indent=2))
        if busines_err_code:
            assert data['errCode'] == busines_err_code
        return data

    # pylint: disable=too-many-arguments
    def delete(self, query_url, payload=None, expected_status=200,
               busines_err_code=None, email=None, password=None):
        """DELETE HTTP method"""
        data = None
        if not email:
            email = self.email
        if not password:
            password = self.password
        if payload:
            data = json.dumps(payload)
        req = requests.delete(
            query_url,
            data=data,
            headers=self.headers,
            auth=HTTPBasicAuth(email, password),
            verify=self.verify)
        self.log.debug("status_code : %s", req.status_code)
        self.log.debug("payload : %s", req.text)
        assert req.status_code == expected_status
        data = req.json()
        self.log.debug("data : %s", json.dumps(data, sort_keys=True, indent=2))
        if busines_err_code:
            assert data['errCode'] == busines_err_code
        return data
    # pylint: enable=too-many-arguments

    # pylint: disable=too-many-arguments
    def put(self, query_url, payload=None, expected_status=200,
            busines_err_code=None, email=None, password=None):
        """PUT HTTP method"""
        if not email:
            email = self.email
        if not password:
            password = self.password
        req = requests.put(
            query_url,
            data=json.dumps(payload),
            headers=self.headers,
            auth=HTTPBasicAuth(email, password),
            verify=self.verify)
        self.log.debug("status_code : %s", req.status_code)
        self.log.debug("payload : %s", req.text)
        assert req.status_code == expected_status
        data = req.json()
        self.log.debug("data : %s", json.dumps(data, sort_keys=True, indent=2))
        if busines_err_code:
            assert data['errCode'] == busines_err_code
        return data
    # pylint: enable=too-many-arguments

    def patch(self, query_url, payload):
        """PATCH HTTP method"""
        req = requests.patch(
            query_url,
            data=json.dumps(payload),
            headers=self.headers,
            auth=HTTPBasicAuth(self.email, self.password),
            verify=self.verify)
        self.log.debug("status_code : %s", req.status_code)
        self.log.debug("payload : %s", req.text)
        assert req.status_code == 200
        data = req.json()
        self.log.debug("data : %s", json.dumps(data, sort_keys=True, indent=2))
        return data

    def assert_json_payload(self, expected, payload_response):
        """Method that allows to assert information returned on the responses
        Parameters:
        expected: list of expected fields in the source object.
        payload_response : returned object to be tested.
         """
        all_fields_exists = True
        for item in payload_response:
            if item not in expected:
                all_fields_exists = False
                self.log.error(
                    "Field '%s' was not found in the expected payload",
                    item)
        for item in expected:
            if item not in payload_response:
                all_fields_exists = False
                self.log.error(
                    "Expected field '%s' was not found in the response",
                    item)
        assert all_fields_exists
        self.log.debug("expected: %s", expected)
        self.log.debug("payload_response keys: %s", payload_response.keys())
        assert len(expected), len(payload_response.keys())


@pytest.fixture(scope="module", name="request_helper")
def fixture_request_helper(user_cfg):
    """Get RequestHelper"""
    helper = RequestHelper(
        user_cfg['DEFAULT']['email'],
        user_cfg['DEFAULT']['password'],
        verify=int(user_cfg['DEFAULT']['no_verify']) == 0,
        headers={
            'Accept': 'application/json',
            'Content-Type': 'application/json'
        }
    )
    return helper


# Scope should be class in order to access to the custom marker
@pytest.fixture(scope="class", name="domain")
def fixture_create_domain(request, request_helper, base_url):
    """
    This fixture is design to create a domain, domain name can be passed
    thought pytest.mark.domain_data = 'xxx'
    """
    marker = request.node.get_closest_marker("domain_data")
    if marker is None:
        name = "TopDomainUserProvider"
    else:
        name = marker.args[0]

    query_url = '{baseUrl}/domains'.format_map({
        'baseUrl': base_url,
    })
    payload = {
        "parent": {"uuid": "LinShareRootDomain"},
        "type": "TOPDOMAIN",
        "name": name,
        "description": "Description of top domain 'test user provider'"
    }
    domain = request_helper.post(query_url, payload)
    assert domain
    assert domain['uuid']

    yield domain

    query_url = '{baseUrl}/domains/{uuid}'.format_map({
        'baseUrl': base_url,
        'uuid': domain['uuid']
    })
    request_helper.delete(query_url)
