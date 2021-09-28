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


@pytest.fixture(scope="session", name="admin_cfg")
def fixture_admin_cfg():
    """Return a object will all configuration properties for admin api"""

    log = logging.getLogger('tests.configtest')
    config_file_admin = os.getenv('CONFIG_FILE_ADMIN', None)
    if not config_file_admin:
        config_file_admin = 'linshare.admin.ini'
    log.debug("config_file_admin: %s", config_file_admin)
    config = configparser.ConfigParser()
    config.read(config_file_admin)
    return config


@pytest.fixture(scope="session", name="admin_debug_flag")
def fixture_admin_debug_flag(admin_cfg):
    """Return true if debug mode is eanbled."""
    debug = False
    if int(admin_cfg['DEFAULT']['debug']) == 1:
        debug = True
    if os.getenv('LS_TEST_DEBUG', None):
        debug = True
    return debug


class RequestHelper:
    """A tiny helper to call the API"""

    def __init__(self, email, password, verify=True, headers=None):
        self.email = email
        self.password = password
        self.verify = verify
        self.headers = headers
        self.log = logging.getLogger('tests.funcs.requesthelper')

    def get(self, query_url, expected_status=200):
        """GET HTTP method"""
        req = requests.get(
            query_url,
            headers=self.headers,
            auth=HTTPBasicAuth(self.email, self.password),
            verify=self.verify
        )
        self.log.debug("status_code : %s", req.status_code)
        assert req.status_code == expected_status
        data = req.json()
        self.log.debug("data : %s", json.dumps(req.json(), sort_keys=True,
                       indent=2))
        return data

    def head(self, query_url):
        """HEAD HTTP method"""
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
        """POST HTTP method"""
        # pylint: disable=too-many-arguments
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
        assert req.status_code == expected_status
        data = req.json()
        self.log.debug("data : %s", json.dumps(data, sort_keys=True, indent=2))
        if busines_err_code:
            assert data['errCode'] == busines_err_code
        return data

    def delete(self, query_url, payload=None):
        """DELETE HTTP method"""
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
        assert req.status_code == 200
        data = req.json()
        self.log.debug("data : %s", json.dumps(data, sort_keys=True, indent=2))
        return data

    def put(self, query_url, payload=None, expected_status=200,
            busines_err_code=None):
        """PUT HTTP method"""
        req = requests.put(
            query_url,
            data=json.dumps(payload),
            headers=self.headers,
            auth=HTTPBasicAuth(self.email, self.password),
            verify=self.verify)
        self.log.debug("status_code : %s", req.status_code)
        self.log.debug("result : %s", req.text)
        assert req.status_code == expected_status
        data = req.json()
        self.log.debug("data : %s", json.dumps(data, sort_keys=True, indent=2))
        if busines_err_code:
            assert data['errCode'] == busines_err_code
        return data

    def patch(self, query_url, payload):
        """PATCH HTTP method"""
        req = requests.patch(
            query_url,
            data=json.dumps(payload),
            headers=self.headers,
            auth=HTTPBasicAuth(self.email, self.password),
            verify=self.verify)
        self.log.debug("status_code : %s", req.status_code)
        self.log.debug("result : %s", req.text)
        assert req.status_code == 200
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
