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


@pytest.fixture(name="display_admin_cfg")
def fixture_display_admin_cfg(admin_cfg, base_url):
    """Just display current config."""
    def display():
        print()
        print(admin_cfg['DEFAULT']['host'])
        print(admin_cfg['DEFAULT']['email'])
        print(admin_cfg['DEFAULT']['password'])
        print("base URL:", base_url)
    return display


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

    def get(self, query_url, expected_status=200,
            busines_err_code=None):
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
        if busines_err_code:
            assert data['errCode'] == busines_err_code
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

    def delete(self, query_url, payload=None, expected_status=200,
               busines_err_code=None):
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
        assert req.status_code == expected_status
        data = req.json()
        self.log.debug("data : %s", json.dumps(data, sort_keys=True, indent=2))
        if busines_err_code:
            assert data['errCode'] == busines_err_code
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


@pytest.fixture(scope="module", name="new_group_filter")
def fixture_create_group_filter(request_helper, base_url):
    """Create domain group filter."""
    search_gq = (
        "ldap.search(baseDn, "
        "\"(&(objectClass=groupOfNames)(cn=drive-*))\");"
    )
    search_q = (
        "ldap.search(baseDn, "
        "\"(&(objectClass=groupOfNames)(cn=drive-\" + pattern + \"))\");"
    )
    payload = {
        "description": "Test domain workgroup filter",
        "name": "Group filter name",
        "searchAllGroupsQuery": search_gq,
        "searchGroupQuery": search_q,
        "searchPageSize": 100,
        "groupMemberAttribute": "member",
        "groupNameAttribute": "cn",
        "groupPrefixToRemove": "workgroup-",
        "memberFirstNameAttribute": "givenname",
        "memberLastNameAttribute": "sn",
        "memberMailAttribute": "mail"
    }
    query_url = '{baseUrl}/group_filters'.format_map({
        'baseUrl': base_url
    })
    group_filter = request_helper.post(query_url, payload)
    assert group_filter
    assert group_filter['uuid']

    yield group_filter

    query_url = '{baseUrl}/group_filters/{groupFilterUuid}'.format_map({
        'baseUrl': base_url,
        'groupFilterUuid': group_filter['uuid']
    })
    request_helper.delete(query_url)
