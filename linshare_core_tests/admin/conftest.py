#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Common fixtures"""


import os
import configparser
import logging
import json
import urllib
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


@pytest.fixture(scope="module", name="usersv5_base_url")
def fixture_usersv5_base_url(admin_cfg):
    """Return base URL for all tests"""
    host = admin_cfg['DEFAULT']['host']
    base_url = host + '/linshare/webservice/rest/user/v5'
    return base_url


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
            busines_err_code=None, email=None, password=None):
        """GET HTTP method"""
        # pylint: disable=too-many-arguments
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
               busines_err_code=None, email=None, password=None):
        """DELETE HTTP method"""
        # pylint: disable=too-many-arguments
        if not email:
            email = self.email
        if not password:
            password = self.password
        data = None
        if payload:
            data = json.dumps(payload)
        req = requests.delete(
            query_url,
            data=data,
            headers=self.headers,
            auth=HTTPBasicAuth(email, password),
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
            busines_err_code=None, email=None, password=None):
        """PUT HTTP method"""
        # pylint: disable=too-many-arguments
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
        self.log.debug("result : %s", req.text)
        assert req.status_code == expected_status
        data = req.json()
        self.log.debug("data : %s", json.dumps(data, sort_keys=True, indent=2))
        if busines_err_code:
            assert data['errCode'] == busines_err_code
        return data

    def patch(self, query_url, payload, expected_status=200,
              busines_err_code=None):
        """PATCH HTTP method"""
        req = requests.patch(
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


@pytest.fixture(scope="class", name="new_subdomain")
def fixture_create_subdomain(request_helper, base_url):
    """
    This fixture is design to create a subdomain of 'MyDomain'
    """
    query_url = '{baseUrl}/domains'.format_map({
        'baseUrl': base_url,
    })
    payload = {
        "parent": {"uuid": "MyDomain"},
        "type": "SUBDOMAIN",
        "name": "SubMyDomain",
        "description": "Description of sub domain"
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


@pytest.fixture(scope="class", name="new_admin")
def fixture_promote_admin(request_helper, admin_cfg, base_url,
                          usersv5_base_url):
    """Promote to admin."""
    # Create user (automatic provisioning)
    query_url = '{baseUrl}/authentication/authorized'.format_map({
        'baseUrl': usersv5_base_url
    })
    request_helper.get(query_url,
                       email=admin_cfg['DEFAULT']['user1_email'],
                       password=admin_cfg['DEFAULT']['user1_password'])

    # Load the user DTO
    encoded_url = urllib.parse.urlencode({
        "mail": admin_cfg['DEFAULT']['user1_email']
    })
    query_url = '{baseUrl}/users?{encode}'.format_map({
        'baseUrl': base_url,
        'encode': encoded_url
    })
    admins = request_helper.get(query_url)
    assert admins

    # Promote to ADMIN
    admin = admins[0]
    admin['role'] = "ADMIN"
    query_url = '{baseUrl}/users/{uuid}'.format_map({
        'baseUrl': base_url,
        'uuid': admin['uuid']
    })
    admin = request_helper.put(query_url, admin)
    assert admin

    yield admin

    admin['role'] = "SIMPLE"
    query_url = '{baseUrl}/users/{uuid}'.format_map({
        'baseUrl': base_url,
        'uuid': admin['uuid']
    })
    request_helper.put(query_url, admin)


@pytest.fixture(scope="module", name="guest_domain")
def fixture_create_guest_domain(request_helper, base_url):
    """This fixture is design to create a guest domain"""
    query_url = '{baseUrl}/domains'.format_map({
        'baseUrl': base_url,
    })
    payload = {
        "parent": {"uuid": "LinShareRootDomain"},
        "type": "GUESTDOMAIN",
        "name": "MyGuestDomain",
        "description": "Description of guest domain"
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


@pytest.fixture(scope="module", name="remote_server")
def fixture_create_remote_server(request_helper, base_url, admin_cfg):
    """Create a remote server."""
    payload = {
        "name": "new remote server",
        "serverType": "LDAP",
        "bindDn": admin_cfg['DEFAULT']['local_ldap_user_dn'],
        "url": admin_cfg['DEFAULT']['local_ldap_url'],
        "bindPassword": admin_cfg['DEFAULT']['local_ldap_password']
    }
    query_url = '{baseUrl}/remote_servers'.format_map({
        'baseUrl': base_url
    })
    server = request_helper.post(query_url, payload)
    assert server

    yield server

    query_url = '{baseUrl}/remote_servers/{uuid}'.format_map({
        'baseUrl': base_url,
        'uuid': server['uuid']
    })
    request_helper.delete(query_url)


@pytest.fixture(scope="module", name="twake_remote_server")
def fixture_create_twake_remote_server(request_helper, base_url):
    """Create a Twake remote server."""
    payload = {
        "name": "Twake connection",
        "url": "twake_url",
        "serverType": "TWAKE",
        "description": "Twake description",
        "clientId": "twakeClientId",
        "clientSecret": "twakeClientSecret"
    }
    query_url = '{baseUrl}/remote_servers'.format_map({
        'baseUrl': base_url
    })
    server = request_helper.post(query_url, payload)
    assert server

    yield server

    query_url = '{baseUrl}/remote_servers/{uuid}'.format_map({
        'baseUrl': base_url,
        'uuid': server['uuid']
    })
    request_helper.delete(query_url)


@pytest.fixture(scope="module", name="new_user_filter")
def fixture_create_user_filter(request_helper, base_url):
    """Create domain user filter."""
    auth_command = (
        "ldap.search(domain, \"(&(objectClass=inetOrgPerson) "
        "(mail=*)(givenName=*)(sn=*)(|(mail=\"+login+\") "
        "(uid=\"+login+\")))\");"
    )
    search_user_command = (
        "ldap.search(domain, "
        "\"(&(objectClass=inetOrgPerson) "
        "(mail=\"+mail+\")(givenName=\"+first_name+\") "
        "(sn=\"+last_name+\"))\");"
    )
    ac_on_all_attributes = (
        "ldap.search(domain, "
        " \"(&(objectClass=inetOrgPerson)(mail=*) "
        "(givenName=*)(sn=*) "
        "(|(mail=\" + pattern + \")(sn=\" + pattern + \") "
        "(givenName=\" + pattern + \")))\");"
    )
    ac_on_first_and_last_name = (
        "ldap.search(domain, \"(&(objectClass=inetOrgPerson)(mail=*) "
        "(givenName=*)(sn=*) "
        "(|(&(sn=\" + first_name + \") "
        "(givenName=\" + last_name + \"))"
        "(&(sn=\" + last_name + \") "
        "(givenName=\" + first_name + \"))))\");"
    )
    payload = {
        "description": "Test domain workgroup filter",
        "name": "User filter name",
        "authenticationQuery": auth_command,
        "searchUserQuery": search_user_command,
        "userMailAttribute": "mail",
        "userFirstNameAttribute": "givenName",
        "userLastNameAttribute": "sn",
        "userUidAttribute": "uid",
        "autoCompleteCommandOnAllAttributes": ac_on_all_attributes,
        "autoCompleteCommandOnFirstAndLastName": ac_on_first_and_last_name,
        "searchPageSize": 100,
        "searchSizeLimit": 100,
        "completionPageSize": 10,
        "completionSizeLimit": 10
    }
    query_url = '{baseUrl}/user_filters'.format_map({'baseUrl': base_url})
    user_filter = request_helper.post(query_url, payload)
    assert user_filter['userMailAttribute'] == "mail"

    yield user_filter

    query_url = '{baseUrl}/user_filters/{userFilterUuid}'.format_map({
        'baseUrl': base_url,
        'userFilterUuid': user_filter['uuid']
    })
    request_helper.delete(query_url)


@pytest.fixture(scope="class", name="twake_user_provider")
def fixture_create_twake_user_provider(
        request_helper, base_url, twake_remote_server, domain):
    """Create a Twake user provider."""
    query_url = '{baseUrl}/domains/{uuid}/user_providers'.format_map({
        'baseUrl': base_url,
        'uuid': domain['uuid']
    })
    payload = {
        "twakeServer": {
            "uuid": twake_remote_server['uuid'],
            "name": "Twake connection"
        },
        "twakeCompanyId": "TcId",
        "type": "TWAKE_PROVIDER"
    }
    user_provider = request_helper.post(query_url, payload)
    assert user_provider

    yield user_provider

    query_url = '{baseUrl}/domains/{uuid}/user_providers/{pid}'.format_map({
        'baseUrl': base_url,
        'uuid': domain['uuid'],
        'pid': user_provider['uuid']
    })
    request_helper.delete(query_url)


@pytest.fixture(scope="class", name="twake_guest_up")
def fixture_create_twake_guest_user_provider(
        request_helper, base_url, twake_remote_server, guest_domain):
    """Create a Twake Guest user provider."""
    query_url = '{baseUrl}/domains/{uuid}/user_providers'.format_map({
        'baseUrl': base_url,
        'uuid': guest_domain['uuid']
    })
    payload = {
        "twakeServer": {
            "uuid": twake_remote_server['uuid'],
            "name": "Twake connection"
        },
        "twakeCompanyId": "TcId",
        "type": "TWAKE_GUEST_PROVIDER"
    }
    user_provider = request_helper.post(query_url, payload)
    assert user_provider

    yield user_provider

    query_url = '{baseUrl}/domains/{uuid}/user_providers/{pid}'.format_map({
        'baseUrl': base_url,
        'uuid': guest_domain['uuid'],
        'pid': user_provider['uuid']
    })
    request_helper.delete(query_url)
