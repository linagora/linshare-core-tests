#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""TODO"""
# pylint: disable=too-many-lines


import configparser
import json
import logging
import os
import sys
import unittest
import urllib
import requests

from requests.auth import HTTPBasicAuth
from requests_toolbelt.utils import dump
from requests_toolbelt import (MultipartEncoder, MultipartEncoderMonitor)
from clint.textui.progress import Bar as ProgressBar

CONFIG_FILE_ADMIN = os.getenv('CONFIG_FILE_ADMIN', None)
if not CONFIG_FILE_ADMIN:
    CONFIG_FILE_ADMIN = 'linshare.admin.ini'
CONFIG_FILE_USER = os.getenv('CONFIG_FILE_USER', None)
if not CONFIG_FILE_USER:
    CONFIG_FILE_USER = 'linshare.user.ini'

# Import the global configuration
CONFIG = configparser.ConfigParser()
CONFIG.read(CONFIG_FILE_ADMIN)
DEBUG = False
NO_VERIFY = False

if int(CONFIG['DEFAULT']['debug']) == 1:
    DEBUG = True
if os.getenv('LS_TEST_DEBUG', None):
    DEBUG=True

if int(CONFIG['DEFAULT']['no_verify']) == 1:
    NO_VERIFY = True

if DEBUG:
    logging.basicConfig(level=logging.DEBUG)
else:
    logging.basicConfig()
LOGGER = logging.getLogger()

# Import the configuration related to LinShare user API
CONFIG_USER = configparser.ConfigParser()
CONFIG_USER.read(CONFIG_FILE_USER)

class AbstractTestCase(unittest.TestCase):
    host = CONFIG['DEFAULT']['host']
    base_url = host + '/linshare/webservice/rest/admin'
    base_url_v4 = host + '/linshare/webservice/rest/admin/v4'
    base_admin_v5_url = host + '/linshare/webservice/rest/admin/v5'
    email = CONFIG['DEFAULT']['email']
    password = CONFIG['DEFAULT']['password']
    verify = not NO_VERIFY
    headers = {
        'Accept': 'application/json',
        'Content-Type': 'application/json'
    }

    def request_get(self, query_url):
        """GET request"""
        req = requests.get(
            query_url,
            headers=self.headers,
            auth=HTTPBasicAuth(self.email, self.password),
            verify=self.verify
        )
        self.assertEqual(req.status_code, 200)
        LOGGER.debug("status_code : %s", req.status_code)
        data = req.json()
        LOGGER.debug("data : %s", json.dumps(req.json(), sort_keys=True, indent=2))
        return data

    def request_head(self, query_url):
        """HEAD request"""
        req = requests.head(
            query_url,
            headers=self.headers,
            auth=HTTPBasicAuth(self.email, self.password),
            verify=self.verify
        )
        self.assertEqual(req.status_code, 200)
        LOGGER.debug("status_code : %s", req.status_code)


    def _assertJsonPayload(self, expected, payloadResponse):
        """Method that allows to assert information returned on the responses
        Parameters:
        expected: list of expected fields in the source object.
        payloadResponse : returned object to be tested.
         """
        allFieldsExists = True
        for item in payloadResponse:
            if item not in expected:
                allFieldsExists = False
                LOGGER.error(" %s does not exists in the expected payload", item)

        self.assertTrue(allFieldsExists, " List of expected fields is different with response field's")
        self.assertEqual(len(expected), len(payloadResponse.keys()))

    def request_post(self, query_url, payload, headers=None, expected_status=200, busines_err_code=None):
        """Do POST request"""
        if not headers:
            headers = self.headers
        if (headers['Content-Type'] != 'application/json'):
            body = payload
        else:
            body=json.dumps(payload)
        req = requests.post(
            query_url,
            headers=headers,
            data=body,
            auth=HTTPBasicAuth(self.email, self.password),
            verify=self.verify)
        LOGGER.debug("status_code : %s", req.status_code)
        LOGGER.debug("result : %s", req.text)
        self.assertEqual(req.status_code, expected_status)
        data = req.json()
        LOGGER.debug("data : %s", json.dumps(data, sort_keys=True, indent=2))
        if busines_err_code:
            self.assertEqual (data['errCode'], busines_err_code)
        return data

    def request_delete(self, query_url, payload=None):
        """Do POST request"""
        data = None
        if payload:
            data = json.dumps(payload)
        req = requests.delete(
            query_url,
            data=data,
            headers=self.headers,
            auth=HTTPBasicAuth(self.email, self.password),
            verify=self.verify)
        LOGGER.debug("status_code : %s", req.status_code)
        LOGGER.debug("result : %s", req.text)
        self.assertEqual(req.status_code, 200)
        data = req.json()
        LOGGER.debug("data : %s", json.dumps(data, sort_keys=True, indent=2))
        return data

    def request_put(self, query_url, payload=None, expected_status=200, busines_err_code=None):
        """Do PUT request"""
        req = requests.put(
            query_url,
            data=json.dumps(payload),
            headers=self.headers,
            auth=HTTPBasicAuth(self.email, self.password),
            verify=self.verify)
        LOGGER.debug("status_code : %s", req.status_code)
        LOGGER.debug("result : %s", req.text)
        self.assertEqual(req.status_code, expected_status)
        data = req.json()
        LOGGER.debug("data : %s", json.dumps(data, sort_keys=True, indent=2))
        if busines_err_code:
            self.assertEqual (data['errCode'], busines_err_code)
        return data

    def request_patch(self, query_url, payload):
        req = requests.patch(
            query_url,
            data=json.dumps(payload),
            headers=self.headers,
            auth=HTTPBasicAuth(self.email, self.password),
            verify=self.verify)
        LOGGER.debug("status_code : %s", req.status_code)
        LOGGER.debug("result : %s", req.text)
        self.assertEqual(req.status_code, 200)
        data = req.json()
        LOGGER.debug("data : %s", json.dumps(data, sort_keys=True, indent=2))
        return data


class PatchTestCase(AbstractTestCase):
    """Default test case class"""
    user1_email = CONFIG['DEFAULT']['user1_email']
    user1_password = CONFIG['DEFAULT']['user1_password']
    user_base_url = AbstractTestCase.host + '/linshare/webservice/rest/user/v2'
    local_ldap_url=CONFIG['DEFAULT']['local_ldap_url']
    local_ldap_user_dn=CONFIG['DEFAULT']['local_ldap_user_dn']
    local_ldap_password=CONFIG['DEFAULT']['local_ldap_password']
    local_ldap_group_base_dn=CONFIG['DEFAULT']['local_ldap_group_base_dn']
    default_drive_pattern=CONFIG['DEFAULT']['default_drive_pattern']

    def get_user1(self):
        """Return user info for user1"""
        query_url = self.base_url + '/users/search'
        payload = {"mail": self.user1_email}
        req = requests.post(
            query_url,
            data=json.dumps(payload),
            headers=self.headers,
            auth=HTTPBasicAuth(self.email, self.password),
            verify=self.verify)
        LOGGER.debug("status_code : %s", req.status_code)
        LOGGER.debug("result : %s", req.text)
        self.assertEqual(req.status_code, 200)
        LOGGER.debug("data : %s", req.json())
        if not req.json():
            LOGGER.error("invalid user email. can't find : %s", self.user1_email)
            data = self.request_get(self.base_url + '/ldap_connections')
            LOGGER.error(data)
            data = self.request_get(self.base_url + '/domains')
            LOGGER.error(data)
            sys.exit(1)
        user1 = req.json()[0]
        query_url = self.base_url + '/users/' + req.json()[0]['uuid']
        req = requests.head(
            query_url,
            headers=self.headers,
            auth=HTTPBasicAuth(self.email, self.password),
            verify=self.verify)
        LOGGER.debug("status_code : %s", req.status_code)
        LOGGER.debug("result : %s", req.text)
        if req.status_code == 204:
            # user already exists
            return user1
        else:
            LOGGER.debug("user1 : %s", user1)
            query_url = self.base_url + '/users'
            req = requests.post(
                query_url,
                data=json.dumps(user1),
                headers=self.headers,
                auth=HTTPBasicAuth(self.email, self.password),
                verify=self.verify)
            LOGGER.debug("status_code : %s", req.status_code)
            LOGGER.debug("result : %s", req.text)
            self.assertEqual(req.status_code, 200)
            return req.json()

    def test_patch_ldap(self):
        data = self.request_get(self.base_url + '/ldap_connections')
        ldap_host = os.getenv("LDAP_PORT_1636_TCP_ADDR", None)
        if not ldap_host:
            LOGGER.warning("Patching ldap host ignored, env variable LDAP_PORT_1636_TCP_ADDR not found")
            return True
        ldap_uri = 'ldap://' + ldap_host  + ':1389'
        LOGGER.info("ldap uri: %s", ldap_uri)
        for ldap in data:
            if ldap['providerUrl'] == 'ldap://ldap:1389':
                ldap['providerUrl'] = ldap_uri
                self.request_put(self.base_url + '/ldap_connections', ldap)

if __name__ == '__main__':
    unittest.main()
