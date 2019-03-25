#!/usr/bin/env python3
# -*- coding: utf-8 -*-


import configparser
import json
import logging
import requests
import unittest

from requests.auth import HTTPBasicAuth



CONFIG = configparser.ConfigParser()
CONFIG.read('linshare.admin.ini')
DEBUG = False
NO_VERIFY = False

if int(CONFIG['DEFAULT']['debug']) == 1:
    DEBUG = True
if int(CONFIG['DEFAULT']['no_verify']) == 1:
    NO_VERIFY = True

if DEBUG:
    logging.basicConfig(level=logging.DEBUG)
else:
    logging.basicConfig()
LOGGER = logging.getLogger()


class TestCase(unittest.TestCase):
    """Default test case class"""

    host = CONFIG['DEFAULT']['host']
    base_url = host + '/linshare/webservice/rest/admin'
    email = CONFIG['DEFAULT']['email']
    verify = not NO_VERIFY
    password = CONFIG['DEFAULT']['password']
    headers = {
        'Accept': 'application/json',
        'Content-Type': 'application/json'
    }

    def get_user1(self):
        """Return user info for user1"""
        query_url = self.base_url + '/users/search'
        mail = "user1@linshare.org"
        payload = {"mail": mail}
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
        user_uuid = req.json()[0]['uuid']
        user_domain = req.json()[0]['domain']
        return mail, user_uuid, user_domain

    def request_post(self, query_url, payload):
        """Do POST request"""
        req = requests.post(
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

    def request_delete(self, query_url, payload=None):
        """Do POST request"""
        data = None
        if payload:
            data = json.dumps(payload),
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


class TestAdminApiJwt(TestCase):
    """Test admin api"""

    def test_auth(self):
        """Test user authentication."""
        query_url = self.base_url + '/authentication/authorized'
        req = requests.get(
            query_url,
            headers={'Accept': 'application/json'},
            auth=HTTPBasicAuth(self.email, self.password),
            verify=self.verify)
        LOGGER.debug("status_code : %s", req.status_code)
        LOGGER.debug("result : %s", req.text)
        self.assertEqual(req.status_code, 200)
        LOGGER.debug("data : %s", req.json())

    def test_jwt_create(self):
        """Trying to create a jwt token as an admin"""

        mail, user_uuid, user_domain = self.get_user1()
        query_url = self.base_url + '/jwt'
        payload = {
            "actor": {
                "uuid": user_uuid
            },
            "description": None,
            "domain": {
                "uuid": user_domain
            },
            "label": "fred4",
            "subject": mail
        }
        data = self.request_post(query_url, payload)
        self.assertEqual(data['domain']['uuid'], user_domain)
        self.assertEqual(data['actor']['uuid'], user_uuid)
        self.assertEqual(data['label'], 'fred4')
        self.assertEqual(data['subject'], mail)
        self.assertTrue('jwtToken' in data)
        self.assertTrue('token' in data['jwtToken'])

    def test_jwt_delete(self):
        """Trying to create a jwt token as an admin"""

        mail, user_uuid, user_domain = self.get_user1()
        query_url = self.base_url + '/jwt'
        payload = {
            "actor": {
                "uuid": user_uuid
            },
            "description": None,
            "domain": {
                "uuid": user_domain
            },
            "label": "test_label_for_delete",
            "subject": mail
        }
        data = self.request_post(query_url, payload)
        uuid = data['uuid']
        data = self.request_delete(query_url + '/' + uuid)
        self.assertEqual(data['domain']['uuid'], user_domain)
        self.assertEqual(data['actor']['uuid'], user_uuid)
        self.assertEqual(data['label'], 'test_label_for_delete')
        self.assertEqual(data['subject'], mail)


if __name__ == '__main__':
    unittest.main()
