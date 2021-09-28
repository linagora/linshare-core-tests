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

def create_callback(encoder):
    """TODO"""
    encoder_len = encoder.len
    bar = ProgressBar(expected_size=encoder_len, filled_char='=')
    def callback(monitor):
        bar.show(monitor.bytes_read)
    return callback

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
        """HEAD request Returns HTTP Response"""
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


class AdminTestCase(AbstractTestCase):
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


class UserTestCase(AbstractTestCase):
    host = CONFIG_USER['DEFAULT']['host']
    base_url = host + '/linshare/webservice/rest/user/v4'
    base_url_v2 = host + '/linshare/webservice/rest/user/v2'
    base_test_url = host + '/linshare/webservice/rest/test/user/v4'
    base_test_upload_request_url = host + '/linshare/webservice/rest/uploadrequest/v4/flow/upload'
    base_external_url = host + '/linshare/webservice/rest/uploadrequest/v4'
    email = CONFIG_USER['DEFAULT']['email']
    password = CONFIG_USER['DEFAULT']['password']
    amy_email = CONFIG_USER['DEFAULT']['amy_email']
    email_external1 = CONFIG_USER['DEFAULT']['email_external1']
    password_external1 = CONFIG_USER['DEFAULT']['password_external1']
    email_external2 = CONFIG_USER['DEFAULT']['email_external2']
    password_external2 = CONFIG_USER['DEFAULT']['password_external2']
    email_external3 = CONFIG_USER['DEFAULT']['email_external3']
    email_external4 = CONFIG_USER['DEFAULT']['email_external4']
    shared_space_kind = "SHARED_SPACE"
    def currentUser(self):
        """Return user info for the current user"""
        query_url = self.base_url + '/authentication/authorized'
        req = requests.get(
            query_url,
            headers=self.headers,
            auth=HTTPBasicAuth(self.email, self.password),
            verify=self.verify)
        self.assertEqual(req.status_code, 200)
        LOGGER.debug("data : %s", req.json())
        return req.json()

    def get_user1(self):
        """Return user info for user1"""
        parameters = {
            'host': AbstractTestCase.host
            }
        query_url = '{host}/linshare/webservice/rest/admin/users/search'.format_map(parameters)
        payload = {"mail": AdminTestCase.user1_email}
        req = requests.post(
            query_url,
            data=json.dumps(payload),
            headers=self.headers,
            auth=HTTPBasicAuth('root@localhost.localdomain', 'adminlinshare'),
            verify=self.verify)
        LOGGER.debug("status_code : %s", req.status_code)
        LOGGER.debug("result : %s", req.text)
        self.assertEqual(req.status_code, 200)
        LOGGER.debug("data : %s", req.json())
        if not req.json():
            LOGGER.error("invalid user email. can't find : %s", AdminTestCase.user1_email)
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
            url = '{host}/linshare/webservice/rest/admin/users'.format_map(parameters)
            req = requests.post(
                url,
                data=json.dumps(user1),
                headers=self.headers,
                auth=HTTPBasicAuth('root@localhost.localdomain', 'adminlinshare'),
                verify=self.verify)
            LOGGER.debug("status_code : %s", req.status_code)
            LOGGER.debug("result : %s", req.text)
            self.assertEqual(req.status_code, 200)
            return req.json()

    def get_user(self, user_name="peter"):
        """
        Return user giving the user_name parameter
        """
        parameters = {
            'host': AbstractTestCase.host
            }
        user_email = self.email
        if user_name == "amy":
            user_email = self.amy_email
        query_url = '{host}/linshare/webservice/rest/admin/users/search'.format_map(parameters)
        payload = {"mail": user_email}
        req = requests.post(
            query_url,
            data=json.dumps(payload),
            headers=self.headers,
            auth=HTTPBasicAuth('root@localhost.localdomain', 'adminlinshare'),
            verify=self.verify)
        LOGGER.debug("status_code : %s", req.status_code)
        LOGGER.debug("result : %s", req.text)
        self.assertEqual(req.status_code, 200)
        LOGGER.debug("data : %s", req.json())
        if not req.json():
            LOGGER.error("invalid user email. can't find : %s", user_email)
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
            url = '{host}/linshare/webservice/rest/admin/users'.format_map(parameters)
            req = requests.post(
                url,
                data=json.dumps(user1),
                headers=self.headers,
                auth=HTTPBasicAuth('root@localhost.localdomain', 'adminlinshare'),
                verify=self.verify)
            LOGGER.debug("status_code : %s", req.status_code)
            LOGGER.debug("result : %s", req.text)
            self.assertEqual(req.status_code, 200)
            return req.json()

    def getRole(self, roleName):
        """Return user info for the current user"""
        parameters = {
            'base_url': self.base_url,
            'name':roleName
            }
        url = '{base_url}/shared_space_roles/role/{name}'.format_map(parameters)
        req = requests.get(
            url,
            headers=self.headers,
            auth=HTTPBasicAuth(self.email, self.password),
            verify=self.verify)
        self.assertEqual(req.status_code, 200)
        LOGGER.debug("data : %s", req.json())
        return req.json()

    def upload_upload_request_entry(self, email, password,request_url_uuid):
        """method to upload an entry on upload request"""
        query_url = self.base_test_upload_request_url
        file_path = 'file10M'
        filesize = os.path.getsize(file_path)
        with open(file_path, 'rb') as file_stream:
            encoder = MultipartEncoder(
                fields={
                    'flowTotalChunks' : '1',
                    'flowChunkSize': str(filesize),
                    'flowTotalSize': str(filesize),
                    'file': ('file10M.new', file_stream),
                    'flowIdentifier' : 'entry',
                    'flowFilename' : 'file10M',
                    "flowRelativePath" : file_path,
                    'requestUrlUuid' : request_url_uuid,
                    'password' : '',
                    'body':'Test upload an upload request entry',
                    'flowChunkNumber':'1'
                }
            )
            monitor = MultipartEncoderMonitor(encoder, create_callback(encoder))
            headers = {
                'Accept': 'application/json',
                'Content-Type': monitor.content_type
            }
            req = requests.post(
                query_url,
                data=monitor,
                headers=headers,
                auth=HTTPBasicAuth(email, password),
                verify=self.verify)
        self.assertEqual(req.status_code, 200)
        LOGGER.debug("status_code : %s", req.status_code)
        LOGGER.debug("result : %s", req.text)
@unittest.skip
class TestAdminApiJwt(AdminTestCase):
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

    def create_simple_jwt(self):
        """Trying to create a simple jwt token as an admin"""
        user1 = self.get_user1()
        query_url = self.base_url + '/jwt'
        payload = {
            "actor": {
                "uuid": user1['uuid']
            },
            "description": None,
            "label": "fred4",
        }
        data = self.request_post(query_url, payload)
        return data

    def test_jwt_create(self):
        """Trying to create a jwt token as an admin"""
        user1 = self.get_user1()
        query_url = self.base_url + '/jwt'
        payload = {
            "actor": {
                "uuid": user1['uuid']
            },
            "description": None,
            "label": "fred4",
        }
        data = self.request_post(query_url, payload)
        self.assertEqual(data['domain']['uuid'], user1['domain'])
        self.assertEqual(data['actor']['uuid'], user1['uuid'])
        self.assertIsNotNone(data['description'])
        self.assertEqual(data['label'], 'fred4')
        self.assertEqual(data['subject'], user1['mail'])
        self.assertTrue('token' in data)

    def test_jwt_delete(self):
        """Trying to create and delete a jwt token as an admin"""
        user1 = self.get_user1()
        query_url = self.base_url + '/jwt'
        payload = {
            "actor": {
                "uuid": user1['uuid']
            },
            "description": None,
            "domain": {
                "uuid": user1['domain']
            },
            "label": "test_label_for_delete",
            "subject": user1['mail']
        }
        data = self.request_post(query_url, payload)
        uuid = data['uuid']
        req = requests.delete(
            query_url + '/' + uuid,
            data=json.dumps(None),
            headers = self.headers,
            auth=HTTPBasicAuth(self.email, self.password),
            verify=self.verify)
        self.assertEqual(data['domain']['uuid'], user1['domain'])
        self.assertEqual(data['actor']['uuid'], user1['uuid'])
        self.assertEqual(data['label'], 'test_label_for_delete')
        self.assertEqual(data['subject'], user1['mail'])

    def test_jwt_update(self):
        """Trying create and update a jwt token as an admin"""
        user1 = self.get_user1()
        query_url = self.base_url + '/jwt'
        payload = {
            "actor": {
                "uuid": user1['uuid']
            },
            "description": "jwt description",
            "label": "fred4",
        }
        data = self.create_simple_jwt()
        uuid = data['uuid']
        data = self.request_put(query_url + '/' + uuid, payload)
        self.assertEqual(data['description'], 'jwt description')

class TestAdminV5ApiUsers(AdminTestCase):
    def test_findAll_users(self):
        query_url = '{baseUrl}/users'.format_map({
            'baseUrl' : self.base_admin_v5_url})
        self.request_get(query_url)
    def test_find_user(self):
        query_url = '{baseUrl}/users/{user1_uuid}'.format_map({
            'baseUrl' : self.base_admin_v5_url,
            'user1_uuid' : self.get_user1()["uuid"]})
        return self.request_get(query_url)

    def test_find_user_quota(self):
        user1 = self.test_find_user()
        query_url = '{baseUrl}/users/{user1_uuid}/quota/{user_quota_uuid}'.format_map({
            'baseUrl': self.base_admin_v5_url,
            'user1_uuid': user1["uuid"],
            'user_quota_uuid': user1["quotaUuid"]})
        data = self.request_get(query_url)
        self._assertJsonPayload(['account', 'creationDate', 'defaultMaxFileSize', 'defaultQuota', 'maintenance', 'maxFileSize',
                                 'maxFileSizeOverride', 'modificationDate', 'quota', 'quotaOverride', 'realTimeUsedSpace', 'usedSpace', 'uuid', 'yesterdayUsedSpace'],
                                 data)
        return data

    def test_update_user_quota_null_payload(self):
        # update quota with a payload that have no fields
        quota_user1 = self.test_find_user_quota()
        query_url = '{baseUrl}/users/{user1_uuid}/quota/{user_quota_uuid}'.format_map({
            'baseUrl': self.base_admin_v5_url,
            'user1_uuid': quota_user1["account"]["uuid"],
            'user_quota_uuid': quota_user1["uuid"]})
        payload = {
        }
        data = self.request_put(query_url, payload, expected_status=400, busines_err_code=20005)

    def test_update_user_quota(self):
        quota_user1 = self.test_find_user_quota()
        query_url = '{baseUrl}/users/{user1_uuid}/quota/{user_quota_uuid}'.format_map({
            'baseUrl': self.base_admin_v5_url,
            'user1_uuid': quota_user1["account"]["uuid"],
            'user_quota_uuid': quota_user1["uuid"]})
        payload = {
            'quota': 9000000
        }
        data = self.request_put(query_url, payload)
        self._assertJsonPayload(['account', 'creationDate', 'defaultMaxFileSize', 'defaultQuota', 'maintenance', 'maxFileSize',
                                 'maxFileSizeOverride', 'modificationDate', 'quota', 'quotaOverride', 'realTimeUsedSpace', 'usedSpace', 'uuid', 'yesterdayUsedSpace'],
                                 data)
        self.assertEqual(data["quota"], 9000000)
        
class TestAdminApiFunctionalites(AdminTestCase):
    """Class for tests on API V4 """
    identifier_integer = 'UPLOAD_REQUEST__MAXIMUM_FILE_COUNT'
    identifier_unit = 'UPLOAD_REQUEST__DELAY_BEFORE_ACTIVATION'
    encoded_url = urllib.parse.urlencode({'domainId': "LinShareRootDomain"})
    def test_find_all_functionalites(self):
        """Test find all functionlaties for root domain on API v4"""
        query_url = '{baseUrl}/functionalities?{encode}'.format_map({
            'baseUrl' : self.base_url_v4,
            'encode': self.encoded_url})
        data = self.request_get(query_url)
        self.assertTrue(data)
        return data

    def test_find_functionality_integer_type(self):
        """Test find a functionality Integer type for a Admin API V4"""
        query_url = '{base_url}/functionalities/{identifier}?{encode}'.format_map({
            'base_url': self.base_url_v4,
            'identifier' : self.identifier_integer,
            'encode' : self.encoded_url
            })
        data = self.request_get(query_url)
        self._assertJsonPayload(['integer', 'maxInteger', 'string', 'bool', 'defaultValueUsed','maxValueUsed','type', 'select'], data['parameters'][0])
        return data

    def test_find_functionality_integer_type_admin_v1(self):
        """Test find a functionality Integer type for a Admin API V1
        Avoid to not expose filed maxInteger"""
        query_url = '{base_url}/functionalities/{identifier}?{encode}'.format_map({
            'base_url': self.base_url,
            'identifier' : self.identifier_integer,
            'encode' : self.encoded_url
            })
        data = self.request_get(query_url)
        # Expected to not expose the field `maxInteger` on the old API
        self._assertJsonPayload(['integer', 'string', 'bool', 'type', 'select'], data['parameters'][0])
        return data

    def test_find_functionality_unit_type(self):
        """Test find a functionality Unit type for a Admin API V4"""
        query_url = '{base_url}/functionalities/{identifier}?{encode}'.format_map({
            'base_url': self.base_url_v4,
            'identifier' : self.identifier_unit,
            'encode' : self.encoded_url
            })
        data = self.request_get(query_url)
        self._assertJsonPayload(['integer', 'maxInteger','maxString','string', 'defaultValueUsed','maxValueUsed','bool', 'type', 'select'], data['parameters'][0])
        return data

    def test_find_functionality_unit_type_admin_v1(self):
        """Test find a functionality Unit type for a Admin API V1
        Avoid to not expose filed maxInteger and maxString"""
        query_url = '{base_url}/functionalities/{identifier}?{encode}'.format_map({
            'base_url': self.base_url,
            'identifier' : self.identifier_unit,
            'encode' : self.encoded_url
            })
        data = self.request_get(query_url)
        # Expected to not expose the field `maxString` and `maxInteger` on the old API
        self._assertJsonPayload(['integer', 'string', 'bool', 'type', 'select'], data['parameters'][0])
        return data

    def test_update_functionality_integer_type(self):
        """ Test update a functionality Integer type in admin V4 """
        recovered_func = self.test_find_functionality_integer_type()
        query_url = '{baseUrl}/functionalities'.format_map({'baseUrl' : self.base_url_v4 })
        recovered_func['parameters'][0]['maxInteger'] = 15
        recovered_func['parameters'][0]['integer'] = 12
        data = self.request_put(query_url, recovered_func)
        self.assertEqual(15, data['parameters'][0]['maxInteger'], 'Updating maxInteger parameter of functionality Integer type has failed | expected maxInteger = {} but was {}'.format(15, data['parameters'][0]['maxInteger']))
        self.assertEqual(12, data['parameters'][0]['integer'], 'Updating integer parameter of functionality Integer type has failed | expected integer = {} but was {}'.format(12, data['parameters'][0]['integer']))

    def test_update_functionality_integer_type_admin_v1(self):
        """ Test update a functionality Integer type in admin V1 """
        recovered_func = self.test_find_functionality_integer_type_admin_v1()
        recovered_func['parameters'][0]['integer'] = 20
        query_url = '{baseUrl}/functionalities'.format_map({'baseUrl' : self.base_url })
        data = self.request_put(query_url, recovered_func )
        self.assertEqual(20, data['parameters'][0]['integer'], 'Updating integer parameter of functionality Integer type has failed | expected integer = {}'.format(20))

    def test_update_functionality_unit_type(self):
        """"Test update functionality Unit type on Admin V4"""
        recovered_func = self.test_find_functionality_unit_type()
        query_url = '{baseUrl}/functionalities'.format_map({'baseUrl' : self.base_url_v4 })
        recovered_func ['parameters'][0]['integer'] = 1
        recovered_func ['parameters'][0]['maxInteger'] = 2
        recovered_func ['parameters'][0]['string'] = 'DAY'
        recovered_func ['parameters'][0]['maxString'] = 'WEEK'
        data = self.request_put(query_url, recovered_func)
        self.assertEqual(1, data['parameters'][0]['integer'], 'Updating integer parameter of functionality unit type has failed | expected integer = {} but was {}'.format(1, data['parameters'][0]['integer']))
        self.assertEqual(2, data['parameters'][0]['maxInteger'], 'Updating maxInteger parameter of functionality unit type has failed | expected maxInteger = {} but was {}'.format(2, data['parameters'][0]['maxInteger']))
        self.assertEqual('DAY', data['parameters'][0]['string'], 'Updating string parameter of functionality unit type has failed | expected string = {} but was {}'.format('DAY', data['parameters'][0]['string']))
        self.assertEqual('WEEK', data['parameters'][0]['maxString'], 'Updating maxString parameter of functionality unit type has failed | expected maxString = {} but was {}'.format('WEEK', data['parameters'][0]['maxString']))

    def test_update_functionality_unit_type_admin_v1(self):
        """"Test update functionality Unit type on Admin V1"""
        recovered_func = self.test_find_functionality_unit_type_admin_v1()
        recovered_func['parameters'][0]['integer'] = 3
        recovered_func['parameters'][0]['string'] = 'MONTH'
        query_url = '{baseUrl}/functionalities'.format_map({'baseUrl' : self.base_url })
        data = self.request_put(query_url, recovered_func)
        self.assertEqual(3, data['parameters'][0]['integer'], 'Updating integer parameter of functionality unit type has failed | expected integer = {} but was {}'.format(3, data['parameters'][0]['integer']))
        self.assertEqual('MONTH', data['parameters'][0]['string'], 'Updating string parameter of functionality unit type has failed | expected string = {} but was {}'.format('MONTH', data['parameters'][0]['string']))


class TestUserApiDocuments(AdminTestCase):
    """Test user api"""

    host = CONFIG['DEFAULT']['host']
    base_url = host + '/linshare/webservice/rest/user/v2'

    def test_documents_upload(self):
        """testing upload document"""
        query_url = self.base_url + '/documents'
        file_path = 'README.md'
        with open(file_path, 'rb') as file_stream:
            payload = {
                'file': ('README.md2', file_stream),
                'filesize': os.path.getsize(file_path)
            }
            headers = {
                'Accept': 'application/json',
            }
            req = requests.post(
                query_url,
                files=payload,
                headers=headers,
                auth=HTTPBasicAuth(self.email, self.password),
                verify=self.verify)
        if DEBUG:
            # https://toolbelt.readthedocs.io/en/latest/dumputils.html
            data = dump.dump_all(req)
            LOGGER.debug("dump_all : %s", data.decode('utf-8'))
        LOGGER.debug("status_code : %s", req.status_code)
        LOGGER.debug("result : %s", req.text)
        self.assertEqual(req.status_code, 200)
        data = req.json()
        LOGGER.debug("data : %s", json.dumps(data, sort_keys=True, indent=2))
        return data

    def test_document_upload_multipart(self):
        """testing upload document using multipart"""
        base_url = self.host + '/linshare/webservice/rest/user/v2'
        query_url = base_url + '/documents'
        file_path = 'file10M'
        filesize = os.path.getsize(file_path)
        with open(file_path, 'rb') as file_stream:
            encoder = MultipartEncoder(
                fields={
                    'filesize': str(filesize),
                    'file': ('file10M.new', file_stream)
                }
            )
            monitor = MultipartEncoderMonitor(encoder, create_callback(encoder))
            headers = {
                'Accept': 'application/json',
                'Content-Type': monitor.content_type
            }
            req = requests.post(
                query_url,
                data=monitor,
                headers=headers,
                auth=HTTPBasicAuth(self.email, self.password),
                verify=self.verify)
        if DEBUG:
            # https://toolbelt.readthedocs.io/en/latest/dumputils.html
            data = dump.dump_all(req)
            LOGGER.debug("dump_all : %s", data.decode('utf-8'))
        LOGGER.debug("status_code : %s", req.status_code)
        LOGGER.debug("result : %s", req.text)
        self.assertEqual(req.status_code, 200)
        data = req.json()
        LOGGER.debug("data : %s", json.dumps(data, sort_keys=True, indent=2))
        return data


class TestMailAttachment(AdminTestCase):

    EXPECTED_FIELD_LIST = ['uuid', 'enable', 'enableForAll', 'language', 'description', 'name', 'cid']

    def test_mail_attachments_create(self):
        """Trying to create a mail attachment as an admin"""
        query_url = self.base_url + '/mail_attachments'
        file_path = 'LinShare.jpg'
        filesize = os.path.getsize(file_path)
        with open(file_path, 'rb') as file_stream:
            encoder = MultipartEncoder(
                fields={
                    'filesize': str(filesize),
                    'file': ('LinShare.jpg', file_stream),
                    'description': 'Test mail attachment',
                    'enableForAll': 'True',
                    'enable':'True',
                    'mail_config':'946b190d-4c95-485f-bfe6-d288a2de1edd',
                    'cid':'logo.linshare@linshare.org',
                    'language' : 'ENGLISH'
                }
            )
            monitor = MultipartEncoderMonitor(encoder, create_callback(encoder))
            headers = {
                'Accept': 'application/json',
                'Content-Type': monitor.content_type
            }
            data = self.request_post(query_url, monitor, headers)
            self.assertEqual(True, data['enableForAll'])
            self.assertEqual(True, data['enable'])
        return data

    def test_mail_attachments_fail_create(self):
        """Trying to create a mail attachment as an admin"""
        query_url = self.base_url + '/mail_attachments'
        file_path = 'file10M'
        filesize = os.path.getsize(file_path)
        with open(file_path, 'rb') as file_stream:
            encoder = MultipartEncoder(
                fields={
                    'filesize': str(filesize),
                    'file': ('file10M', file_stream),
                    'description': 'Test mail attachment',
                    'enableForAll': 'False',
                    'enable':'True',
                    'mail_config':'946b190d-4c95-485f-bfe6-d288a2de1edd',
                    'cid':'logo.mail.attachment.test',
                    'language' : 'FRENCH'
                }
            )
            monitor = MultipartEncoderMonitor(encoder, create_callback(encoder))
            headers = {
                'Accept': 'application/json',
                'Content-Type': monitor.content_type
            }
            req = requests.post(
                query_url,
                data=monitor,
                headers=headers,
                auth=HTTPBasicAuth(self.email, self.password),
                verify=self.verify)
            if DEBUG:
            # https://toolbelt.readthedocs.io/en/latest/dumputils.html
                data = dump.dump_all(req)
                LOGGER.debug("dump_all : %s", data.decode('utf-8'))
        LOGGER.debug("status_code : %s", req.status_code)
        LOGGER.debug("result : %s", req.text)
        self.assertEqual(req.status_code, 400)
        data = req.json()
        LOGGER.debug("data : %s", json.dumps(data, sort_keys=True, indent=2))
        return data

    def test_mail_attachments_create_no_cid(self):
        """Trying to create a mail attachment as an admin without cid"""
        query_url = self.base_url + '/mail_attachments'
        default_mail_attachment_cid = 'logo.linshare@linshare.org'
        file_path = 'LinShare.jpg'
        filesize = os.path.getsize(file_path)
        with open(file_path, 'rb') as file_stream:
            encoder = MultipartEncoder(
                fields={
                    'filesize': str(filesize),
                    'file': ('LinShare.jpg', file_stream),
                    'description': 'Test mail attachment',
                    'enableForAll': 'False',
                    'enable':'True',
                    'mail_config':'946b190d-4c95-485f-bfe6-d288a2de1edd',
                    'language' : 'ENGLISH'
                }
            )
            monitor = MultipartEncoderMonitor(encoder, create_callback(encoder))
            headers = {
                'Accept': 'application/json',
                'Content-Type': monitor.content_type
            }
            req = requests.post(
                query_url,
                data=monitor,
                headers=headers,
                auth=HTTPBasicAuth(self.email, self.password),
                verify=self.verify)
            if DEBUG:
            # https://toolbelt.readthedocs.io/en/latest/dumputils.html
                data = dump.dump_all(req)
                LOGGER.debug("dump_all : %s", data.decode('utf-8'))
        LOGGER.debug("status_code : %s", req.status_code)
        LOGGER.debug("result : %s", req.text)
        self.assertEqual(req.status_code, 200)
        data = req.json()
        self.assertEqual(data['cid'], default_mail_attachment_cid)
        LOGGER.debug("data : %s", json.dumps(data, sort_keys=True, indent=2))
        return data

    def test_mail_attachments_create_no_optional_fields(self):
        """Trying to create a mail attachment as an admin without cid"""
        query_url = self.base_url + '/mail_attachments'
        default_mail_attachment_cid = 'logo.linshare@linshare.org'
        file_path = 'LinShare.jpg'
        filesize = os.path.getsize(file_path)
        with open(file_path, 'rb') as file_stream:
            encoder = MultipartEncoder(
                fields={
                    'filesize': str(filesize),
                    'file': ('LinShare.jpg', file_stream),
                    'enableForAll': 'False',
                    'enable':'True',
                    'mail_config':'946b190d-4c95-485f-bfe6-d288a2de1edd',
                }
            )
            monitor = MultipartEncoderMonitor(encoder, create_callback(encoder))
            headers = {
                'Accept': 'application/json',
                'Content-Type': monitor.content_type
            }
            req = requests.post(
                query_url,
                data=monitor,
                headers=headers,
                auth=HTTPBasicAuth(self.email, self.password),
                verify=self.verify)
            if DEBUG:
            # https://toolbelt.readthedocs.io/en/latest/dumputils.html
                data = dump.dump_all(req)
                LOGGER.debug("dump_all : %s", data.decode('utf-8'))
        LOGGER.debug("status_code : %s", req.status_code)
        LOGGER.debug("result : %s", req.text)
        self.assertEqual(req.status_code, 200)
        data = req.json()
        self.assertEqual(data['cid'], default_mail_attachment_cid)
        self.assertEqual(data['description'], '')
        self.assertEqual(data['language'], 'ENGLISH')

        LOGGER.debug("data : %s", json.dumps(data, sort_keys=True, indent=2))
        return data

    def test_mail_attachment_find(self):
        """Trying to create and find a mail attachment as an admin"""
        query_url = self.base_url + '/mail_attachments'
        data = self.test_mail_attachments_create()
        uuid = data['uuid']
        req = requests.get(
            query_url + '/' + uuid,
            headers=self.headers,
            auth=HTTPBasicAuth(self.email, self.password),
            verify=self.verify)
        LOGGER.debug("status_code : %s", req.status_code)
        LOGGER.debug("result : %s", req.text)
        self.assertEqual(req.status_code, 200)
        self.assertEqual(data['description'], 'Test mail attachment')
        self.assertEqual(data['enableForAll'], True)
        self.assertEqual(data['enable'], True)

    def test_mail_attachment_delete_with_payload(self):
        """Test delete a mail attachment as an admin"""
        data = self.test_mail_attachments_create()
        payload = {
            'uuid': data['uuid']
        }
        query_url = '{base_url}/mail_attachments'.format_map({
            'base_url': self.base_url,
            })
        data = self.request_delete(query_url, payload)
        self.assertEqual(data['description'], 'Test mail attachment')
        self.assertEqual(data['enableForAll'], True)
        self.assertEqual(data['enable'], True)
        return data

    def test_mail_attachment_delete_no_payload(self):
        """Trying to create and delete a mail attachment as an admin"""
        query_url = self.base_url + '/mail_attachments'
        data = self.test_mail_attachments_create()
        uuid = data['uuid']
        req = requests.delete(
            query_url + '/' + uuid,
            headers = self.headers,
            auth=HTTPBasicAuth(self.email, self.password),
            verify=self.verify)
        self.assertEqual(req.status_code, 200)
        data = req.json()
        self.assertEqual(data['description'], 'Test mail attachment')
        self.assertEqual(data['enableForAll'], True)
        self.assertEqual(data['enable'], True)
        return data

    def test_mail_attachment_update(self):
        """Trying to create and update a mail attachment as an admin"""
        query_url = self.base_url + '/mail_attachments'
        data = self.test_mail_attachments_create()
        uuid = data['uuid']
        payload = {
            'name': 'Hello LinShare',
            'description': 'Test mail attachment update',
            'enableForAll': 'True',
            'enable':'False',
            'cid':'logo.mail.attachment.test',
            'language' : 'ENGLISH'
        }
        req = requests.put(
            query_url + '/' + uuid,
            data=json.dumps(payload),
            headers = self.headers,
            auth=HTTPBasicAuth(self.email, self.password),
            verify=self.verify)
        self.assertEqual(req.status_code, 200)
        data = req.json()
        self.assertEqual(data['description'], 'Test mail attachment update')
        self.assertEqual(data['enableForAll'], True)
        self.assertEqual(data['enable'], False)
        self.assertEqual(data['language'], 'ENGLISH')
        return data

    def test_findAll(self):
        """Test find all mail attachments"""
        query_url = self.base_url + '/mail_attachments?configUuid=946b190d-4c95-485f-bfe6-d288a2de1edd'
        mail_attachments = self.request_get(query_url)
        return mail_attachments

    def test_findAll_without_configUuid(self):
        """Test find all mail attachments without set configUuid."""
        query_url = '{baseUrl}/mail_attachments'.format_map({'baseUrl': self.base_url})
        mail_attachments = self.request_get(query_url)
        if mail_attachments:
            self._assertJsonPayload(['uuid', 'enable', 'enableForAll', 'language', 'description', 'name', 'cid', 'mailConfig'], mail_attachments[0])

    def test_findAll_wrong_mail_config(self):
        """Test findaAll mail attachments returns not found http status
        with a wrong configuration uuid."""
        query_url = self.base_url + '/mail_attachments?configUuid=946b190d-4c95-485f-bfe6-d288a2de1ede'
        req = requests.get(
            query_url,
            headers=self.headers,
            auth=HTTPBasicAuth(self.email, self.password),
            verify=self.verify)
        LOGGER.debug("status_code : %s", req.status_code)
        LOGGER.debug("result : %s", req.text)
        self.assertEqual(req.status_code, 404)
        LOGGER.debug("data : %s", req.json())

    def test_find_all_audits_mail_attachment(self):
        """"Test findAll audits of a mail attachment"""
        mail_attachment = self.test_mail_attachments_create()
        query_url = '{base_url}/mail_attachments/{mail_attachment_uuid}/audits'.format_map({
            'base_url': self.base_url,
            'mail_attachment_uuid' : mail_attachment['uuid']
            })
        mail_attachments_audit = self.request_get(query_url)
        self._assertJsonPayload(self.EXPECTED_FIELD_LIST, mail_attachments_audit[0].get('resource'))
        return mail_attachments_audit

    def test_find_all_audits_mail_attachment_filtred_by_actions(self):
        """"Test findAll audits of a mail attachment filtered by
        list of actions [CREATE, UPDATE, DELETE]"""
        mail_attachment = self.test_mail_attachments_create()
        encode = urllib.parse.urlencode({'actions' : ['create', 'update']}, doseq=True)
        query_url = '{base_url}/mail_attachments/{mail_attachment_uuid}/audits?{encode}'.format_map({
            'base_url': self.base_url,
            'mail_attachment_uuid' : mail_attachment['uuid'],
            'encode': encode
            })
        mail_attachments = self.request_get(query_url)
        self._assertJsonPayload(self.EXPECTED_FIELD_LIST, mail_attachments[0].get('resource'))
        return mail_attachments

    def create_abstract_domain(self):
        """Get linShareRootDomain"""
        query_url = '{base_url}/domains/{Domain}'.format_map({
            'base_url': self.base_url,
            'Domain' : 'LinShareRootDomain'
            })
        domain = self.request_get(query_url)
        # Create an abstract domain
        query_url = '{base_url}/domains'.format_map({
            'base_url': self.base_url,
            })
        payload = {
            "parent":domain['identifier'],
            "type":"TOPDOMAIN",
            "providers":[],
            "externalMailLocale":"ENGLISH",
            "language":"ENGLISH",
            "mailConfigUuid":domain['mailConfigUuid'],
            "currentWelcomeMessage":domain['currentWelcomeMessage'],
            "mimePolicyUuid":domain['mimePolicyUuid'],
            "userRole":"SIMPLE",
            "policy":{"identifier":"DefaultDomainPolicy"},
            "label":"TopDomain",
            "description":"test creating top domain"
        }
        data = self.request_post(query_url, payload)
        self.assertEqual(data['label'], 'TopDomain')
        return data

    def create_mail_configuration(self):
        """Get a default mail configuration"""
        domain = self.create_abstract_domain()
        query_url = '{base_url}/mail_configs/{default_mail_config}'.format_map({
            'base_url': self.base_url,
            'default_mail_config' : domain['mailConfigUuid']
            })
        default_mail_config = self.request_get(query_url)
        # Create an mail configuration
        query_url = '{base_url}/mail_configs'.format_map({
            'base_url': self.base_url,
            })
        payload = {
            "name":"default mail config",
            "visible":True,
            "domain":domain['identifier'],
            "readonly":False,
            "mailLayout":default_mail_config['mailLayout'],
            "mailFooterLangs":default_mail_config['mailFooterLangs'],
            "mailContentLangs":default_mail_config['mailContentLangs']
        }
        data = self.request_post(query_url, payload)
        self.assertEqual(data['name'], 'default mail config')
        return data

    def test_find_all_audits_mail_attachment_by_domain(self):
        """"Create mail configuration"""
        mail_configuration = self.create_mail_configuration()
        # Create a mail attachment as an admin
        query_url = '{base_url}/mail_attachments'.format_map({
            'base_url': self.base_url,
            })
        file_path = 'LinShare.jpg'
        filesize = os.path.getsize(file_path)
        with open(file_path, 'rb') as file_stream:
            encoder = MultipartEncoder(
                fields={
                    'filesize': str(filesize),
                    'file': ('LinShare.jpg', file_stream),
                    'description': 'Test mail attachment',
                    'enableForAll': 'False',
                    'enable':'True',
                    'mail_config':mail_configuration['uuid'],
                    'cid':'logo.mail.attachment.test',
                    'language' : 'ENGLISH'
                }
            )
            monitor = MultipartEncoderMonitor(encoder, create_callback(encoder))
            headers = {
                'Accept': 'application/json',
                'Content-Type': monitor.content_type
            }
            mail_attachment = self.request_post(query_url, monitor, headers)
        # Test findAll audits of mail attachments of a choosen domain
        encode = urllib.parse.urlencode({'domainUuid' : mail_configuration['domain']})
        query_url = '{base_url}/mail_attachments/audits?{encode}'.format_map({
            'base_url' : self.base_url,
            'encode' : encode})
        mail_attachments_audits = self.request_get(query_url)
        self._assertJsonPayload(self.EXPECTED_FIELD_LIST, mail_attachments_audits[0].get('resource'))

    def test_find_all_audits_mail_attachment_without_domain(self):
        """"Test findAll audits of mail attachments of all domains"""
        query_url = '{base_url}/mail_attachments/audits'.format_map({
            'base_url': self.base_url,
            })
        mail_attachments_audit = self.request_get(query_url)
        self._assertJsonPayload(self.EXPECTED_FIELD_LIST, mail_attachments_audit[0].get('resource'))

class TestUserApiDocumentRevision(UserTestCase):
    """
    Test User api workgroup documents and
    workgroup document revisions
    """
# Helpers
    def create_ss_node(self):
        """create a shared space node."""
        query_url = '{baseUrl}/shared_spaces'.format_map({
            'baseUrl' : self.base_url})
        payload = {
            "name": "workgroup_test",
            "nodeType": "WORK_GROUP"
        }
        data = self.request_post(query_url, payload)
        self.assertEqual(data['name'], 'workgroup_test')
        return data

    def create_workgroup_document(self, shared_space_uuid):
        """create a workgroup document."""
        query_url = '{baseUrl}/shared_spaces/{shared_space_uuid}/nodes'.format_map({
            'baseUrl' : self.base_url,
            'shared_space_uuid' : shared_space_uuid})
        file_path = 'file10M'
        filesize = os.path.getsize(file_path)
        with open(file_path, 'rb') as file_stream:
            encoder = MultipartEncoder(
                fields={
                    'filesize': str(filesize),
                    'file': ('file10M.new', file_stream),
                    'filename': 'file10M'
                }
            )
            monitor = MultipartEncoderMonitor(encoder, create_callback(encoder))
            headers = {
                'Accept': 'application/json',
                'Content-Type': monitor.content_type
            }
            req = requests.post(
                query_url,
                data=monitor,
                headers=headers,
                auth=HTTPBasicAuth(self.email, self.password),
                verify=self.verify)
        if DEBUG:
            data = dump.dump_all(req)
            LOGGER.debug("dump_all : %s", data.decode('utf-8'))
        data = req.json()
        LOGGER.debug("data : %s", data)
        return data

    def update_workgroup_document(self, workgroup_uuid, workgroup_node_uuid):
        """Update a workgroup document."""
        query_url = '{baseUrl}/shared_spaces/{workgroup_uuid}/nodes/{workgroup_node_uuid}'.format_map({
            'baseUrl' : self.base_url,
            'workgroup_uuid' : workgroup_uuid,
            'workgroup_node_uuid' : workgroup_node_uuid})
        payload = {
            'uuid': workgroup_node_uuid,
            'name': 'test1',
            'type': 'DOCUMENT'
        }
        return self.request_put(query_url, payload)

    def test_create_workgroup_document_revision(self):
        """Test user create a workgroup document revision."""
        workgroup_uuid = self.create_ss_node()['uuid']
        # Upload the same file twice
        first_upload = self.create_workgroup_document(workgroup_uuid)
        self.create_workgroup_document(workgroup_uuid)
        encode = urllib.parse.urlencode({'parent' : first_upload['uuid']})
        query_url = '{baseUrl}/shared_spaces/{workgroup_uuid}/nodes?{encode}'.format_map({
            'baseUrl' : self.base_url,
            'workgroup_uuid' : workgroup_uuid,
            'encode' : encode})
        self.request_get(query_url)

    @unittest.skip('Assertion error.')
    def test_copy_workgroup_document_revision(self):
        """Test copy a workgroup document revision in the same workgroup."""
        workgroup_uuid = self.create_ss_node()['uuid']
        # Upload the same file twice
        workgroup_document = self.create_workgroup_document(workgroup_uuid)
        workgroup_document_revision = self.create_workgroup_document(workgroup_uuid)
        # Copy the workGroup document
        query_url = '{baseUrl}/shared_spaces/{shared_space_uuid}/nodes/copy'.format_map({
            'baseUrl' : self.base_url,
            'shared_space_uuid' : workgroup_uuid})
        payload = {
            "kind" : self.shared_space_kind,
            "uuid" : workgroup_document_revision['uuid'],
            "contextUuid" : workgroup_uuid
        }
        data = self.request_post(query_url, payload)
        # TODO: FIXME The returned document name is auto-generated
        self.assertEqual(data[0]["name"], workgroup_document_revision["name"])

    def test_copy_workgroup_document(self):
        """Test copy a workgroup document into another workgroup."""
        workgroup_uuid = self.create_ss_node()['uuid']
        workgroup_uuid_1 = self.create_ss_node()['uuid']
        workgroup_document = self.create_workgroup_document(workgroup_uuid)
        # Create revision: create the workgroup document twice
        workgroup_document_revision = self.create_workgroup_document(workgroup_uuid)
        self.assertEqual(workgroup_document_revision["name"], workgroup_document["name"])
        # Copy the workGroup document
        query_url = '{baseUrl}/shared_spaces/{shared_space_uuid}/nodes/copy'.format_map({
            'baseUrl' : self.base_url,
            'shared_space_uuid': workgroup_uuid_1})
        payload = {
            "kind" : self.shared_space_kind,
            "uuid" : workgroup_document['uuid'],
            "contextUuid" : workgroup_uuid
        }
        data = self.request_post(query_url, payload)
        self.assertEqual(data[0]["name"], workgroup_document["name"])

    def test_find_all_audit_document(self):
        """Test user create a workgroup document revision."""
        workgroup_uuid = self.create_ss_node()['uuid']
        # Upload the same file twice
        document = self.create_workgroup_document(workgroup_uuid)
        self.create_workgroup_document(workgroup_uuid)
        # update the name of document
        document = self.update_workgroup_document(workgroup_uuid, document['uuid'])
        query_url = '{baseUrl}/shared_spaces/{workgroup_uuid}/nodes/{document_uuid}/audit'.format_map({
            'baseUrl' : self.base_url,
            'workgroup_uuid' : workgroup_uuid,
            'document_uuid' : document['uuid']})
        self.request_get(query_url)

@unittest.skip
class TestUserApiJwtPermanentToken(AdminTestCase):
    """Test User api"""

    host = CONFIG['DEFAULT']['host']
    base_url = host + '/linshare/webservice/rest/user/v2/jwt'

    def create_jwt_permanent_token(self):
        """Test user create a shared space."""
        payload = {
            "issuer" : "test1",
            "label" : "label1",
            "subject" : "amy.wolsh@int6.linshare.dev",
            "token" : "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
        }
        data = self.request_post(self.base_url, payload)
        return data

    def test_head_jwt_permanent_token(self):
        """"Test Head JWT permanent token by uuid """
        token = self.create_jwt_permanent_token()
        query_url = self.base_url + '/' + token['uuid']
        req = requests.get(
            query_url,
            headers={'Accept': 'application/json'},
            auth=HTTPBasicAuth(self.email, self.password),
            verify=self.verify
        )
        LOGGER.debug("status_code : %s", req.status_code)
        self.assertEqual(req.status_code, 204)

    def test_find_jwt_permanent_token(self):
        """"Test find JWT permanent token by uuid """
        token = self.create_jwt_permanent_token()
        query_url = self.base_url + '/' + token['uuid']
        req = requests.get(
            query_url,
            headers={'Accept': 'application/json'},
            auth=HTTPBasicAuth(self.email, self.password),
            verify=self.verify
        )
        data = req.json()
        LOGGER.debug("status_code : %s", req.status_code)
        LOGGER.debug("result : %s", req.text)
        self.assertEqual(req.status_code, 200)
        self.assertEqual(data['subject'], token['subject'])
        LOGGER.debug("data : %s", json.dumps(req.json(), sort_keys=True, indent=2))


class TestAdminApiUpdateCanCreateGuestField(AdminTestCase):
    def test_update_can_create_guest(self):
        """Test update canCreateGuest field for user"""
        data = self.get_user1()
        query_url = self.base_url + '/users'
        uuid = data['uuid']
        req = requests.get(
            query_url + '/' + uuid,
            headers={'Accept': 'application/json'},
            auth=HTTPBasicAuth(self.email, self.password),
            verify=self.verify)
        self.assertEqual(req.status_code, 200)
        data = req.json()
        initCanCreateGuest = data['canCreateGuest']
        payload = {
            'mail': data['mail'],
            'accountType' : data['accountType'],
            'canUpload' : data['canUpload'],
            'canCreateGuest' : not initCanCreateGuest,
            'firstName' : data['firstName'],
            'lastName' : data['lastName'],
            'quotaUuid': data['quotaUuid'],
            'role' : data['role'],
            'externalMailLocale': data['externalMailLocale'],
            'locale' : data['locale'],
            'uuid' : data['uuid']
        }
        req = requests.put(
        query_url,
        data=json.dumps(payload),
        headers = self.headers,
        auth=HTTPBasicAuth(self.email, self.password),
        verify=self.verify)
        data = req.json()
        self.assertEqual(req.status_code, 200)
        self.assertEqual(data['canCreateGuest'], not initCanCreateGuest)


class TestUserApiContactList(AdminTestCase):
    """Test User api"""
    host = CONFIG['DEFAULT']['host']
    base_url = host + '/linshare/webservice/rest/user/v2/contact_lists'

    def test_create_contact_list(self):
        """Test create a contactList."""
        payload = {
            "name": "contactList",
        }
        data = self.request_post(self.base_url, payload)
        self.assertEqual(data['name'], 'contactList')
        return data

    def test_create_find_contact_list(self):
        """"Test create and find contactList by uuid """
        payload = {
            "name": "contactList2",
        }
        data = self.request_post(self.base_url, payload)
        self.assertEqual(data['name'], 'contactList2')
        query_url = self.base_url + '/' + data['uuid']
        req = requests.get(
            query_url,
            headers={'Accept': 'application/json'},
            auth=HTTPBasicAuth(self.email, self.password),
            verify=self.verify
        )
        data = req.json()
        LOGGER.debug("status_code : %s", req.status_code)
        LOGGER.debug("result : %s", req.text)
        self.assertEqual(req.status_code, 200)
        self.assertEqual(data['name'], "contactList2")
        LOGGER.debug("data : %s", json.dumps(req.json(), sort_keys=True, indent=2))

    def test_create_delete_contact_list(self):
        """"Test create and delete contactList by uuid """
        payload = {
            "name": "contactList3",
        }
        data = self.request_post(self.base_url, payload)
        self.assertEqual(data['name'], 'contactList3')
        query_url = self.base_url + '/' + data['uuid']
        req = requests.delete(
            query_url,
            headers={'Accept': 'application/json'},
            auth=HTTPBasicAuth(self.email, self.password),
            verify=self.verify
        )
        data = req.json()
        LOGGER.debug("status_code : %s", req.status_code)
        LOGGER.debug("result : %s", req.text)
        self.assertEqual(req.status_code, 200)
        LOGGER.debug("data : %s", json.dumps(req.json(), sort_keys=True, indent=2))

    def test_create_update_contact_list(self):
        """Test create and update a contactList."""
        payload = {
            "name": "contactList4",
        }
        data = self.request_post(self.base_url, payload)
        self.assertEqual(data['name'], 'contactList4')
        query_url = self.base_url + '/' + data['uuid']
        payload = {
            "name": "contactList5",
        }
        data = self.request_put(query_url, payload)
        self.assertEqual(data['name'], 'contactList5')
        return data

    def test_find_all_contact_list(self):
        """Test user find all contactList."""
        req = requests.get(
            self.base_url,
            headers={'Accept': 'application/json'},
            auth=HTTPBasicAuth(self.email, self.password),
            verify=self.verify)
        LOGGER.debug("status_code : %s", req.status_code)
        LOGGER.debug("result : %s", req.text)
        self.assertEqual(req.status_code, 200)
        LOGGER.debug("data : %s", req.json())


class TestUserApiSharedSpaceNode(UserTestCase):
    """Test User api sharedSpaceNode"""

    def create_shared_space(self):
        """Test user API create a shared space."""
        query_url = self.base_url + '/shared_spaces'
        payload = {
            "name": "workgroup_test",
            "nodeType": "WORK_GROUP"
        }
        data = self.request_post(query_url, payload)
        self.assertEqual(data['name'], 'workgroup_test')
        return data

    def create_shared_space_node(self):
        """Test user API create a shared space node."""
        workgroup = self.create_shared_space()
        query_url = self.base_url + '/shared_spaces/' + workgroup['uuid'] + '/nodes'
        payload = {
            "name": "FOLDER_test",
            "type": "FOLDER"
        }
        data = self.request_post(query_url, payload)
        self.assertEqual(data['name'], 'FOLDER_test')
        return data

    def test_find_shared_space_node(self):
        """"Test user API find a shared space node"""
        folder = self.create_shared_space_node()
        query_url = self.base_url + '/shared_spaces/' + folder['workGroup'] + '/nodes/' + folder['uuid']
        req = requests.get(
            query_url,
            headers={'Accept': 'application/json'},
            auth=HTTPBasicAuth(self.email, self.password),
            verify=self.verify
        )
        data = req.json()
        LOGGER.debug("status_code : %s", req.status_code)
        LOGGER.debug("result : %s", req.text)
        self.assertEqual(req.status_code, 200)
        self.assertEqual(data['name'], "FOLDER_test")
        LOGGER.debug("data : %s", json.dumps(req.json(), sort_keys=True, indent=2))
        return data

    def test_archive_download_folder(self):
        """"Test user API download a folder"""
        folder = self.test_find_shared_space_node()
        self.assertEqual(folder['type'], "FOLDER")
        query_url = '{baseUrl}/shared_spaces/{shared_spaces_uuid}/nodes/{shared_spaces_node_uuid}/download'.format_map({
            'baseUrl' : self.base_url,
            'shared_spaces_uuid' : folder['workGroup'],
            'shared_spaces_node_uuid' : folder['uuid']})
        req = requests.get(
            query_url,
            headers={'Accept': 'application/json'},
            auth=HTTPBasicAuth(self.email, self.password),
            verify=self.verify
        )
        LOGGER.debug("status_code : %s", req.status_code)
        LOGGER.debug("result : %s", req.text)
        self.assertEqual(req.status_code, 200)

    def test_update_shared_space_node_with_nodeuuid_path(self):
        """Test create and update a shared space node."""
        folder = self.create_shared_space_node()
        query_url = self.base_url + '/shared_spaces/' + folder['workGroup'] + '/nodes/' + folder['uuid']
        payload = {
            "name": "Update_Node_Name",
            "description": "Updated desc",
            "type": "FOLDER",
        }
        data = self.request_put(query_url, payload)
        self.assertEqual(data['name'], "Update_Node_Name")
        self.assertEqual(data['description'], payload['description'])
        return data

    def test_update_shared_space_node_without_nodeuuid_path(self):
        """Test create and update a shared space node."""
        folder = self.create_shared_space_node()
        query_url = self.base_url + '/shared_spaces/' + folder['workGroup'] + '/nodes/'
        payload = {
            "name": "Update_Node_Name",
            "type": "FOLDER",
            "uuid": folder['uuid']
        }
        data = self.request_put(query_url, payload)
        self.assertEqual(data['name'], "Update_Node_Name")
        return data

    def test_shared_space_node_delete(self):
        """Trying to create and delete a shared_space_node"""
        folder = self.create_shared_space_node()
        query_url = self.base_url + '/shared_spaces/' + folder['workGroup'] + '/nodes/'
        payload = {
            "name": "FOLDER_test",
            "type": "FOLDER",
            "uuid":folder['uuid']
        }
        req = requests.delete(
            query_url,
            data=json.dumps(payload),
            headers = self.headers,
            auth=HTTPBasicAuth(self.email, self.password),
            verify=self.verify)
        self.assertEqual(req.status_code, 200)
        data = req.json()
        self.assertEqual(data['name'], 'FOLDER_test')
        self.assertEqual(data['type'], 'FOLDER')
        return data

    def test_shared_space_node_delete_no_payload(self):
        """Trying to create and delete a shared_space_node with no payload"""
        folder = self.create_shared_space_node()
        query_url = self.base_url + '/shared_spaces/' + folder['workGroup'] + '/nodes/' + folder['uuid']
        req = requests.delete(
            query_url,
            headers = self.headers,
            auth=HTTPBasicAuth(self.email, self.password),
            verify=self.verify)
        self.assertEqual(req.status_code, 200)
        data = req.json()
        self.assertEqual(data['name'], 'FOLDER_test')
        self.assertEqual(data['type'], 'FOLDER')
        return data

    def test_find_all_shared_space_nodes(self):
        """Test user find all shared space node."""
        folder = self.create_shared_space_node()
        query_url = self.base_url + '/shared_spaces/' + folder['workGroup'] + '/nodes'
        req = requests.get(
            query_url,
            headers={'Accept': 'application/json'},
            auth=HTTPBasicAuth(self.email, self.password),
            verify=self.verify)
        LOGGER.debug("status_code : %s", req.status_code)
        LOGGER.debug("result : %s", req.text)
        self.assertEqual(req.status_code, 200)
        LOGGER.debug("data : %s", req.json())

    def test_patch_shared_space_node(self):
        """Test create and update a shared space node."""
        folder = self.create_shared_space_node()
        query_url = self.base_url + '/shared_spaces/' + folder['workGroup']
        payload = {
            "name": "name",
            "value": "renamed_node"
        }
        data = self.request_patch(query_url, payload)
        self.assertEqual(data['name'], "renamed_node")
        return data

    def test_find_specific_shared_spaces_audit(self):
        """Test user find all shared space."""
        folder = self.create_shared_space_node()
        query_url = self.base_url + '/shared_spaces/'+ folder['workGroup'] +'/nodes/'+ folder['uuid'] + '/audit'
        req = requests.get(
            query_url,
            headers={'Accept': 'application/json'},
            auth=HTTPBasicAuth(self.email, self.password),
            verify=self.verify)
        LOGGER.debug("status_code : %s", req.status_code)
        LOGGER.debug("result : %s", req.text)
        self.assertEqual(req.status_code, 200)
        LOGGER.debug("data : %s", req.json())


class TestUserApiSharedSpace(UserTestCase):
    """Test User api sharedSpaces: Drive and Workgroups management."""
    # utils
    DRIVE = "DRIVE"
    WORK_GROUP = "WORK_GROUP"
    FOLDER = "FOLDER"

    # Helpers

    def create_drive_by_peter(self):
        """
        Helper method
        Create By Peter Wilson
        See configuration (CONFIG_USER['DEFAULT']['email'])
        """
        query_url = '{base_url}/shared_spaces'.format_map({
            "base_url": self.base_url})
        payload = {
            "name": "Drive",
            "nodeType": self.DRIVE
        }
        return self.request_post(query_url, payload)

    def create_workgroup_by_peter(self):
        """
        Helper method
        Create By Peter Wilson
        See configuration (CONFIG_USER['DEFAULT']['email'])
        """
        query_url = self.base_url + '/shared_spaces'
        payload = {
            "name": "workgroup_test",
            "nodeType": self.WORK_GROUP
        }
        return self.request_post(query_url, payload)

    def create_nested_workgroup_by_peter(self):
        """
        Helper method
        Create a nested workgroup by Peter Wilson
        See (CONFIG_USER['DEFAULT']['email'])
        By default your principal user will be add
        as a member to the nested workgroup
        """
        drive = self.create_drive_by_peter()
        query_url = '{baseUrl}/shared_spaces'.format_map({
            'baseUrl' : self.base_url
            })
        payload = {
            "name": "Nested_workgroup",
            "nodeType": self.WORK_GROUP,
            "parentUuid":drive["uuid"]
        }
        return self.request_post(query_url, payload)

    def delete_workgroup(self):
        """
        Helper method
        Delete a workgroup by Peter Wilson
        See configuration (CONFIG_USER['DEFAULT']['email'])
        """
        shared_space = self.create_workgroup_by_peter()
        query_url = self.base_url + '/shared_spaces'
        payload = {
            "name": "workgroup_test",
            "nodeType": self.WORK_GROUP,
            "uuid":shared_space['uuid'],
            "versioningParameters": {
                "enable": "true",
            }
        }
        return self.request_delete(query_url, payload)

    def create_shared_space_member(self):
        """
        Helper method
        Add Amy as a member to a stand-alone workgroup created by principal
        """
        user1 = self.get_user("amy")
        shared_space = self.create_workgroup_by_peter()
        base_url = self.host + '/linshare/webservice/rest/user/v2/shared_spaces/'
        query_url = base_url + shared_space['uuid'] + "/members"
        payload = {
            "account" : {
                "uuid" : user1['uuid'],
                "firstName" : user1['firstName'],
                "lastName" : user1['lastName'],
                "mail" : user1['mail'],
                },
            "role" : {
                "uuid" : "234be74d-2966-41c1-9dee-e47c8c63c14e",
                "name" : "ADMIN"
                },
            "node" : {
                "uuid" : shared_space['uuid'],
                "name" : shared_space['name'],
                "nodeType" : shared_space['nodeType']
                }
        }
        return self.request_post(query_url, payload)

    def test_find_shared_space_wg(self):
        """"Test user find a shared space WORKGROUP"""
        workgroup = self.create_workgroup_by_peter()
        query_url = self.base_url + '/shared_spaces/' + workgroup['uuid']
        data = self.request_get(query_url)
        self.assertIsNotNone(data['quotaUuid'])

    def test_find_shared_space_quota(self):
        """"Test user find shared space WORKGROUP quota"""
        workgroup = self.create_workgroup_by_peter()
        query_url = self.base_url + '/quota/' + workgroup['quotaUuid']
        self.request_get(query_url)

    def test_update_shared_space_with_uuid_path(self):
        """Test create and update a shared space."""
        shared_space = self.create_workgroup_by_peter()
        query_url = self.base_url + '/shared_spaces/' + shared_space['uuid']
        payload = {
            "name": "Update_shared_space_Name",
            "nodeType": self.WORK_GROUP,
            "versioningParameters": {
                "enable": "true",
            }
        }
        data = self.request_put(query_url, payload)
        self.assertEqual(data['name'], payload['name'], "The name is the different")

    def test_update_shared_space_without_uuid_path(self):
        """Test create and update a shared space."""
        shared_space = self.create_workgroup_by_peter()
        query_url = self.base_url + '/shared_spaces'
        payload = {
            "name": "Update_shared_space_Name",
            "nodeType": self.WORK_GROUP,
            "uuid":shared_space['uuid'],
            "versioningParameters": {
                "enable": "true",
            }
        }
        data = data = self.request_put(query_url, payload)
        self.assertEqual(data['name'], payload['name'])

    def test_shared_space_delete_no_payload(self):
        """
        Trying to create and delete a shared_space WORKGROUP with no payload
        """
        shared_space = self.create_workgroup_by_peter()
        query_url = self.base_url +'/shared_spaces/'+ shared_space['uuid']
        data = self.request_delete(query_url)
        self.assertEqual(data['name'], 'workgroup_test')
        return data

    def test_find_all_shared_spaces(self):
        """Test user find all shared spaces."""
        query_url = self.base_url + '/shared_spaces'
        nodes = self.request_get(query_url)
        if len(nodes) != 0:
            for node in nodes:
                self.assertEqual(node['parentUuid'], None,
                                  "One of returned Shared space is not on top level")

    def test_find_all_shared_spaces_with_role(self):
        """Test user api find all with the role of the member of this node shared spaces """
        encode = urllib.parse.urlencode({'withRole' : True})
        query_url = '{baseUrl}/shared_spaces/?{encode}'.format_map({
            'baseUrl' : self.base_url,
            'encode' : encode})
        data = self.request_get(query_url)
        self.assertIn('role', data[0])

    def test_find_all_shared_spaces_audit(self):
        """Test user find all shared space audit."""
        workgroup = self.create_workgroup_by_peter()
        query_url = self.base_url + '/shared_spaces/' + workgroup['uuid'] + "/audit"
        audits = self.request_get(query_url)
        self.assertTrue(audits)
        # Create shared space node (folder)
        query_url = '{baseUrl}/shared_spaces/{shared_space_uuid}/nodes'.format_map({
            "baseUrl" : self.base_url,
            "shared_space_uuid" : workgroup['uuid'
        ]})
        payload = {
            "name": "FOLDER_test",
            "type": self.FOLDER
        }
        created_node = self.request_post(query_url, payload)
        # Delete shared space node (folder)
        query_url = '{baseUrl}/shared_spaces/{shared_space_uuid}/nodes'.format_map({
            "baseUrl" : self.base_url,
            "shared_space_uuid" : workgroup['uuid']})
        payload = {
            "name": "FOLDER_test",
            "type": self.FOLDER,
            "uuid":created_node['uuid']
        }
        deleted_node = self.request_delete(query_url, payload)
        # Find audit traces related to the folder
        encode = urllib.parse.urlencode({
            'nodeUuid': deleted_node['uuid']})
        query_url = '{baseUrl}/shared_spaces/{shared_space_uuid}/nodes/{workgroup_node_uuid}/audit'.format_map({
            "baseUrl" : self.base_url,
            "shared_space_uuid" : workgroup['uuid'],
            "workgroup_node_uuid" : deleted_node['uuid'],
            "encode" : encode })
        audits = self.request_get(query_url)
        self.assertTrue(audits)
        self.assertEqual(len(audits), 2)

    def test_create_nested_wg_in_drive(self):
        """Test user API create a workgroup  into a drive."""
        drive = self.create_drive_by_peter()
        query_url = '{baseUrl}/shared_spaces'.format_map({
            'baseUrl' : self.base_url
            })
        payload = {
            "name": "Nested_workgroup",
            "nodeType": self.WORK_GROUP,
            "parentUuid":drive["uuid"]
        }
        nested_wg = self.request_post(query_url, payload)
        self.assertEqual(nested_wg['parentUuid'], drive['uuid'])

    def test_create_shared_space_member_workgroup_explicit_type(self):
        """ Test user API add a member to a WORKGROUP """
        user1 = self.get_user("amy")
        workgroup = self.create_workgroup_by_peter()
        query_url = '{base_url}/shared_spaces/{workgroupUuid}/members'.format_map({
            'base_url': self.base_url,
            'workgroupUuid': workgroup['uuid']
            })
        role = self.getRole('READER')
        payload = {
            "account" : {
                "uuid" : user1['uuid'],
                },
            "role" : {
                "uuid" : role['uuid'],
                },
            "node" : {
                "uuid" : workgroup['uuid'],
                "name" : workgroup['name'],
                "nodeType" : workgroup['nodeType']
                },
            "type" : "WORK_GROUP"
            }
        self.request_post(query_url, payload)

    def test_create_shared_space_member_workgroup_wrong_with_role_type(self):
        """ Test user API add a member FORBIDDEN to a WORKGROUP
        by give a DRIVE role type to a WORKGROUP member """
        user1 = self.get_user("amy")
        workgroup = self.create_workgroup_by_peter()
        query_url = '{base_url}/shared_spaces/{workgroupUuid}/members'.format_map({
            'base_url': self.base_url,
            'workgroupUuid': workgroup['uuid']
            })
        role = self.getRole('DRIVE_READER')
        payload = {
            "account" : {
                "uuid" : user1['uuid'],
                },
            "role" : {
                "uuid" : role['uuid'],
                },
            "node" : {
                "uuid" : workgroup['uuid'],
                "name" : workgroup['name'],
                "nodeType" : workgroup['nodeType']
                },
            "type" : "WORK_GROUP"
            }
        self.request_post(query_url, payload, expected_status=403 , busines_err_code=60005)

    def test_create_shared_space_member_workgroup_implicit_type(self):
        """ Test user API add a member to a WORKGROUP """
        user1 = self.get_user("amy")
        workgroup = self.create_workgroup_by_peter()
        query_url = '{base_url}/shared_spaces/{workgroupUuid}/members'.format_map({
            'base_url': self.base_url,
            'workgroupUuid': workgroup['uuid']
            })
        role = self.getRole('READER')
        payload = {
            "account" : {
                "uuid" : user1['uuid'],
                },
            "role" : {
                "uuid" : role['uuid'],
                },
            "node" : {
                "uuid" : workgroup['uuid'],
                "name" : workgroup['name'],
                "nodeType" : workgroup['nodeType']
                },
            }
        self.request_post(query_url, payload)

    def test_create_shared_space_member_drive(self):
        """Test user API add a shared space member into a DRIVE """
        nested_role = self.getRole('ADMIN')
        role = self.getRole('DRIVE_ADMIN')
        drive = self.create_drive_by_peter()
        user1 = self.get_user("amy")
        query_url = self.base_url + '/shared_spaces/{driveUuid}/members'.format(driveUuid=drive['uuid'])
        payload = {
            "account" : {
                "uuid" : user1['uuid'],
                "firstName" : user1['firstName'],
                "lastName" : user1['lastName'],
                "mail" : user1['mail'],
                },
            "role" : {
                "uuid" : role['uuid'],
                },
            "nestedRole": {
                "uuid": nested_role['uuid'],
            },
            "node" : {
                "uuid" : drive['uuid'],
                "name" : drive['name'],
                "nodeType" : drive['nodeType']
                },
            "type" : "DRIVE"
        }
        data = self.request_post(query_url, payload)
        self.assertEqual (data['account']['firstName'], user1['firstName'])
        return data

    def test_create_shared_space_member_drive_fails_with_wrong_role(self):
        """Test user API add a shared space member FORBIDDEN into a DRIVE
        by give Work_GROUP role type to DRIVE member"""
        nestedRole = self.getRole('ADMIN')
        role = self.getRole('DRIVE_ADMIN')
        drive = self.create_drive_by_peter()
        user1 = self.get_user("amy")
        query_url = '{baseUrl}/shared_spaces/{driveUuid}/members'.format_map({
            'driveUuid' : drive['uuid'],
            'baseUrl' : self.base_url
            })
        payload = {
            "account" : {
                "uuid" : user1['uuid'],
                "firstName" : user1['firstName'],
                "lastName" : user1['lastName'],
                "mail" : user1['mail'],
                },
            "role" : {
                "uuid" : nestedRole['uuid'],
                },
            "nestedRole": {
                "uuid": role['uuid'],
            },
            "node" : {
                "uuid" : drive['uuid'],
                "name" : drive['name'],
                "nodeType" : drive['nodeType']
                },
            "type" : "DRIVE"
        }
        self.request_post(query_url, payload, expected_status=403, busines_err_code=60005)

    def test_add_shared_space_member_in_drive_and_its_nested_wg(self):
        """
        Test user API add a shared space member
        into a DRIVE and its nested workgroups
        """
        nestedRole = self.getRole('ADMIN')
        role = self.getRole('DRIVE_ADMIN')

        # Create the Shared space DRIVE (parent)
        drive = self.create_drive_by_peter()

        # Get an LS internal user to add in Shared space
        user1 = self.get_user("amy")

        wg_create_query_url = '{baseUrl}/shared_spaces'.format_map({
            'baseUrl' : self.base_url
            })

        # Payload to create the first nested workgroup

        wg_payload_1 = {
            "name": "Nested_workgroup_1",
            "nodeType": self.WORK_GROUP,
            "parentUuid":drive["uuid"]
        }

        # Payload to create the second nested workgroup
        wg_payload_2 = {
            "name": "Nested_workgroup_2",
            "nodeType": self.WORK_GROUP,
            "parentUuid":drive["uuid"]
        }
        # Payload to create the third nested workgroup
        wg_payload_3 = {
            "name": "Nested_workgroup_3",
            "nodeType": self.WORK_GROUP,
            "parentUuid":drive["uuid"]
        }
        # Add nested WG 1
        nested_wg_1 = self.request_post(wg_create_query_url, wg_payload_1)
        # Add nested WG 2
        nested_wg_2 = self.request_post(wg_create_query_url, wg_payload_2)
        # Add nested WG 3
        nested_wg_3 = self.request_post(wg_create_query_url, wg_payload_3)

        # Add a member to the Drive (parent)
        add_membr_query_url = '{baseUrl}/shared_spaces/{driveUuid}/members'.format_map({
            "baseUrl":self.base_url ,
            "driveUuid": drive['uuid']})
        member_payload = {
            "account" : {
                "uuid" : user1['uuid'],
                "firstName" : user1['firstName'],
                "lastName" : user1['lastName'],
                "mail" : user1['mail'],
                },
            "role" : {
                "uuid" : role['uuid'],
                },
            "nestedRole": {
                "uuid": nestedRole['uuid'],
            },
            "node" : {
                "uuid" : drive['uuid'],
                "name" : drive['name'],
                "nodeType" : drive['nodeType']
                },
            "type" : "DRIVE"
        }
        # Get all the members of the node
        get_members_of_wg1_query_url = '{baseUrl}/shared_spaces/{nodeUuid}/members'.format_map({
            "baseUrl" : self.base_url ,
            "nodeUuid" : nested_wg_1['uuid']})

        get_members_of_wg2_query_url = '{baseUrl}/shared_spaces/{nodeUuid}/members'.format_map({
            "baseUrl" : self.base_url ,
            "nodeUuid" : nested_wg_2['uuid']})

        get_members_of_wg3_query_url = '{baseUrl}/shared_spaces/{nodeUuid}/members'.format_map({
            "baseUrl" : self.base_url ,
            "nodeUuid" : nested_wg_3['uuid']})

        member_1 = requests.get(
            get_members_of_wg1_query_url,
            headers={'Accept': 'application/json'},
            auth=HTTPBasicAuth(self.email, self.password),
            verify=self.verify).json()

        member_2 = requests.get(
            get_members_of_wg2_query_url,
            headers={'Accept': 'application/json'},
            auth=HTTPBasicAuth(self.email, self.password),
            verify=self.verify).json()

        member_3 = requests.get(
            get_members_of_wg3_query_url,
            headers={'Accept': 'application/json'},
            auth=HTTPBasicAuth(self.email, self.password),
            verify=self.verify).json()

        request = requests.post(
            add_membr_query_url,
            json.dumps(member_payload),
            headers=self.headers,
            auth=HTTPBasicAuth(self.email, self.password),
            verify=self.verify)
        member_drive = request.json()
        # Assertions
        self.assertEqual(request.status_code, 200)
        self.assertEqual (member_drive['account']['firstName'], user1['firstName'])
        self.assertEqual(member_1[0]['nested'], True, "FAILED, created member is not nested")
        self.assertEqual(member_2[0]['nested'], True, "FAILED, created member is not nested")
        self.assertEqual(member_3[0]['nested'], True, "FAILED, created member is not nested")
        return member_drive

    def test_add_shared_space_member_in_nested_wg(self):
        """
        Test user API add a shared space member into a nested WORKGROUP
        The member will be an external member
        (exists only in The workgroup and not in Drive)
        """
        # The role that's given to the member in the nested node
        role = self.getRole('ADMIN')
        drive = self.create_drive_by_peter()
        workgroup = self.create_nested_workgroup_by_peter()
        user1 = self.get_user("amy")
        query_url = '{baseUrl}/shared_spaces/{nodeUuid}/members'.format_map({
            'baseUrl' : self.base_url,
            'nodeUuid': workgroup['uuid']})
        payload = {
            "account" : {
                "uuid" : user1['uuid'],
                "firstName" : user1['firstName'],
                "lastName" : user1['lastName'],
                "mail" : user1['mail'],
                },
            "role" : {
                "uuid" : role['uuid'],
                },
            "node" : {
                "uuid" : workgroup['uuid']
                }
        }
        member = self.request_post(query_url, payload)
        self.assertEqual (member['account']['firstName'], user1['firstName'])
        self.assertEqual(member['node']['nodeType'], workgroup['nodeType'], "FAILED, node type is different")
        self.assertEqual(member['nested'], True, "FAILED, created member is not nested")
        return member

    def shared_space_delete(self, uuid):
        """Trying to create and delete a shared_space with no payload"""
        query_url = self.base_url + '/shared_spaces/' + uuid
        req = requests.delete(
            query_url,
            headers = self.headers,
            auth=HTTPBasicAuth(self.email, self.password),
            verify=self.verify)
        self.assertEqual(req.status_code, 200)
        data = req.json()
        return data

    def test_soft_propagate_shared_space_member_role(self):
        """soft update role member ."""
        user1 = self.get_user("amy")
        drive = self.create_drive_by_peter()
        nestedRole = self.getRole('ADMIN')
        nestedRoleContributor = self.getRole('CONTRIBUTOR')
        role = self.getRole('DRIVE_ADMIN')

        # Create a workGroup into the drive.

        query_url = self.base_url + '/shared_spaces/'
        payload = {
            "name": "Workgroup_test",
            "nodeType": self.WORK_GROUP,
            "parentUuid":drive['uuid']
        }
        data_workgroup = self.request_post(query_url, payload)

        # Add  a member into the drive.

        query_url = '{base_url}/shared_spaces/{driveUuid}/members'.format_map({
            'driveUuid' : drive['uuid'],
            'base_url': self.base_url
        })
        payload = {
            "account" : {
                "uuid" : user1['uuid'],
                },
            "role" : {
                "uuid" : role['uuid'],
                },
            "nestedRole": {
                "uuid": nestedRole['uuid'],
            },
            "node" : {
                "uuid" : drive['uuid'],
                "name" : drive['name'],
                "nodeType" : drive['nodeType']
                },
            "type" : "DRIVE"
        }
        data_member = self.request_post(query_url, payload)
        self.assertEqual(data_member['account']['firstName'], user1['firstName'])

        # Soft update of a member into the drive.
        query_url = '{base_url}/shared_spaces/{driveUuid}/members/{memberUuid}/?force=false'.format_map({
            'base_url': self.base_url,
            'driveUuid': drive['uuid'],
            'memberUuid': data_member['uuid']
        })
        payload = {
            "account" : {
                "uuid" : user1['uuid'],
                },
            "role" : {
                "uuid" : role['uuid']
                },
            "nestedRole": {
                "uuid": nestedRoleContributor['uuid']
            },
            "node" : {
                "uuid" : drive['uuid'],
                "name" : drive['name'],
                "nodeType" : drive['nodeType']
                },
            "type" : "DRIVE"
        }
        request = requests.put(
            query_url,
            data=json.dumps(payload),
            headers=self.headers,
            auth=HTTPBasicAuth(self.email, self.password),
            verify=self.verify)
        data_member = request.json()
        self.assertEqual(request.status_code, 200, 'FAILED')
        self.assertEqual (data_member['account']['firstName'],user1['firstName'])
        self.assertEqual (data_member['nestedRole']['name'],'CONTRIBUTOR')
        # Check the new created member into the nested workgroup.
        query_url = self.base_url + '/shared_spaces?withRole=TRUE'
        req = requests.get(
            query_url,
            headers={'Accept': 'application/json'},
            auth=HTTPBasicAuth(self.email, self.password),
            verify=self.verify
        )
        data = req.json()
        LOGGER.debug("status_code : %s", req.status_code)
        LOGGER.debug("result : %s", req.text)
        self.assertEqual(req.status_code, 200)
        self.assertTrue(data[0]['role']['name'], 'ADMIN')
        self.shared_space_delete(drive['uuid'])
        return data

    def test_force_propagate_shared_space_member_role(self):
        """Test user API create a shared space member."""
        drive = self.create_drive_by_peter()
        nestedRole = self.getRole('ADMIN')
        nestedRoleContributor = self.getRole('CONTRIBUTOR')
        role = self.getRole('DRIVE_ADMIN')
        # Create a workGroup into the drive.
        query_url = self.base_url + '/shared_spaces/'
        payload = {
            "name": "Workgroup_test",
            "nodeType": self.WORK_GROUP,
            "parentUuid":drive['uuid']
        }
        data_workgroup = self.request_post(query_url, payload)
        # add Amy as a member into the drive.
        user1 = self.get_user("amy")
        query_url = self.base_url + '/shared_spaces/' + drive['uuid'] + '/members'
        payload = {
            "account" : {
                "uuid" : user1['uuid'],
                "firstName" : user1['firstName'],
                "lastName" : user1['lastName'],
                "mail" : user1['mail'],
                },
            "role" : {
                "uuid" : role['uuid'],
                },
            "nestedRole": {
                "uuid": nestedRole['uuid'],
            },
            "node" : {
                "uuid" : drive['uuid'],
                "name" : drive['name'],
                "nodeType" : drive['nodeType']
                },
            "type" : "DRIVE"
        }
        data_member = self.request_post(query_url, payload)
        self.assertEqual (data_member['account']['firstName'],user1['firstName'])
        self.assertEqual (data_member['nestedRole']['name'],'ADMIN')
        # Soft update of a member into the drive.
        query_url = self.base_url + '/shared_spaces/' + drive['uuid'] + '/members/' + data_member['uuid'] + '?force=true'
        payload = {
            "account" : {
                "uuid" : user1['uuid'],
                "firstName" : user1['firstName'],
                "lastName" : user1['lastName'],
                "mail" : user1['mail'],
                },
            "role" : {
                "uuid" : role['uuid'],
                },
            "nestedRole": {
                "uuid": nestedRoleContributor['uuid'],
            },
            "node" : {
                "uuid" : drive['uuid'],
                "name" : drive['name'],
                "nodeType" : drive['nodeType']
                },
            "type" : "DRIVE"
        }
        data_member = self.request_put(query_url, payload)
        self.assertEqual (data_member['account']['firstName'],user1['firstName'])
        self.assertEqual (data_member['nestedRole']['name'],'CONTRIBUTOR')
        # Check the new created member into the nested workgroup.
        query_url = self.base_url + '/shared_spaces?withRole=TRUE'
        req = requests.get(
            query_url,
            headers={'Accept': 'application/json'},
            auth=HTTPBasicAuth(self.email, self.password),
            verify=self.verify
        )
        data = req.json()
        LOGGER.debug("status_code : %s", req.status_code)
        LOGGER.debug("result : %s", req.text)
        self.assertEqual(req.status_code, 200)
        self.assertTrue(data[0]['role']['name'], 'CONTRIBUTOR')
        self.shared_space_delete(drive['uuid'])
        return data

    def test_propagate_shared_space_member_drive(self):
        """Test user API propagate the creation of member in nested nodes."""
        drive = self.create_drive_by_peter()
        nestedRole = self.getRole('ADMIN')
        role = self.getRole('DRIVE_ADMIN')

        # Add Amy as a new member into the created drive.by principal
        user1 = self.get_user("amy")
        query_url = self.base_url + '/shared_spaces/' + drive['uuid'] + '/members'
        payload = {
            "account" : {
                "uuid" : user1['uuid']
                },
            "role" : {
                "uuid" : role['uuid'],
                },
            "node" : {
                "uuid" : drive['uuid'],
                }
        }
        data_member_drive = self.request_post(query_url, payload)
        self.assertEqual (data_member_drive['account']['uuid'], user1['uuid'])

        # Create a workGroup into the drive.
        query_url = self.base_url + '/shared_spaces/'
        payload = {
            "name": "Workgroup_test",
            "nodeType": "WORK_GROUP",
            "parentUuid":drive['uuid']
        }
        req = requests.post(
            query_url,
            data=json.dumps(payload),
            headers=self.headers,
            auth=HTTPBasicAuth(self.email, self.password),
            verify=self.verify)
        LOGGER.debug("status_code : %s", req.status_code)
        LOGGER.debug("result : %s", req.text)
        self.assertEqual(req.status_code, 200)
        data_nested_workgroup = req.json()

        # Check the new created member is into the nested workgroup.
        accountUuid = data_member_drive['account']['uuid']
        encode = urllib.parse.urlencode({
            'accountUuid': data_member_drive['account']['uuid']})
        query_url = '{baseUrl}/shared_spaces/{nodeUuid}/members/?{encode}'.format_map({
            "baseUrl" : self.base_url,
            "nodeUuid" : data_nested_workgroup['uuid'],
            "encode" : encode })
        req = requests.get(
            query_url,
            headers={'Accept': 'application/json'},
            auth=HTTPBasicAuth(self.email, self.password),
            verify=self.verify
        )
        data = req.json()
        LOGGER.debug("status_code : %s", req.status_code)
        LOGGER.debug("result : %s", req.text)
        self.assertEqual(req.status_code, 200)
        self.shared_space_delete(drive['uuid'])
        return data

    def test_find_all_shared_spaces_members_drive(self):
        """Test user find all shared spaces members."""
        drive = self.create_drive_by_peter()
        query_url = self.base_url + '/shared_spaces/' + drive['uuid'] + '/members'
        req = requests.get(
            query_url,
            headers={'Accept': 'application/json'},
            auth=HTTPBasicAuth(self.email, self.password),
            verify=self.verify)
        LOGGER.debug("status_code : %s", req.status_code)
        LOGGER.debug("result : %s", req.text)
        self.assertEqual(req.status_code, 200)
        self.shared_space_delete(drive['uuid'])
        LOGGER.debug("data : %s", req.json())

    def test_create_work_group_into_drive(self):
        """Test user API create a workgroup into drive."""
        drive = self.create_drive_by_peter()
        query_url = self.base_url + '/shared_spaces/'
        payload = {
            "name": "Workgroup_test",
            "nodeType": "WORK_GROUP",
            "parentUuid":drive['uuid']
        }
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
        self.assertEqual (data['name'],"Workgroup_test")
        self.assertEqual (data['parentUuid'],drive['uuid'])
        LOGGER.debug("data : %s", json.dumps(data, sort_keys=True, indent=2))
        return data

    def test_create_shared_space_member(self):
        """Test user API create a shared space member."""
        user1 = self.get_user("amy")
        shared_space = self.create_workgroup_by_peter()
        base_url = self.host + '/linshare/webservice/rest/user/v2/shared_spaces/'
        query_url = base_url + shared_space['uuid'] + "/members"
        payload = {
            "account" : {
                "uuid" : user1['uuid'],
                "firstName" : user1['firstName'],
                "lastName" : user1['lastName'],
                "mail" : user1['mail'],
                },
            "role" : {
                "uuid" : "234be74d-2966-41c1-9dee-e47c8c63c14e",
                "name" : "ADMIN"
                },
            "node" : {
                "uuid" : shared_space['uuid'],
                "name" : shared_space['name'],
                "nodeType" : shared_space['nodeType']
                }
        }
        data = self.request_post(query_url, payload)
        self.assertEqual (data['account']['firstName'],user1['firstName'])

    def test_delete_shared_space_member(self):
        """Test user API delete a shared space member from a WORKGROUP."""
        user1 = self.get_user("amy")
        shared_space = self.create_workgroup_by_peter()
        base_url = self.host + '/linshare/webservice/rest/user/v2/shared_spaces/'
        query_url = base_url + shared_space['uuid'] + "/members"
        payload = {
            "account" : {
                "uuid" : user1['uuid'],
                "firstName" : user1['firstName'],
                "lastName" : user1['lastName'],
                "mail" : user1['mail'],
                },
            "role" : {
                "uuid" : "234be74d-2966-41c1-9dee-e47c8c63c14e",
                "name" : "ADMIN"
                },
            "node" : {
                "uuid" : shared_space['uuid'],
                "name" : shared_space['name'],
                "nodeType" : shared_space['nodeType']
                }
        }
        shared_space_member = self.request_post(query_url, payload)
        query_url = '{base_url}/shared_spaces/{nodeUuid}/members/{memberUuid}'.format_map({
            'base_url': self.base_url,
            'nodeUuid' : shared_space_member['node']['uuid'],
            'memberUuid': shared_space_member['uuid']
            })
        payload = {
            "account" : shared_space_member['account'],
            "role" : {
                "uuid" : "4ccbed61-71da-42a0-a513-92211953ac95",
                "name" : "READER"
                },
            "node" : shared_space_member['node']
        }
        req = requests.delete(
            query_url,
            data=json.dumps(payload),
            headers = self.headers,
            auth=HTTPBasicAuth(self.email, self.password),
            verify=self.verify)
        self.assertEqual(req.status_code, 200)
        data = req.json()
        self.assertEqual (data['account']['firstName'],shared_space_member['account']['firstName'])
        return data

    def test_delete_shared_space_member_no_payload(self):
        """Test user API create a shared space member."""
        shared_space_member = self.create_shared_space_member()
        #query_url = self.base_url + '/' + shared_space_member['node']['uuid'] + "/members/" +
        query_url = '{base_url}/shared_spaces/{nodeUuid}/members/{memberUuid}'.format_map({
            'base_url': self.base_url,
            'nodeUuid' : shared_space_member['node']['uuid'],
            'memberUuid': shared_space_member['uuid']
            })
        req = requests.delete(
            query_url,
            headers = self.headers,
            auth=HTTPBasicAuth(self.email, self.password),
            verify=self.verify)
        self.assertEqual(req.status_code, 200)
        data = req.json()
        return data

    def test_find_shared_space_member(self):
        """"Test user API find a shared space member"""
        shared_space_member = self.create_shared_space_member()
        base_url = self.host + '/linshare/webservice/rest/user/v2/shared_spaces/'
        query_url = base_url + shared_space_member['node']['uuid'] + "/members/" +shared_space_member['uuid']
        req = requests.get(
            query_url,
            headers={'Accept': 'application/json'},
            auth=HTTPBasicAuth(self.email, self.password),
            verify=self.verify
        )
        data = req.json()
        LOGGER.debug("status_code : %s", req.status_code)
        LOGGER.debug("result : %s", req.text)
        self.assertEqual(req.status_code, 200)
        self.assertEqual (data['account']['firstName'],shared_space_member['account']['firstName'])
        LOGGER.debug("data : %s", json.dumps(req.json(), sort_keys=True, indent=2))

    def test_find_all_shared_spaces_members(self):
        """Test user find all shared spaces members."""
        shared_space = self.create_workgroup_by_peter()
        base_url = self.host + '/linshare/webservice/rest/user/v2/shared_spaces/'
        query_url = base_url + shared_space['uuid'] + "/members"
        req = requests.get(
            query_url,
            headers={'Accept': 'application/json'},
            auth=HTTPBasicAuth(self.email, self.password),
            verify=self.verify)
        LOGGER.debug("status_code : %s", req.status_code)
        LOGGER.debug("result : %s", req.text)
        self.assertEqual(req.status_code, 200)
        LOGGER.debug("data : %s", req.json())

    def test_update_shared_space_member(self):
        """Test user API create a shared space member."""
        shared_space_member = self.create_shared_space_member()
        query_url = '{base_url}/shared_spaces/{nodeUuid}/members/{memberUuid}'.format_map({
            'base_url': self.base_url,
            'nodeUuid' : shared_space_member['node']['uuid'],
            'memberUuid': shared_space_member['uuid']
            })
        payload = {
            "account" : shared_space_member['account'],
            "role" : {
                "uuid" : "4ccbed61-71da-42a0-a513-92211953ac95",
                "name" : "READER"
                },
            "node" : shared_space_member['node'],
        }
        data = self.request_put(query_url, payload)
        self.assertEqual (data['role']['name'],'READER')
        return data

    def test_update_shared_space_member_drive(self):
        """Test user API update shared space member drive"""
        shared_space_member = self.test_create_shared_space_member_drive()
        role = self.getRole('DRIVE_READER')
        nestedRole = self.getRole('READER')
        query_url = '{base_url}/shared_spaces/{nodeUuid}/members/{memberUuid}'.format_map({
            'base_url': self.base_url,
            'nodeUuid' : shared_space_member['node']['uuid'],
            'memberUuid': shared_space_member['uuid']
            })
        payload = {
            "account" : shared_space_member['account'],
            "role" : {
                "uuid" : role['uuid']
                },
            "nestedRole": {
                "uuid": nestedRole['uuid'],
            },
            "node" : shared_space_member['node'],
            "type" : shared_space_member['node']["nodeType"]
        }
        self.request_put(query_url, payload)

    def test_update_shared_space_member_work_group_wrong_role(self):
        """Test user API update shared space member work group with wrong role."""
        shared_space_member = self.create_shared_space_member()
        role = self.getRole('DRIVE_ADMIN')
        query_url = '{base_url}/shared_spaces/{nodeUuid}/members/{memberUuid}'.format_map({
            'base_url': self.base_url,
            'nodeUuid' : shared_space_member['node']['uuid'],
            'memberUuid': shared_space_member['uuid']
            })
        payload = {
            "account" : shared_space_member['account'],
            "role" : {
                "uuid" : role['uuid']
                },
            "node" : shared_space_member['node'],
        }
        self.request_put(query_url, payload,expected_status=403 , busines_err_code=60005)

    def test_update_shared_space_member_drive_wrong_role(self):
        """Test user API update shared space member drive with wrong role."""
        shared_space_member = self.test_create_shared_space_member_drive()
        nestedRole = self.getRole('ADMIN')
        query_url = '{base_url}/shared_spaces/{nodeUuid}/members/{memberUuid}'.format_map({
            'base_url': self.base_url,
            'nodeUuid' : shared_space_member['node']['uuid'],
            'memberUuid': shared_space_member['uuid']
            })
        payload = {
            "account" : shared_space_member['account'],
            "role" : {
                "uuid" : nestedRole['uuid']
                },
            "node" : shared_space_member['node'],
        }
        self.request_put(query_url, payload,expected_status=403 , busines_err_code=60005)

    def test_delete_drive_by_invited_shared_space_member(self):
        # Test user API delete a DRIVE by an invited member
        nested_role = self.getRole('READER')
        role = self.getRole('DRIVE_ADMIN')
        drive = self.create_drive_by_peter()
        user1 = self.get_user("amy")
        # Add a member to the Drive
        query_url = self.base_url + '/shared_spaces/{driveUuid}/members'.format(driveUuid=drive['uuid'])
        payload = {
            "account" : {
                "uuid" : user1['uuid'],
                "firstName" : user1['firstName'],
                "lastName" : user1['lastName'],
                "mail" : user1['mail'],
                },
            "role" : {
                "uuid" : role['uuid'],
                },
            "nestedRole": {
                "uuid": nested_role['uuid'],
            },
            "node" : {
                "uuid" : drive['uuid'],
                "name" : drive['name'],
                "nodeType" : drive['nodeType']
                },
            "type" : "DRIVE"
        }
        member = self.request_post(query_url, payload)
        self.assertEqual (member['account']['firstName'], user1['firstName'])
        self.assertEqual(member['role']['name'], role['name'])
        self.assertEqual(member['nestedRole']['name'], nested_role['name'])
        # Create a nested workGroup into the created Drive
        query_url = '{baseUrl}/shared_spaces'.format_map({
            'baseUrl' : self.base_url
            })
        payload = {
            "name": "Nested_workgroup",
            "nodeType": self.WORK_GROUP,
            "parentUuid":drive["uuid"]
        }
        nested_wg = self.request_post(query_url, payload)
        self.assertEqual(nested_wg['parentUuid'], drive['uuid'])
        # Create a workGroupNode into the nested created workGroup
        query_url = '{baseUrl}/shared_spaces/{workgroup_uuid}/nodes'.format_map({
            'baseUrl' : self.base_url,
            'workgroup_uuid' : nested_wg['uuid']})
        file_path = 'file10M'
        filesize = os.path.getsize(file_path)
        with open(file_path, 'rb') as file_stream:
            encoder = MultipartEncoder(
                fields={
                    'filesize': str(filesize),
                    'file': ('file10M.new', file_stream)
                }
            )
            monitor = MultipartEncoderMonitor(encoder, create_callback(encoder))
            headers = {
                'Accept': 'application/json',
                'Content-Type': monitor.content_type
            }
            req = requests.post(
                query_url,
                data=monitor,
                headers=headers,
                auth=HTTPBasicAuth(self.email, self.password),
                verify=self.verify)
        if DEBUG:
            data = dump.dump_all(req)
            LOGGER.debug("dump_all : %s", data.decode('utf-8'))
        # get the list of workGroupNodes
        query_url = '{baseUrl}/shared_spaces/{workgroup_uuid}/nodes'.format_map({
            'baseUrl' : self.base_url,
            'workgroup_uuid' : nested_wg['uuid']})
        workgroup_nodes = self.request_get(query_url)
        self.assertTrue(len(workgroup_nodes), "The list of workgroup nodes is empty")
        # Delete the created Drive with all its nested resources
        query_url = '{baseUrl}/shared_spaces/{drive_uuid}'.format_map({
            'baseUrl' : self.base_url,
            'drive_uuid' : drive["uuid"]})
        self.request_delete(query_url)


class TestUserApiSharedSpaceRoles(UserTestCase):
    """"Test user API SharedSpaceRoles """
    def test_find_all_shared_spaces_roles_by_node_type_default(self):
        """Test user api find all shared spaces role by nodeType."""
        query_url = '{base_url}/shared_space_roles'.format_map({
            'base_url': self.base_url,
            })
        roles = self.request_get(query_url)
        if len(roles) != 0:
            for role in roles:
                self.assertEqual(role['type'], "WORK_GROUP")

    def test_find_all_shared_spaces_roles_by_node_type_drive(self):
        """Test user api find all shared spaces role by nodeType."""
        encode = urllib.parse.urlencode({'nodeType' : 'DRIVE'})
        query_url = '{base_url}/shared_space_roles?{encode}'.format_map({
            'base_url': self.base_url,
            'encode' : encode
            })
        roles = self.request_get(query_url)
        if len(roles) != 0:
            for role in roles:
                self.assertEqual(role['type'], "DRIVE")

@unittest.skip
class TestUserApiGuest (UserTestCase):
    """"Test user API guests """
    def test_create_guest(self):
        """Test user API create a guest."""
        payload = {
            "firstName": "bart",
            "lastName": "simpson",
            "mail":"bart.simpson@int1.linshare.dev",
            "restricted":False
        }
        query_url = self.base_url + '/guests'
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

    def test_delete_guest(self):
        """Test user API create and delete guest."""
        user1 = self.get_user1()
        payload = {
            "domain": user1['domain'],
            "firstName": "homer",
            "lastName": "simpson",
            "mail":"homer.simpson@int1.linshare.dev",
            "restricted":False
        }
        query_url = self.base_url + '/guests'
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
        query_url = self.base_url + '/guests/' + data['uuid']
        req = requests.delete(
            query_url,
            headers = self.headers,
            auth=HTTPBasicAuth(self.email, self.password),
            verify=self.verify)
        self.assertEqual(req.status_code, 200)
        data = req.json()
        return data

    def test_update_guest(self):
        """Test user API create and update a guest."""
        user1 = self.get_user1()
        payload = {
            "domain": user1['domain'],
            "firstName": "lisa",
            "lastName": "simpson",
            "mail":"lisa.simpson@int1.linshare.dev",
            "restricted":False
        }
        query_url = self.base_url + '/guests'
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
        payload = {
            "domain": user1['domain'],
            "firstName": "lisa",
            "lastName": "Updated",
            "mail":"lisa.simpson@int1.linshare.dev",
            "restricted":False
        }
        query_url = self.base_url + '/guests/' + data['uuid']
        req = requests.put(
            query_url,
            data=json.dumps(payload),
            headers=self.headers,
            auth=HTTPBasicAuth(self.email, self.password),
            verify=self.verify)
        data = req.json()
        self.assertEqual (data['lastName'],'Updated')
        return data

    def test_find_shared_guest(self):
        """"Test user API create find a guest"""
        user1 = self.get_user1()
        payload = {
            "domain": user1['domain'],
            "firstName": "maggie",
            "lastName": "simpson",
            "mail":"maggie.simpson@int1.linshare.dev",
            "restricted":False
        }
        query_url = self.base_url + '/guests'
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
        query_url = self.base_url + '/guests/' + data['uuid']
        req = requests.get(
            query_url,
            headers={'Accept': 'application/json'},
            auth=HTTPBasicAuth(self.email, self.password),
            verify=self.verify
        )
        data = req.json()
        LOGGER.debug("status_code : %s", req.status_code)
        LOGGER.debug("result : %s", req.text)
        self.assertEqual(req.status_code, 200)
        self.assertEqual (data['mail'],'maggie.simpson@int1.linshare.dev')
        LOGGER.debug("data : %s", json.dumps(req.json(), sort_keys=True, indent=2))

    def test_find_all_guests(self):
        """Test user find all guests."""
        query_url = self.base_url + '/guests'
        req = requests.get(
            query_url,
            headers={'Accept': 'application/json'},
            auth=HTTPBasicAuth(self.email, self.password),
            verify=self.verify)
        LOGGER.debug("status_code : %s", req.status_code)
        LOGGER.debug("result : %s", req.text)
        self.assertEqual(req.status_code, 200)
        LOGGER.debug("data : %s", req.json())


class TestFindQuota(AdminTestCase):
    def create_shared_space(self):
        """Test user create a shared space."""
        query_url = self.user_base_url + '/shared_spaces'
        payload = {
            "name": "workgroup_test",
            "nodeType": "WORK_GROUP"
        }
        data = self.request_post(query_url, payload)
        self.assertEqual(data['name'], 'workgroup_test')
        return data

    def test_find_quota(self):
        """"Test user API create find a quota"""
        user1 = self.get_user1()
        shared_space = self.create_shared_space()
        query_url = self.user_base_url + '/quota/' + shared_space['quotaUuid']
        req = requests.get(
            query_url,
            headers={'Accept': 'application/json'},
            auth=HTTPBasicAuth(self.user1_email, self.password),
            verify=self.verify
        )
        data = self.request_get(query_url)


class TestAdminWorkGroupPattern (AdminTestCase):
    """"Test admin API workGroup pattern """

    def find_model(self):
        """Test admin find all models"""
        query_url = self.base_url + '/group_patterns/models'
        req = requests.get(
            query_url,
            headers={'Accept': 'application/json'},
            auth=HTTPBasicAuth(self.email, self.password),
            verify=self.verify)
        data = req.json()
        LOGGER.debug("status_code : %s", req.status_code)
        LOGGER.debug("result : %s", req.text)
        self.assertEqual(req.status_code, 200)
        LOGGER.debug("data : %s", req.json())
        return data

    def test_workGroup_pattern_create(self):
        """Trying to create a workGroup pattern as an admin"""
        pattern_model = self.find_model()
        query_url = self.base_url + '/group_patterns'
        payload = {
            'label':'workGroupPatternTest',
            'description': pattern_model[0]['description'],
            'searchAllGroupsQuery': pattern_model[0]['searchAllGroupsQuery'],
            'searchGroupQuery': pattern_model[0]['searchGroupQuery'],
            'groupName': pattern_model[0]['groupName'],
            'groupMember': pattern_model[0]['groupMember'],
            'groupPrefix': pattern_model[0]['groupPrefix'],
            'memberFirstName': pattern_model[0]['memberFirstName'],
            'memberLastName': pattern_model[0]['memberLastName'],
            'memberMail': pattern_model[0]['memberMail'],
            'searchPageSize': pattern_model[0]['searchPageSize']
        }
        data = self.request_post(query_url, payload)
        self.assertEqual(data['label'],"workGroupPatternTest")
        return data

    def test_delete_work_group_pattern(self):
        """Test admin API create and delete work_group_pattern."""
        work_group_pattern = self.test_workGroup_pattern_create()
        query_url = self.base_url + '/group_patterns/' + work_group_pattern['uuid']
        req = requests.delete(
            query_url,
            headers = self.headers,
            auth=HTTPBasicAuth(self.email, self.password),
            verify=self.verify)
        self.assertEqual(req.status_code, 200)
        data = req.json()
        return data

    def test_update_work_group_pattern(self):
        """Test admin API create and update a work_group_pattern."""
        work_group_pattern = self.test_workGroup_pattern_create()
        query_url = self.base_url + '/group_patterns/' + work_group_pattern['uuid']
        payload = {
            'label':'updateTestDescription',
            'description': work_group_pattern['description'],
            'searchAllGroupsQuery': work_group_pattern['searchAllGroupsQuery'],
            'searchGroupQuery': work_group_pattern['searchGroupQuery'],
            'groupName': work_group_pattern['groupName'],
            'groupMember': work_group_pattern['groupMember'],
            'groupPrefix': work_group_pattern['groupPrefix'],
            'memberFirstName': work_group_pattern['memberFirstName'],
            'memberLastName': work_group_pattern['memberLastName'],
            'memberMail': work_group_pattern['memberMail'],
            'searchPageSize': work_group_pattern['searchPageSize']
        }
        data = self.request_put(query_url, payload)
        self.assertEqual(data['label'],"updateTestDescription")
        return data

    def test_find_workGroup_pattern(self):
        """Test admin create and find a workGroup_pattern."""
        work_group_pattern = self.test_workGroup_pattern_create()
        query_url = self.base_url + '/group_patterns/' + work_group_pattern['uuid']
        req = requests.get(
            query_url,
            headers={'Accept': 'application/json'},
            auth=HTTPBasicAuth(self.email, self.password),
            verify=self.verify)
        LOGGER.debug("status_code : %s", req.status_code)
        LOGGER.debug("result : %s", req.text)
        self.assertEqual(req.status_code, 200)
        data = req.json()
        self.assertEqual(data['label'],"workGroupPatternTest")
        LOGGER.debug("data : %s", req.json())

    def test_find_all_workGroup_pattern(self):
        """Test admin find all workGroup_pattern."""
        query_url = self.base_url + '/group_patterns'
        req = requests.get(
            query_url,
            headers={'Accept': 'application/json'},
            auth=HTTPBasicAuth(self.email, self.password),
            verify=self.verify)
        LOGGER.debug("status_code : %s", req.status_code)
        LOGGER.debug("result : %s", req.text)
        self.assertEqual(req.status_code, 200)
        LOGGER.debug("data : %s", req.json())

@unittest.skip
class TestUserApiUploadRequestGroup(UserTestCase):
    """NOTE: Tests of this class need that delay before expiration , notification and activation functionalities should be enabled"""
    # Test user API upload request group
    def test_create_upload_request_group(self):
        """"Test create upload request group with one recipient"""
        query_url = '{base_url}/upload_request_groups'.format_map({
            'base_url': self.base_url
            })
        payload = {
            "label": "upload request group",
            "canDelete":True,
            "canClose":True,
            "contactList":[self.email_external1],
            "body":"test body",
            "enableNotification":True
       }
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
        self.assertEqual (data['label'],"upload request group")
        LOGGER.debug("data : %s", json.dumps(data, sort_keys=True, indent=2))
        return data

    def test_create_upload_request_group_two_recipients(self):
        """"Test create upload request group with two recipients"""
        query_url = '{base_url}/upload_request_groups'.format_map({
            'base_url': self.base_url
            })
        payload = {
            "label": "upload request group",
            "canDelete":True,
            "canClose":True,
            "contactList":[self.email_external1, self.email_external2],
            "body":"test body",
            "enableNotification":True
       }
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
        self.assertEqual (data['label'],"upload request group")
        LOGGER.debug("data : %s", json.dumps(data, sort_keys=True, indent=2))
        return data

    def test_create_upload_request_group_collective_mode_true(self):
        """"Test create upload request group with collective mode true"""
        query_url = '{base_url}/upload_request_groups?collective={collective}'.format_map({
            'base_url': self.base_url,
            'collective' : 'true'
            })
        payload = {
            "label": "upload request group",
            "canDelete":True,
            "canClose":True,
            "contactList":[self.email_external1, self.email_external2, self.email_external3],
            "body":"test body",
            "enableNotification":True
       }
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
        self.assertEqual (data['label'],"upload request group")
        LOGGER.debug("data : %s", json.dumps(data, sort_keys=True, indent=2))
        query_url = '{base_url}/upload_request_groups/{upload_req_group_uuid}/upload_requests'.format_map({
            'base_url': self.base_url,
            'upload_req_group_uuid' : data['uuid']
            })
        req = requests.get(
            query_url,
            headers=self.headers,
            auth=HTTPBasicAuth(self.email, self.password),
            verify=self.verify
        )
        data = req.json()
        LOGGER.debug("status_code : %s", req.status_code)
        LOGGER.debug("result : %s", req.text)
        self.assertEqual(req.status_code, 200)
        self.assertEqual(len(data), 1)
        return data

    def test_create_upload_request_group_collective_mode_false(self):
        """"Test create upload request group with collective mode false"""
        query_url = '{base_url}/upload_request_groups?groupMode={collective}'.format_map({
            'base_url': self.base_url,
            'collective' : 'false'
            })
        payload = {
            "label": "upload request group",
            "canDelete":True,
            "canClose":True,
            "contactList":[self.email_external1, self.email_external2, self.email_external3],
            "body":"test body",
            "enableNotification":True
       }
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
        self.assertEqual (data['label'],"upload request group")
        LOGGER.debug("data : %s", json.dumps(data, sort_keys=True, indent=2))
        query_url = '{base_url}/upload_request_groups/{upload_req_group_uuid}/upload_requests'.format_map({
            'base_url': self.base_url,
            'upload_req_group_uuid' : data['uuid']
            })
        req = requests.get(
            query_url,
            headers=self.headers,
            auth=HTTPBasicAuth(self.email, self.password),
            verify=self.verify
        )
        data = req.json()
        LOGGER.debug("status_code : %s", req.status_code)
        LOGGER.debug("result : %s", req.text)
        self.assertEqual(req.status_code, 200)
        self.assertEqual(len(data), 3)
        return data

    def test_find_upload_request_group(self):
        """"Test find upload request group"""
        upload_request_group = self.test_create_upload_request_group()
        query_url = '{base_url}/upload_request_groups/{upload_req_group_uuid}'.format_map({
            'base_url': self.base_url,
            'upload_req_group_uuid' : upload_request_group['uuid']
            })
        req = requests.get(
            query_url,
            headers=self.headers,
            auth=HTTPBasicAuth(self.email, self.password),
            verify=self.verify
        )
        data = req.json()
        LOGGER.debug("status_code : %s", req.status_code)
        LOGGER.debug("result : %s", req.text)
        self.assertEqual(req.status_code, 200)
        self.assertEqual (data['label'], upload_request_group['label'])
        LOGGER.debug("data : %s", json.dumps(req.json(), sort_keys=True, indent=2))
        return data

    def test_find_all_upload_request_group(self):
        """"Test findAll upload request group"""
        query_url = '{base_url}/upload_request_groups'.format_map({
            'base_url': self.base_url,
            })
        req = requests.get(
            query_url,
            headers=self.headers,
            auth=HTTPBasicAuth(self.email, self.password),
            verify=self.verify
        )
        data = req.json()
        LOGGER.debug("status_code : %s", req.status_code)
        LOGGER.debug("result : %s", req.text)
        self.assertEqual(req.status_code, 200)
        LOGGER.debug("data : %s", json.dumps(req.json(), sort_keys=True, indent=2))
        return data

    def test_find_all_upload_requests_of_URG(self):
        """"Test findAll upload requests of an upload request group"""
        upload_request_group = self.test_create_upload_request_group()
        query_url = '{base_url}/upload_request_groups/{upload_req_group_uuid}/upload_requests'.format_map({
            'base_url': self.base_url,
            'upload_req_group_uuid' : upload_request_group['uuid']
            })
        req = requests.get(
            query_url,
            headers=self.headers,
            auth=HTTPBasicAuth(self.email, self.password),
            verify=self.verify
        )
        data = req.json()
        LOGGER.debug("status_code : %s", req.status_code)
        LOGGER.debug("result : %s", req.text)
        self.assertEqual(req.status_code, 200)
        LOGGER.debug("data : %s", json.dumps(req.json(), sort_keys=True, indent=2))
        self.assertEqual(data[0]['nbrUploadedFiles'], 0)
        self.assertEqual(data[0]['usedSpace'], 0)

        return data

    def test_find_all_closed_upload_requests_of_URG(self):
        """"Test findAll closed upload requests of an upload request group"""
        upload_request_group = self.test_create_upload_request_group()
        query_url = '{base_url}/upload_request_groups/{upload_req_group_uuid}/upload_requests?status = {status}'.format_map({
            'base_url': self.base_url,
            'upload_req_group_uuid' : upload_request_group['uuid'],
            'status' : 'CLOSED'
            })
        req = requests.get(
            query_url,
            headers=self.headers,
            auth=HTTPBasicAuth(self.email, self.password),
            verify=self.verify
        )
        data = req.json()
        LOGGER.debug("status_code : %s", req.status_code)
        LOGGER.debug("result : %s", req.text)
        self.assertEqual(req.status_code, 200)
        LOGGER.debug("data : %s", json.dumps(req.json(), sort_keys=True, indent=2))
        return data

    def test_find_all_closed_upload_requests_group(self):
        """"Test findAll closed upload request group"""
        query_url = '{base_url}/upload_request_groups?status = {status}'.format_map({
            'base_url': self.base_url,
            'status' : 'CLOSED'
            })
        req = requests.get(
            query_url,
            headers=self.headers,
            auth=HTTPBasicAuth(self.email, self.password),
            verify=self.verify
        )
        data = req.json()
        LOGGER.debug("status_code : %s", req.status_code)
        LOGGER.debug("result : %s", req.text)
        self.assertEqual(req.status_code, 200)
        LOGGER.debug("data : %s", json.dumps(req.json(), sort_keys=True, indent=2))
        return data

    def test_find_all_audits_of_URG(self):
        """"Test findAll audits of an upload request group"""
        upload_request_group = self.test_create_upload_request_group()
        query_url = '{base_url}/upload_request_groups/{upload_req_group_uuid}/audit'.format_map({
            'base_url': self.base_url,
            'upload_req_group_uuid' : upload_request_group['uuid']
            })
        req = requests.get(
            query_url,
            headers=self.headers,
            auth=HTTPBasicAuth(self.email, self.password),
            verify=self.verify
        )
        data = req.json()
        LOGGER.debug("status_code : %s", req.status_code)
        LOGGER.debug("result : %s", req.text)
        self.assertEqual(req.status_code, 200)
        LOGGER.debug("data : %s", json.dumps(req.json(), sort_keys=True, indent=2))
        return data

    def test_update_status_URG(self):
        """Test create and update status of an upload request group."""
        upload_request_group = self.test_create_upload_request_group()
        self.assertEqual(upload_request_group['status'], 'ENABLED')
        query_url = '{base_url}/upload_request_groups/{upload_req_group_uuid}/status/{status}'.format_map({
            'base_url': self.base_url,
            'upload_req_group_uuid' : upload_request_group['uuid'],
            'status' : 'CLOSED'
            })
        req = requests.put(
            query_url,
            headers=self.headers,
            auth=HTTPBasicAuth(self.email, self.password),
            verify=self.verify
        )
        LOGGER.debug("status_code : %s", req.status_code)
        LOGGER.debug("result : %s", req.text)
        self.assertEqual(req.status_code, 200)
        data = req.json()
        self.assertEqual(data['status'], 'CLOSED')
        return data

    def test_update_upload_request_group(self):
        """Test create and update a upload request group."""
        upload_request_group = self.test_create_upload_request_group()
        self.assertEqual(upload_request_group['enableNotification'], True)
        query_url = '{base_url}/upload_request_groups/{upload_req_group_uuid}'.format_map({
            'base_url': self.base_url,
            'upload_req_group_uuid' : upload_request_group['uuid']
            })
        payload = {
            "label": upload_request_group['label'],
            "canDelete":upload_request_group['canDelete'],
            "canClose":upload_request_group['canClose'],
            "body":upload_request_group['body'],
            "enableNotification":False
       }
        req = requests.put(
            query_url,
            json.dumps(payload),
            headers= self.headers,
            auth=HTTPBasicAuth(self.email, self.password),
            verify=self.verify
        )
        LOGGER.debug("status_code : %s", req.status_code)
        LOGGER.debug("result : %s", req.text)
        self.assertEqual(req.status_code, 200)
        data = req.json()
        self.assertEqual(data['enableNotification'], False)
        return data

    def test_update_upload_request_group_with_force(self):
        """"Test create upload request group with collective mode false"""
        # 1- Create a group
        query_url = '{base_url}/upload_request_groups?groupMode={collective}'.format_map({
            'base_url': self.base_url,
            'collective' : 'false'
            })
        payload = {
            "label": "upload request group",
            "canDelete":True,
            "canClose":True,
            "contactList":[self.email_external1, self.email_external2, self.email_external3],
            "body":"test body",
            "enableNotification":True
            }
        group = self.request_post(query_url, payload)
        self.assertEqual(group['enableNotification'], True)
        # Recover all related URs
        query_url_urequests = '{base_url}/upload_request_groups/{upload_req_group_uuid}/upload_requests'.format_map({
            'base_url': self.base_url,
            'upload_req_group_uuid' : group['uuid']
            })
        upload_requests = self.request_get(query_url_urequests)
        self.assertEqual(upload_requests[0]['enableNotification'], True)
        self.assertEqual(upload_requests[1]['enableNotification'], True)
        self.assertEqual(upload_requests[2]['enableNotification'], True)
        # 2- Update a group without force
        query_url_update_grp = '{base_url}/upload_request_groups/{upload_req_group_uuid}'.format_map({
            'base_url': self.base_url,
            'upload_req_group_uuid' : group['uuid']
            })
        payload = {
            "enableNotification":False
            }
        urg_updated = self.request_put(query_url_update_grp, payload)
        self.assertEqual(urg_updated['enableNotification'], False)
        # Get URs after update the group
        upload_requests_updated = self.request_get(query_url_urequests)
        self.assertEqual(upload_requests_updated[0]['enableNotification'], False)
        self.assertEqual(upload_requests_updated[1]['enableNotification'], False)
        self.assertEqual(upload_requests_updated[2]['enableNotification'], False)
        # 3- update one upload request
        upload_request_1 = upload_requests_updated[0]
        query_url = '{base_url}/upload_requests/{upload_req_uuid}'.format_map({
            'base_url': self.base_url,
            'upload_req_uuid' : upload_request_1['uuid']
            })
        payload = {
            "enableNotification":True
            }
        updated_ur = self.request_put(query_url, payload)
        self.assertEqual(updated_ur['enableNotification'], True)
        # Update group without force parameter
        payload = {
            "enableNotification":False
            }
        urg_updated = self.request_put(query_url_update_grp, payload)
        upload_requests_updated = self.request_get(query_url_urequests)
        self.assertEqual(upload_requests_updated[0]['enableNotification'], True)
        self.assertEqual(upload_requests_updated[1]['enableNotification'], False)
        self.assertEqual(upload_requests_updated[2]['enableNotification'], False)
        # Update group with force parameter | expected all UR updated
        encoded_url = urllib.parse.urlencode({'force': "true"})
        query_url_force = '{base_url}/upload_request_groups/{upload_req_group_uuid}?{encode}'.format_map({
            'base_url': self.base_url,
            'upload_req_group_uuid' : group['uuid'],
            'encode': encoded_url
            })
        payload = {
            "enableNotification":False
            }
        urg_updated = self.request_put(query_url_force, payload)
        upload_requests_updated = self.request_get(query_url_urequests)
        self.assertEqual(upload_requests_updated[0]['enableNotification'], False)
        self.assertEqual(upload_requests_updated[1]['enableNotification'], False)
        self.assertEqual(upload_requests_updated[2]['enableNotification'], False)

    def test_add_recipient_upload_request_group_collective_mode_false(self):
        """Test create upload request group and add a new recipient the collective mode is false by default."""
        upload_request_group = self.test_create_upload_request_group()
        query_url = '{base_url}/upload_request_groups/{upload_req_group_uuid}/recipients'.format_map({
            'base_url': self.base_url,
            'upload_req_group_uuid' : upload_request_group['uuid']
            })
        payload = [
                {
                "firstName": "walker",
                "lastName": "mccallister",
                "mail": self.email_external2
                }
            ]
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
        # Test findAll upload requests of an upload request group
        query_url = '{base_url}/upload_request_groups/{upload_req_group_uuid}/upload_requests'.format_map({
            'base_url': self.base_url,
            'upload_req_group_uuid' : upload_request_group['uuid']
            })
        req = requests.get(
            query_url,
            headers=self.headers,
            auth=HTTPBasicAuth(self.email, self.password),
            verify=self.verify
        )
        self.assertEqual(req.status_code, 200)
        LOGGER.debug("status_code : %s", req.status_code)
        LOGGER.debug("result : %s", req.text)
        data = req.json()
        self.assertEqual(len(data), 2)
        return data

    def test_add_recipient_upload_request_group_collective_mode_true(self):
        """Test create upload request group and add a new recipient the collective mode is true"""
        query_url = '{base_url}/upload_request_groups?collective={collective}'.format_map({
            'base_url': self.base_url,
            'collective' : 'true'
            })
        payload = {
            "label": "upload request group",
            "canDelete":True,
            "canClose":True,
            "contactList":[self.email_external1, self.email_external2, self.email_external3],
            "body":"test body",
            "enableNotification":True
       }
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
        self.assertEqual (data['label'],"upload request group")
        LOGGER.debug("data : %s", json.dumps(data, sort_keys=True, indent=2))
        # Add new recipient to the collective upload request group
        query_url = '{base_url}/upload_request_groups/{upload_req_group_uuid}/recipients'.format_map({
            'base_url': self.base_url,
            'upload_req_group_uuid' : data['uuid']
            })
        payload = [
                {
                "firstName": "walker",
                "lastName": "mccallister",
                "mail": self.email_external4
                }
            ]
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
        # Test findAll upload requests of an upload request group
        query_url = '{base_url}/upload_request_groups/{upload_req_group_uuid}/upload_requests'.format_map({
            'base_url': self.base_url,
            'upload_req_group_uuid' : data['uuid']
            })
        req = requests.get(
            query_url,
            headers=self.headers,
            auth=HTTPBasicAuth(self.email, self.password),
            verify=self.verify
        )
        self.assertEqual(req.status_code, 200)
        LOGGER.debug("status_code : %s", req.status_code)
        LOGGER.debug("result : %s", req.text)
        data = req.json()
        self.assertEqual(len(data), 1)
        return data

    def test_archive_download_upload_request_entries_of_collective_urg(self):
        """"Test archive download of a collective URG"""
        query_url = '{base_url}/upload_request_groups?collective={collective}'.format_map({
            'base_url': self.base_url,
            'collective' : 'true'
            })
        payload = {
            "label": "upload request group",
            "canDelete":True,
            "canClose":True,
            "contactList":[self.email_external1, self.email_external2, self.email_external3],
            "body":"test body",
            "enableNotification":True
       }
        upload_request_group = self.request_post(query_url, payload)
        self.assertEqual (upload_request_group['label'],"upload request group")
        query_url = '{base_url}/upload_requests_groups/{upload_req_group_uuid}/upload_requests'.format_map({
            'base_url': self.base_test_url,
            'upload_req_group_uuid' : upload_request_group['uuid']
            })
        upload_request = self.request_get(query_url)
        self.assertEqual(len(upload_request), 1)
        # Upload first upload request entry
        self.upload_upload_request_entry(self.email_external1, self.password_external1, upload_request[0]['uploadRequestURLs'][0]['uuid'])
        # Upload a second upload request entry
        self.upload_upload_request_entry(self.email_external1, self.password_external1, upload_request[0]['uploadRequestURLs'][0]['uuid'])
        # Find the list of the uploaded upload request entries
        query_url = '{base_url}/upload_requests/{upload_req_uuid}/entries'.format_map({
            'base_url': self.base_url,
            'upload_req_uuid' : upload_request[0]['uuid']
            })
        entries = self.request_get(query_url)
        self.assertEqual(len(entries), 2)
        # Archive Download an upload request entry
        query_url = '{base_url}/upload_request_groups/{upload_req_group_uuid}/download'.format_map({
            'base_url': self.base_url,
            'upload_req_group_uuid' : upload_request_group['uuid']
            })
        req = requests.get(
            query_url,
            headers=self.headers,
            auth=HTTPBasicAuth(self.email, self.password),
            verify=self.verify
        )
        self.assertEqual(req.status_code, 200)

    def test_archive_download_upload_request_entries_of_individual_urg(self):
        """"Test create individual upload request group """
        query_url = '{base_url}/upload_request_groups?collective={collective}'.format_map({
            'base_url': self.base_url,
            'collective' : 'false'
            })
        payload = {
            "label": "upload request group",
            "canDelete":True,
            "canClose":True,
            "contactList":[self.email_external1, self.email_external2, self.email_external3],
            "body":"test body",
            "enableNotification":True
       }
        upload_request_group = self.request_post(query_url, payload)
        self.assertEqual (upload_request_group['label'],"upload request group")
        query_url = '{base_url}/upload_requests_groups/{upload_req_group_uuid}/upload_requests'.format_map({
            'base_url': self.base_test_url,
            'upload_req_group_uuid' : upload_request_group['uuid']
            })
        upload_requests = self.request_get(query_url)
        self.assertEqual(len(upload_requests), 3)
        # Upload an upload request entry
        self.upload_upload_request_entry(self.email_external1, self.password_external1, upload_requests[0]['uploadRequestURLs'][0]['uuid'])
        # Find the list of the uploaded upload request entries
        query_url = '{base_url}/upload_requests/{upload_req_uuid}/entries'.format_map({
            'base_url': self.base_url,
            'upload_req_uuid' : upload_requests[0]['uuid']
            })
        entries = self.request_get(query_url)
        self.assertEqual(len(entries), 1)
        # Archive Download an upload request entry
        query_url = '{base_url}/upload_request_groups/{upload_req_group_uuid}/download?requestUuid={requestUuid}'.format_map({
            'base_url': self.base_url,
            'upload_req_group_uuid' : upload_request_group['uuid'],
            'requestUuid' : upload_requests[0]['uuid']
            })
        req = requests.get(
            query_url,
            headers=self.headers,
            auth=HTTPBasicAuth(self.email, self.password),
            verify=self.verify
        )
        self.assertEqual(req.status_code, 200)

    def test_return_used_space_nbr_uploaded_files_urg(self):
        """"Test user API return the number of uploaded files and used space on an URG """
        upload_request_group = self.test_create_upload_request_group()
        query_url = '{base_url}/upload_requests_groups/{upload_req_group_uuid}/upload_requests'.format_map({
            'base_url': self.base_test_url,
            'upload_req_group_uuid' : upload_request_group['uuid']
            })
        upload_requests = self.request_get(query_url)
        self.assertEqual(len(upload_requests[0]['uploadRequestURLs']), 1)
        LOGGER.debug("The upload requests of the upload request group are well recovered")
        # Upload an upload request entry
        self.upload_upload_request_entry(self.email_external1, self.password_external1, upload_requests[0]['uploadRequestURLs'][0]['uuid'])
        # Find upload request's entries
        query_url = '{base_url}/upload_requests/{upload_req_uuid}/entries'.format_map({
            'base_url': self.base_url,
            'upload_req_uuid' : upload_requests[0]['uuid']
            })
        upload_requets_entries = self.request_get(query_url)
        # Check the returned nbr of uploaded files and used space of the
        # uploadRequestGroup
        query_url = '{base_url}/upload_request_groups/{upload_req_group_uuid}'.format_map({
            'base_url': self.base_url,
            'upload_req_group_uuid' : upload_request_group['uuid']
            })
        upload_request = self.request_get(query_url)
        self.assertEqual(upload_request['nbrUploadedFiles'], 1)
        self.assertEqual(upload_request['usedSpace'], upload_requets_entries[0]['size'])

@unittest.skip
class TestUserApiUploadRequestEntry(UserTestCase):
    """NOTE: Tests of this class need that delay before expiration , notification and activation functionalities should be enabled"""
    # Test user API upload request entry
    #upload_request_group_class = TestUserApiUploadRequestGroup()
    def test_create_upload_request_entry(self):
        """"Test user API create an upload request entry """
        upload_request_group = self.upload_request_group_class.test_create_upload_request_group()
        query_url = '{base_url}/upload_requests_groups/{upload_req_group_uuid}/upload_requests'.format_map({
            'base_url': self.base_test_url,
            'upload_req_group_uuid' : upload_request_group['uuid']
            })
        upload_requests = self.request_get(query_url)
        self.assertEqual(len(upload_requests[0]['uploadRequestURLs']), 1)
        LOGGER.debug("The upload requests of the upload request group are well recovered")
        # Upload an upload request entry
        query_url = self.base_test_upload_request_url
        file_path = 'file10M'
        filesize = os.path.getsize(file_path)
        with open(file_path, 'rb') as file_stream:
            encoder = MultipartEncoder(
                fields={
                    'flowTotalChunks' : '1',
                    'flowChunkSize': str(filesize),
                    'flowTotalSize': str(filesize),
                    'file': ('file10M.new', file_stream),
                    'flowIdentifier' : 'entry',
                    'flowFilename' : 'file10M',
                    "flowRelativePath" : file_path,
                    'requestUrlUuid' : upload_requests[0]['uploadRequestURLs'][0]['uuid'],
                    'password' : 'test',
                    'body':'Test upload an upload request entry',
                    'flowChunkNumber':'1'
                }
            )
            monitor = MultipartEncoderMonitor(encoder, create_callback(encoder))
            headers = {
                'Accept': 'application/json',
                'Content-Type': monitor.content_type
            }
            req = requests.post(
                query_url,
                data=monitor,
                headers=headers,
                auth=HTTPBasicAuth(self.email, self.password),
                verify=self.verify)
        self.assertEqual(req.status_code, 200)
        LOGGER.debug("status_code : %s", req.status_code)
        LOGGER.debug("result : %s", req.text)
        # Check the returned nbr of uploaded files of the uploadRequest
        query_url = '{base_url}/upload_requests/{upload_req_uuid}'.format_map({
            'base_url': self.base_url,
            'upload_req_uuid' : upload_requests[0]['uuid']
            })
        upload_request = self.request_get(query_url)
        self.assertEqual(upload_request['nbrUploadedFiles'], 1)
        self.assertEqual(upload_request['usedSpace'], filesize)

    def test_find_upload_request_entry(self):
        """"Test user API find an upload request entry """
        upload_request_group = self.upload_request_group_class.test_create_upload_request_group()
        query_url = '{base_url}/upload_requests_groups/{upload_req_group_uuid}/upload_requests'.format_map({
            'base_url': self.base_test_url,
            'upload_req_group_uuid' : upload_request_group['uuid']
            })
        req = requests.get(
            query_url,
            headers=self.headers,
            auth=HTTPBasicAuth(self.email, self.password),
            verify=self.verify
        )
        self.assertEqual(req.status_code, 200)
        LOGGER.debug("status_code : %s", req.status_code)
        LOGGER.debug("result : %s", req.text)
        data_upload_request = req.json()
        self.assertEqual(len(data_upload_request[0]['uploadRequestURLs']), 1)
        # Upload an upload request entry
        query_url = self.base_test_upload_request_url
        file_path = 'file10M'
        filesize = os.path.getsize(file_path)
        with open(file_path, 'rb') as file_stream:
            encoder = MultipartEncoder(
                fields={
                    'flowTotalChunks' : '1',
                    'flowChunkSize': str(filesize),
                    'flowTotalSize': str(filesize),
                    'file': ('file10M.new', file_stream),
                    'flowIdentifier' : 'entry',
                    'flowFilename' : 'file10M',
                    "flowRelativePath" : file_path,
                    'requestUrlUuid' : data_upload_request[0]['uploadRequestURLs'][0]['uuid'],
                    'password' : 'test',
                    'body':'Test upload an upload request entry',
                    'flowChunkNumber':'1'
                }
            )
            monitor = MultipartEncoderMonitor(encoder, create_callback(encoder))
            headers = {
                'Accept': 'application/json',
                'Content-Type': monitor.content_type
            }
            req = requests.post(
                query_url,
                data=monitor,
                headers=headers,
                auth=HTTPBasicAuth(self.email, self.password),
                verify=self.verify)
        self.assertEqual(req.status_code, 200)
        LOGGER.debug("status_code : %s", req.status_code)
        LOGGER.debug("result : %s", req.text)
        # Find upload request entry
        query_url = '{base_url}/upload_requests/{upload_req_uuid}/entries'.format_map({
            'base_url': self.base_url,
            'upload_req_uuid' : data_upload_request[0]['uuid']
            })
        req = requests.get(
            query_url,
            headers=self.headers,
            auth=HTTPBasicAuth(self.email, self.password),
            verify=self.verify
        )
        self.assertEqual(req.status_code, 200)
        LOGGER.debug("status_code : %s", req.status_code)
        LOGGER.debug("result : %s", req.text)
        data = req.json()
        self.assertEqual(len(data), 1)
        # Check the returned nbr of uploaded files of the uploadRequest
        query_url = '{base_url}/upload_requests/{upload_req_uuid}'.format_map({
            'base_url': self.base_url,
            'upload_req_uuid' : data_upload_request[0]['uuid']
            })
        upload_request = self.request_get(query_url)
        self.assertEqual(upload_request['nbrUploadedFiles'], 1)
        self.assertEqual(upload_request['usedSpace'], filesize)
        return data

    def test_delete_upload_request_entry(self):
        # Test user API delete an upload request entry
        upload_request_group = self.upload_request_group_class.test_create_upload_request_group()
        query_url = '{base_url}/upload_requests_groups/{upload_req_group_uuid}/upload_requests'.format_map({
            'base_url': self.base_test_url,
            'upload_req_group_uuid' : upload_request_group['uuid']
            })
        req = requests.get(
            query_url,
            headers=self.headers,
            auth=HTTPBasicAuth(self.email, self.password),
            verify=self.verify
        )
        self.assertEqual(req.status_code, 200)
        LOGGER.debug("status_code : %s", req.status_code)
        LOGGER.debug("result : %s", req.text)
        data_upload_request = req.json()
        self.assertEqual(len(data_upload_request[0]['uploadRequestURLs']), 1)
        # Upload an upload request entry
        query_url = self.base_test_upload_request_url
        file_path = 'file10M'
        filesize = os.path.getsize(file_path)
        with open(file_path, 'rb') as file_stream:
            encoder = MultipartEncoder(
                fields={
                    'flowTotalChunks' : '1',
                    'flowChunkSize': str(filesize),
                    'flowTotalSize': str(filesize),
                    'file': ('file10M.new', file_stream),
                    'flowIdentifier' : 'entry',
                    'flowFilename' : 'file10M',
                    "flowRelativePath" : file_path,
                    'requestUrlUuid' : data_upload_request[0]['uploadRequestURLs'][0]['uuid'],
                    'password' : 'test',
                    'body':'Test upload an upload request entry',
                    'flowChunkNumber':'1'
                }
            )
            monitor = MultipartEncoderMonitor(encoder, create_callback(encoder))
            headers = {
                'Accept': 'application/json',
                'Content-Type': monitor.content_type
            }
            req = requests.post(
                query_url,
                data=monitor,
                headers=headers,
                auth=HTTPBasicAuth(self.email, self.password),
                verify=self.verify)
        self.assertEqual(req.status_code, 200)
        LOGGER.debug("status_code : %s", req.status_code)
        LOGGER.debug("result : %s", req.text)
        # Find upload request entry
        query_url = '{base_url}/upload_requests/{upload_req_uuid}/entries'.format_map({
            'base_url': self.base_url,
            'upload_req_uuid' : data_upload_request[0]['uuid']
            })
        data_entry = self.request_get(query_url)
        self.assertEqual(data_upload_request[0]['status'], 'ENABLED')
        # Delete an upload request entry
        query_url = '{base_url}/upload_request_entries/{upload_req_entry_uuid}'.format_map({
            'base_url': self.base_url,
            'upload_req_entry_uuid' : data_entry[0]['uuid'],
            })
        self.request_delete(query_url)
        # Check the returned nbr of uploaded files of the uploadRequest
        query_url = '{base_url}/upload_requests/{upload_req_uuid}'.format_map({
            'base_url': self.base_url,
            'upload_req_uuid' : data_upload_request[0]['uuid']
            })
        upload_request = self.request_get(query_url)
        self.assertEqual(upload_request['nbrUploadedFiles'], 0)
        self.assertEqual(upload_request['usedSpace'], 0)


    def test_download_upload_request_entry(self):
        """"Test user API delete an upload request entry """
        upload_request_group = self.upload_request_group_class.test_create_upload_request_group()
        query_url = '{base_url}/upload_requests_groups/{upload_req_group_uuid}/upload_requests'.format_map({
            'base_url': self.base_test_url,
            'upload_req_group_uuid' : upload_request_group['uuid']
            })
        req = requests.get(
            query_url,
            headers=self.headers,
            auth=HTTPBasicAuth(self.email, self.password),
            verify=self.verify
        )
        self.assertEqual(req.status_code, 200)
        LOGGER.debug("status_code : %s", req.status_code)
        LOGGER.debug("result : %s", req.text)
        data_upload_request = req.json()
        self.assertEqual(len(data_upload_request[0]['uploadRequestURLs']), 1)
        # Upload an upload request entry
        query_url = self.base_test_upload_request_url
        file_path = 'file10M'
        filesize = os.path.getsize(file_path)
        with open(file_path, 'rb') as file_stream:
            encoder = MultipartEncoder(
                fields={
                    'flowTotalChunks' : '1',
                    'flowChunkSize': str(filesize),
                    'flowTotalSize': str(filesize),
                    'file': ('file10M.new', file_stream),
                    'flowIdentifier' : 'entry',
                    'flowFilename' : 'file10M',
                    "flowRelativePath" : file_path,
                    'requestUrlUuid' : data_upload_request[0]['uploadRequestURLs'][0]['uuid'],
                    'password' : 'test',
                    'body':'Test upload an upload request entry',
                    'flowChunkNumber':'1'
                }
            )
            monitor = MultipartEncoderMonitor(encoder, create_callback(encoder))
            headers = {
                'Accept': 'application/json',
                'Content-Type': monitor.content_type
            }
            req = requests.post(
                query_url,
                data=monitor,
                headers=headers,
                auth=HTTPBasicAuth(self.email, self.password),
                verify=self.verify)
        LOGGER.debug("status_code : %s", req.status_code)
        LOGGER.debug("result : %s", req.text)
        self.assertEqual(req.status_code, 200)
        # Find upload request entry
        query_url = '{base_url}/upload_requests/{upload_req_uuid}/entries'.format_map({
            'base_url': self.base_url,
            'upload_req_uuid' : data_upload_request[0]['uuid']
            })
        req = requests.get(
            query_url,
            headers=self.headers,
            auth=HTTPBasicAuth(self.email, self.password),
            verify=self.verify
        )
        self.assertEqual(req.status_code, 200)
        LOGGER.debug("status_code : %s", req.status_code)
        LOGGER.debug("result : %s", req.text)
        data_entry = req.json()
        # Download an upload request entry
        query_url = '{base_url}/upload_request_entries/{upload_req_entry_uuid}/download'.format_map({
            'base_url': self.base_url,
            'upload_req_entry_uuid' : data_entry[0]['uuid']
            })
        req = requests.get(
            query_url,
            headers=self.headers,
            auth=HTTPBasicAuth(self.email, self.password),
            verify=self.verify
        )
        LOGGER.debug("status_code : %s", req.status_code)
        LOGGER.debug("result : %s", req.text)
        self.assertEqual(req.status_code, 200)

    def test_copy_upload_request_entry(self):
        # Test user API copy an upload request entry
        upload_request_group = self.upload_request_group_class.test_create_upload_request_group()
        query_url = '{base_url}/upload_requests_groups/{upload_req_group_uuid}/upload_requests'.format_map({
            'base_url': self.base_test_url,
            'upload_req_group_uuid' : upload_request_group['uuid']
            })
        req = requests.get(
            query_url,
            headers=self.headers,
            auth=HTTPBasicAuth(self.email, self.password),
            verify=self.verify
        )
        self.assertEqual(req.status_code, 200)
        LOGGER.debug("status_code : %s", req.status_code)
        LOGGER.debug("result : %s", req.text)
        data_upload_request = req.json()
        self.assertEqual(len(data_upload_request[0]['uploadRequestURLs']), 1)
        # Upload an upload request entry
        query_url = self.base_test_upload_request_url
        file_path = 'file10M'
        filesize = os.path.getsize(file_path)
        with open(file_path, 'rb') as file_stream:
            encoder = MultipartEncoder(
                fields={
                    'flowTotalChunks' : '1',
                    'flowChunkSize': str(filesize),
                    'flowTotalSize': str(filesize),
                    'file': ('file10M.new', file_stream),
                    'flowIdentifier' : 'entry',
                    'flowFilename' : 'file10M',
                    "flowRelativePath" : file_path,
                    'requestUrlUuid' : data_upload_request[0]['uploadRequestURLs'][0]['uuid'],
                    'password' : 'test',
                    'body':'Test upload an upload request entry',
                    'flowChunkNumber':'1'
                }
            )
            monitor = MultipartEncoderMonitor(encoder, create_callback(encoder))
            headers = {
                'Accept': 'application/json',
                'Content-Type': monitor.content_type
            }
            req = requests.post(
                query_url,
                data=monitor,
                headers=headers,
                auth=HTTPBasicAuth(self.email, self.password),
                verify=self.verify)
        LOGGER.debug("status_code : %s", req.status_code)
        LOGGER.debug("result : %s", req.text)
        self.assertEqual(req.status_code, 200)
        # Find upload request entry
        query_url = '{base_url}/upload_requests/{upload_req_uuid}/entries'.format_map({
            'base_url': self.base_url,
            'upload_req_uuid' : data_upload_request[0]['uuid']
            })
        req = requests.get(
            query_url,
            headers=self.headers,
            auth=HTTPBasicAuth(self.email, self.password),
            verify=self.verify
        )
        self.assertEqual(req.status_code, 200)
        LOGGER.debug("status_code : %s", req.status_code)
        LOGGER.debug("result : %s", req.text)
        data_entry = req.json()
        # Before copying an upload request entry we need to close the upload
        # request
        self.assertEqual(data_upload_request[0]['status'], 'ENABLED')
        query_url = '{base_url}/upload_requests/{upload_req_uuid}/status/{status}'.format_map({
            'base_url': self.base_url,
            'upload_req_uuid' : data_upload_request[0]['uuid'],
            'status' : 'CLOSED'
            })
        req = requests.put(
            query_url,
            headers=self.headers,
            auth=HTTPBasicAuth(self.email, self.password),
            verify=self.verify
        )
        LOGGER.debug("status_code : %s", req.status_code)
        LOGGER.debug("result : %s", req.text)
        self.assertEqual(req.status_code, 200)
        data = req.json()
        self.assertEqual(data['status'], 'CLOSED')
        # Copy an upload request entry
        query_url = '{base_url}/upload_request_entries/{upload_req_entry_uuid}/copy'.format_map({
            'base_url': self.base_url,
            'upload_req_entry_uuid' : data_entry[0]['uuid']
            })
        req = requests.post(
            query_url,
            headers=self.headers,
            auth=HTTPBasicAuth(self.email, self.password),
            verify=self.verify
        )
        self.assertEqual(req.status_code, 200)
        LOGGER.debug("status_code : %s", req.status_code)
        LOGGER.debug("result : %s", req.text)

    def test_find_all_audits_of_URE(self):
        """"Test user API create an upload request entry """
        upload_request_group = self.upload_request_group_class.test_create_upload_request_group()
        query_url = '{base_url}/upload_requests_groups/{upload_req_group_uuid}/upload_requests'.format_map({
            'base_url': self.base_test_url,
            'upload_req_group_uuid' : upload_request_group['uuid']
            })
        data = self.request_get(query_url)
        self.assertEqual(len(data[0]['uploadRequestURLs']), 1)
        LOGGER.debug("The upload requests of the upload request group are well recovered")
        # Upload an upload request entry
        query_url = self.base_test_upload_request_url
        file_path = 'file10M'
        filesize = os.path.getsize(file_path)
        with open(file_path, 'rb') as file_stream:
            encoder = MultipartEncoder(
                fields={
                    'flowTotalChunks' : '1',
                    'flowChunkSize': str(filesize),
                    'flowTotalSize': str(filesize),
                    'file': ('file10M.new', file_stream),
                    'flowIdentifier' : 'entry',
                    'flowFilename' : 'file10M',
                    "flowRelativePath" : file_path,
                    'requestUrlUuid' : data[0]['uploadRequestURLs'][0]['uuid'],
                    'password' : '',
                    'body':'Test upload an upload request entry',
                    'flowChunkNumber':'1'
                }
            )
            monitor = MultipartEncoderMonitor(encoder, create_callback(encoder))
            headers = {
                'Accept': 'application/json',
                'Content-Type': monitor.content_type
            }
            req = requests.post(
                query_url,
                data=monitor,
                headers=headers,
                auth=HTTPBasicAuth(self.email, self.password),
                verify=self.verify)
        self.assertEqual(req.status_code, 200)
        LOGGER.debug("status_code : %s", req.status_code)
        LOGGER.debug("result : %s", req.text)
        # Test findAll audits of an upload request Entry
        query_url = '{base_url}/upload_request_groups/{upload_req_group_uuid}/audit?entriesLogsOnly=true'.format_map({
            'base_url': self.base_url,
            'upload_req_group_uuid' : upload_request_group['uuid']
            })
        data = self.request_get(query_url)
        self.assertGreater(len(data),0)

@unittest.skip
class TestUserApiUploadRequestExternal(UserTestCase):
    """NOTE: Tests of this class need that delay before expiration , notification and activation functionalities should be enabled"""
    # Test user API upload request for externals
    #upload_request_group_class = TestUserApiUploadRequestGroup()
    def test_close_upload_request_by_external(self):
        """"Test close an upload request by an external user"""
        upload_request_group = self.upload_request_group_class.test_create_upload_request_group()
        query_url = '{base_url}/upload_requests_groups/{upload_req_group_uuid}/upload_requests'.format_map({
            'base_url': self.base_test_url,
            'upload_req_group_uuid' : upload_request_group['uuid']
            })
        data_upload_request = self.request_get(query_url)
        self.assertEqual(data_upload_request[0]['status'], 'ENABLED')
        self.assertEqual(len(data_upload_request[0]['uploadRequestURLs']), 1)
        # Upload upload request entry
        self.upload_upload_request_entry(self.email_external1, self.password_external1, data_upload_request[0]['uploadRequestURLs'][0]['uuid'])
        # Close an uploadRequest by an external
        query_url = '{base_external_url}/requests/{upload_url_uuid}'.format_map({
            'base_external_url': self.base_external_url,
            'upload_url_uuid' : data_upload_request[0]['uploadRequestURLs'][0]['uuid']
            })
        data = self.request_put(query_url)
        # Check the updated status to CLOSED after the update by the external
        # user
        query_url = '{base_url}/upload_requests_groups/{upload_req_group_uuid}/upload_requests'.format_map({
            'base_url': self.base_test_url,
            'upload_req_group_uuid' : upload_request_group['uuid']
            })
        data_upload_request = self.request_get(query_url)
        self.assertEqual(data_upload_request[0]['status'], 'CLOSED')
        return data

    def test_update_upload_group_request_by_issuer(self):
        # Test update upload request group by issuer
        upload_request_group = self.upload_request_group_class.test_create_upload_request_group()
        self.assertEqual(upload_request_group['status'], 'ENABLED')
        self.assertEqual(upload_request_group['label'], 'upload request group')
        self.assertEqual(upload_request_group['enableNotification'], True)
        query_url_get_ur = '{base_url}/upload_requests_groups/{upload_req_group_uuid}/upload_requests'.format_map({
            'base_url': self.base_test_url,
            'upload_req_group_uuid' : upload_request_group['uuid']
            })
        data_upload_request = self.request_get(query_url_get_ur)
        self.assertEqual(data_upload_request[0]['status'], 'ENABLED')
        self.assertTrue(data_upload_request[0]['uploadRequestURLs'])
        # Update URG from the issuer
        query_url = '{base_url}/upload_request_groups/{upload_req_group_uuid}'.format_map({
            'base_url': self.base_url,
            'upload_req_group_uuid' : upload_request_group['uuid']
            })
        payload = {
            "label": "updated label",
            "canDelete":upload_request_group['canDelete'],
            "canClose":upload_request_group['canClose'],
            "body":upload_request_group['body'],
            "enableNotification":True
       }
        data_upload_request_group_updated_by_issuer = self.request_put(query_url, payload)
        # Check updates from groups endpoint
        data_upload_request = self.request_get(query_url_get_ur)
        self.assertEqual(data_upload_request[0]['label'], data_upload_request_group_updated_by_issuer['label'], "Update fails")
        self.assertEqual(data_upload_request[0]['enableNotification'], True)
        # Check if recipient receive updates
        query_url_ext = '{base_external_url}/requests/{upload_url_uuid}'.format_map({
            'base_external_url': self.base_external_url,
            'upload_url_uuid' : data_upload_request[0]['uploadRequestURLs'][0]['uuid']
            })
        data_upload_request_from_ext = requests.get(
            query_url_ext,
            headers=self.headers,
            auth=HTTPBasicAuth(self.email_external1, self.password_external1),
            verify=self.verify
        ).json()
        self.assertEqual(data_upload_request_from_ext['subject'], data_upload_request_group_updated_by_issuer['label'], "The recipient didn't receive the updates")


    def test_delete_upload_request_entry_by_external_no_payload(self):
        """"Test delete an upload request entry by an external user"""
        upload_request_group = self.upload_request_group_class.test_create_upload_request_group()
        query_url = '{base_url}/upload_requests_groups/{upload_req_group_uuid}/upload_requests'.format_map({
            'base_url': self.base_test_url,
            'upload_req_group_uuid' : upload_request_group['uuid']
            })
        req = requests.get(
            query_url,
            headers=self.headers,
            auth=HTTPBasicAuth(self.email, self.password),
            verify=self.verify
        )
        self.assertEqual(req.status_code, 200)
        LOGGER.debug("status_code : %s", req.status_code)
        LOGGER.debug("result : %s", req.text)
        data_upload_request = req.json()
        self.assertEqual(len(data_upload_request[0]['uploadRequestURLs']), 1)
        # Upload an upload request entry
        query_url = self.base_test_upload_request_url
        file_path = 'file10M'
        filesize = os.path.getsize(file_path)
        with open(file_path, 'rb') as file_stream:
            encoder = MultipartEncoder(
                fields={
                    'flowTotalChunks' : '1',
                    'flowChunkSize': str(filesize),
                    'flowTotalSize': str(filesize),
                    'file': ('file10M.new', file_stream),
                    'flowIdentifier' : 'entry',
                    'flowFilename' : 'file10M',
                    "flowRelativePath" : file_path,
                    'requestUrlUuid' : data_upload_request[0]['uploadRequestURLs'][0]['uuid'],
                    'password' : 'test',
                    'body':'Test upload an upload request entry',
                    'flowChunkNumber':'1'
                }
            )
            monitor = MultipartEncoderMonitor(encoder, create_callback(encoder))
            headers = {
                'Accept': 'application/json',
                'Content-Type': monitor.content_type
            }
            req = requests.post(
                query_url,
                data=monitor,
                headers=headers,
                auth=HTTPBasicAuth(self.email_external1, self.password_external1),
                verify=self.verify)
        self.assertEqual(req.status_code, 200)
        LOGGER.debug("status_code : %s", req.status_code)
        LOGGER.debug("result : %s", req.text)
        # Find upload request entry
        query_url = '{base_url}/upload_requests/{upload_req_uuid}/entries'.format_map({
            'base_url': self.base_url,
            'upload_req_uuid' : data_upload_request[0]['uuid']
            })
        req = requests.get(
            query_url,
            headers=self.headers,
            auth=HTTPBasicAuth(self.email, self.password),
            verify=self.verify
        )
        self.assertEqual(req.status_code, 200)
        LOGGER.debug("status_code : %s", req.status_code)
        LOGGER.debug("result : %s", req.text)
        data_entry = req.json()
        # Delete an upload request entry by an external
        query_url = '{base_external_url}/requests/{upload_req_url}/entries/{upload_req_entry_uuid}'.format_map({
            'base_external_url': self.base_external_url,
            'upload_req_url' : data_upload_request[0]['uploadRequestURLs'][0]['uuid'],
            'upload_req_entry_uuid' : data_entry[0]['uuid'],
            })
        req = requests.delete(
            query_url,
            headers=self.headers,
            auth=HTTPBasicAuth(self.email_external1, self.password_external1),
            verify=self.verify
        )
        LOGGER.debug("status_code : %s", req.status_code)
        LOGGER.debug("result : %s", req.text)
        self.assertEqual(req.status_code, 200)

    def test_delete_upload_request_entry_by_external_no_payload_no_content_type(self):
        """"Test delete an upload request entry by an external user"""
        upload_request_group = self.upload_request_group_class.test_create_upload_request_group()
        query_url = '{base_url}/upload_requests_groups/{upload_req_group_uuid}/upload_requests'.format_map({
            'base_url': self.base_test_url,
            'upload_req_group_uuid' : upload_request_group['uuid']
            })
        req = requests.get(
            query_url,
            headers=self.headers,
            auth=HTTPBasicAuth(self.email, self.password),
            verify=self.verify
        )
        self.assertEqual(req.status_code, 200)
        LOGGER.debug("status_code : %s", req.status_code)
        LOGGER.debug("result : %s", req.text)
        data_upload_request = req.json()
        self.assertEqual(len(data_upload_request[0]['uploadRequestURLs']), 1)
        # Upload an upload request entry
        query_url = self.base_test_upload_request_url
        file_path = 'file10M'
        filesize = os.path.getsize(file_path)
        with open(file_path, 'rb') as file_stream:
            encoder = MultipartEncoder(
                fields={
                    'flowTotalChunks' : '1',
                    'flowChunkSize': str(filesize),
                    'flowTotalSize': str(filesize),
                    'file': ('file10M.new', file_stream),
                    'flowIdentifier' : 'entry',
                    'flowFilename' : 'file10M',
                    "flowRelativePath" : file_path,
                    'requestUrlUuid' : data_upload_request[0]['uploadRequestURLs'][0]['uuid'],
                    'password' : 'test',
                    'body':'Test upload an upload request entry',
                    'flowChunkNumber':'1'
                }
            )
            monitor = MultipartEncoderMonitor(encoder, create_callback(encoder))
            headers = {
                'Accept': 'application/json',
                'Content-Type': monitor.content_type
            }
            req = requests.post(
                query_url,
                data=monitor,
                headers=headers,
                auth=HTTPBasicAuth(self.email_external1, self.password_external1),
                verify=self.verify)
        self.assertEqual(req.status_code, 200)
        LOGGER.debug("status_code : %s", req.status_code)
        LOGGER.debug("result : %s", req.text)
        # Find upload request entry
        query_url = '{base_url}/upload_requests/{upload_req_uuid}/entries'.format_map({
            'base_url': self.base_url,
            'upload_req_uuid' : data_upload_request[0]['uuid']
            })
        req = requests.get(
            query_url,
            headers=self.headers,
            auth=HTTPBasicAuth(self.email, self.password),
            verify=self.verify
        )
        self.assertEqual(req.status_code, 200)
        LOGGER.debug("status_code : %s", req.status_code)
        LOGGER.debug("result : %s", req.text)
        data_entry = req.json()
        # Delete an upload request entry by an external
        query_url = '{base_external_url}/requests/{upload_req_url}/entries/{upload_req_entry_uuid}'.format_map({
            'base_external_url': self.base_external_url,
            'upload_req_url' : data_upload_request[0]['uploadRequestURLs'][0]['uuid'],
            'upload_req_entry_uuid' : data_entry[0]['uuid'],
            })
        req = requests.delete(
            query_url,
            auth=HTTPBasicAuth(self.email_external1, self.password_external1),
            verify=self.verify
        )
        LOGGER.debug("status_code : %s", req.status_code)
        LOGGER.debug("result : %s", req.text)
        self.assertEqual(req.status_code, 200)

    def test_delete_upload_request_entry_by_external_payload(self):
        """"Test delete an upload request entry by an external user"""
        upload_request_group = self.upload_request_group_class.test_create_upload_request_group()
        query_url = '{base_url}/upload_requests_groups/{upload_req_group_uuid}/upload_requests'.format_map({
            'base_url': self.base_test_url,
            'upload_req_group_uuid' : upload_request_group['uuid']
            })
        req = requests.get(
            query_url,
            headers=self.headers,
            auth=HTTPBasicAuth(self.email, self.password),
            verify=self.verify
        )
        self.assertEqual(req.status_code, 200)
        LOGGER.debug("status_code : %s", req.status_code)
        LOGGER.debug("result : %s", req.text)
        data_upload_request = req.json()
        self.assertEqual(len(data_upload_request[0]['uploadRequestURLs']), 1)
        # Upload an upload request entry
        query_url = self.base_test_upload_request_url
        file_path = 'file10M'
        filesize = os.path.getsize(file_path)
        with open(file_path, 'rb') as file_stream:
            encoder = MultipartEncoder(
                fields={
                    'flowTotalChunks' : '1',
                    'flowChunkSize': str(filesize),
                    'flowTotalSize': str(filesize),
                    'file': ('file10M.new', file_stream),
                    'flowIdentifier' : 'entry',
                    'flowFilename' : 'file10M',
                    "flowRelativePath" : file_path,
                    'requestUrlUuid' : data_upload_request[0]['uploadRequestURLs'][0]['uuid'],
                    'password' : 'test',
                    'body':'Test upload an upload request entry',
                    'flowChunkNumber':'1'
                }
            )
            monitor = MultipartEncoderMonitor(encoder, create_callback(encoder))
            headers = {
                'Accept': 'application/json',
                'Content-Type': monitor.content_type
            }
            req = requests.post(
                query_url,
                data=monitor,
                headers=headers,
                auth=HTTPBasicAuth(self.email_external1, self.password_external1),
                verify=self.verify)
        self.assertEqual(req.status_code, 200)
        LOGGER.debug("status_code : %s", req.status_code)
        LOGGER.debug("result : %s", req.text)
        # Find upload request entry
        query_url = '{base_url}/upload_requests/{upload_req_uuid}/entries'.format_map({
            'base_url': self.base_url,
            'upload_req_uuid' : data_upload_request[0]['uuid']
            })
        req = requests.get(
            query_url,
            headers=self.headers,
            auth=HTTPBasicAuth(self.email, self.password),
            verify=self.verify
        )
        self.assertEqual(req.status_code, 200)
        LOGGER.debug("status_code : %s", req.status_code)
        LOGGER.debug("result : %s", req.text)
        data_entry = req.json()
        # Delete an upload request entry by an external
        query_url = '{base_external_url}/requests/{upload_req_url}/entries/'.format_map({
            'base_external_url': self.base_external_url,
            'upload_req_url' : data_upload_request[0]['uploadRequestURLs'][0]['uuid']
            })
        payload = {
            'uuid': data_entry[0]['uuid'],
            'name': data_entry[0]['name']
        }
        req = requests.delete(
            query_url,
            data=json.dumps(payload),
            headers=self.headers,
            auth=HTTPBasicAuth(self.email_external1, self.password_external1),
            verify=self.verify
        )
        LOGGER.debug("status_code : %s", req.status_code)
        LOGGER.debug("result : %s", req.text)
        self.assertEqual(req.status_code, 200)

    def test_find_all_entries_group_individual_mode(self):
        """"Test create individual upload request group"""
        query_url = '{base_url}/upload_request_groups?groupMode={groupMode}'.format_map({
            'base_url': self.base_url,
            'groupMode' : 'false'
            })
        payload = {
            "label": "upload request group",
            "canDelete":True,
            "canClose":True,
            "contactList":[self.email_external1, self.email_external2, self.email_external3],
            "body":"test body",
            "enableNotification":True
       }
        upload_request_group = self.request_post(query_url, payload)
        self.assertEqual (upload_request_group['label'],"upload request group")
        # Test get all uploadRequests of an individual uploadRequest group
        query_url = '{base_url}/upload_requests_groups/{upload_req_group_uuid}/upload_requests'.format_map({
            'base_url': self.base_test_url,
            'upload_req_group_uuid' : upload_request_group['uuid']
            })
        req = requests.get(
            query_url,
            headers=self.headers,
            auth=HTTPBasicAuth(self.email, self.password),
            verify=self.verify
        )
        self.assertEqual(req.status_code, 200)
        LOGGER.debug("status_code : %s", req.status_code)
        LOGGER.debug("result : %s", req.text)
        data_upload_request = req.json()
        self.assertEqual(len(data_upload_request), 3)
        # Test create an uploadRequestEntry by ecternal1
        query_url = self.base_test_upload_request_url
        file_path = 'file10M'
        filesize = os.path.getsize(file_path)
        with open(file_path, 'rb') as file_stream:
            encoder = MultipartEncoder(
                fields={
                    'flowTotalChunks' : '1',
                    'flowChunkSize': str(filesize),
                    'flowTotalSize': str(filesize),
                    'file': ('file10M.new', file_stream),
                    'flowIdentifier' : 'entry',
                    'flowFilename' : 'file10M',
                    "flowRelativePath" : file_path,
                    'requestUrlUuid' : data_upload_request[0]['uploadRequestURLs'][0]['uuid'],
                    'password' : 'test',
                    'body':'Test upload an upload request entry',
                    'flowChunkNumber':'1'
                }
            )
            monitor = MultipartEncoderMonitor(encoder, create_callback(encoder))
            headers = {
                'Accept': 'application/json',
                'Content-Type': monitor.content_type
            }
            req = requests.post(
                query_url,
                data=monitor,
                headers=headers,
                auth=HTTPBasicAuth(self.email_external1, self.password_external1),
                verify=self.verify)
        self.assertEqual(req.status_code, 200)
        LOGGER.debug("status_code : %s", req.status_code)
        LOGGER.debug("result : %s", req.text)
        # Test create an uploadRequestEntry by ecternal2
        query_url = self.base_test_upload_request_url
        file_path = 'file10M'
        filesize = os.path.getsize(file_path)
        with open(file_path, 'rb') as file_stream:
            encoder = MultipartEncoder(
                fields={
                    'flowTotalChunks' : '1',
                    'flowChunkSize': str(filesize),
                    'flowTotalSize': str(filesize),
                    'file': ('file10M.new', file_stream),
                    'flowIdentifier' : 'entry',
                    'flowFilename' : 'file10M',
                    "flowRelativePath" : file_path,
                    'requestUrlUuid' : data_upload_request[1]['uploadRequestURLs'][0]['uuid'],
                    'password' : 'test',
                    'body':'Test upload an upload request entry',
                    'flowChunkNumber':'1'
                }
            )
            monitor = MultipartEncoderMonitor(encoder, create_callback(encoder))
            headers = {
                'Accept': 'application/json',
                'Content-Type': monitor.content_type
            }
            req = requests.post(
                query_url,
                data=monitor,
                headers=headers,
                auth=HTTPBasicAuth(self.email_external2, self.password_external2),
                verify=self.verify)
        self.assertEqual(req.status_code, 200)
        LOGGER.debug("status_code : %s", req.status_code)
        LOGGER.debug("result : %s", req.text)
        # Test findAll uploadRequestEntries
        query_url = '{base_external_url}/requests/{upload_req_url_uuid}/entries'.format_map({
            'base_external_url': self.base_external_url,
            'upload_req_url_uuid' : data_upload_request[0]['uploadRequestURLs'][0]['uuid']
            })
        req = requests.get(
            query_url,
            headers=self.headers,
            auth=HTTPBasicAuth(self.email_external1, self.password_external1),
            verify=self.verify
        )
        self.assertEqual(req.status_code, 200)
        LOGGER.debug("status_code : %s", req.status_code)
        LOGGER.debug("result : %s", req.text)
        data = req.json()
        self.assertEqual(len(data), 1)
        return data

    def test_find_all_entries_group_collective_mode(self):
        """"Test create upload request group collective mode"""
        query_url = '{base_url}/upload_request_groups?collective={groupMode}'.format_map({
            'base_url': self.base_url,
            'groupMode' : 'true'
            })
        payload = {
            "label": "upload request group",
            "canDelete":True,
            "canClose":True,
            "contactList":[self.email_external1, self.email_external2, self.email_external3],
            "body":"test body",
            "enableNotification":True
       }
        upload_request_group = self.request_post(query_url, payload)
        self.assertEqual (upload_request_group['label'],"upload request group")
        # Test get all uploadRequests of a collective uploadRequest
        query_url = '{base_url}/upload_requests_groups/{upload_req_group_uuid}/upload_requests'.format_map({
            'base_url': self.base_test_url,
            'upload_req_group_uuid' : upload_request_group['uuid']
            })
        data_upload_request = self.request_get(query_url)
        self.assertEqual(len(data_upload_request), 1)
        # Test create an uploadRequestEntry by ecternal1
        self.upload_upload_request_entry(self.email_external1, self.password_external1, data_upload_request[0]['uploadRequestURLs'][0]['uuid'])
        self.upload_upload_request_entry(self.email_external1, self.password_external1, data_upload_request[0]['uploadRequestURLs'][1]['uuid'])
        # Test findAll uploadRequestEntries
        query_url = '{base_external_url}/requests/{upload_req_url_uuid}/entries'.format_map({
            'base_external_url': self.base_external_url,
            'upload_req_url_uuid' : data_upload_request[0]['uploadRequestURLs'][0]['uuid']
            })
        req = requests.get(
            query_url,
            headers=self.headers,
            auth=HTTPBasicAuth(self.email_external1, self.password_external1),
            verify=self.verify
        )
        self.assertEqual(req.status_code, 200)
        LOGGER.debug("status_code : %s", req.status_code)
        LOGGER.debug("result : %s", req.text)
        data = req.json()
        self.assertEqual(len(data), 2)
        return data

    def test_download_upload_request_entry_by_external(self):
        """"Test download an upload request entry by an external"""
        upload_request_group = self.upload_request_group_class.test_create_upload_request_group()
        query_url = '{base_url}/upload_requests_groups/{upload_req_group_uuid}/upload_requests'.format_map({
            'base_url': self.base_test_url,
            'upload_req_group_uuid' : upload_request_group['uuid']
            })
        data_upload_request = self.request_get(query_url)
        self.assertEqual(len(data_upload_request[0]['uploadRequestURLs']), 1)
        # Upload an upload request entry
        query_url = self.base_test_upload_request_url
        file_path = 'Linagora-logo.png'
        filesize = os.path.getsize(file_path)
        with open(file_path, 'rb') as file_stream:
            encoder = MultipartEncoder(
                fields={
                    'flowTotalChunks' : '1',
                    'flowChunkSize': str(filesize),
                    'flowTotalSize': str(filesize),
                    'file': ('Linagora-logo.png.new', file_stream),
                    'flowIdentifier' : 'entry',
                    'flowFilename' : 'Linagora-logo.png',
                    "flowRelativePath" : file_path,
                    'requestUrlUuid' : data_upload_request[0]['uploadRequestURLs'][0]['uuid'],
                    'password' : '',
                    'body':'Test upload an upload request entry',
                    'flowChunkNumber':'1',
                    'flowCurrentChunkSize':str(filesize)
                }
            )
            monitor = MultipartEncoderMonitor(encoder, create_callback(encoder))
            headers = {
                'Accept': 'application/json',
                'Content-Type': monitor.content_type
            }
            req = requests.post(
                query_url,
                data=monitor,
                headers=headers,
                auth=HTTPBasicAuth(self.email_external1, self.password_external1),
                verify=self.verify)
        self.assertEqual(req.status_code, 200)
        LOGGER.debug("status_code : %s", req.status_code)
        LOGGER.debug("result : %s", req.text)
        # Find upload request entry
        query_url = '{base_url}/upload_requests/{upload_req_uuid}/entries'.format_map({
            'base_url': self.base_url,
            'upload_req_uuid' : data_upload_request[0]['uuid']
            })
        data_entry = self.request_get(query_url)
        # Download an upload request entry by an external
        query_url = '{base_external_url}/requests/{upload_req_url}/entries/{upload_req_entry_uuid}/download'.format_map({
            'base_external_url': self.base_external_url,
            'upload_req_url' : data_upload_request[0]['uploadRequestURLs'][0]['uuid'],
            'upload_req_entry_uuid' : data_entry[0]['uuid']
            })
        req = requests.get(
            query_url,
            headers=self.headers,
            auth=HTTPBasicAuth(self.email_external1, self.email_external1),
            verify=self.verify
        )
        self.assertEqual(req.status_code, 200)
        LOGGER.debug("status_code : %s", req.status_code)
        LOGGER.debug("result : %s", req.text)

    def test_thumbnail_upload_request_entry_by_external(self):
        """"Test thumbnail an upload request entry by an external"""
        upload_request_group = self.upload_request_group_class.test_create_upload_request_group()
        query_url = '{base_url}/upload_requests_groups/{upload_req_group_uuid}/upload_requests'.format_map({
            'base_url': self.base_test_url,
            'upload_req_group_uuid' : upload_request_group['uuid']
            })
        data_upload_request = self.request_get(query_url)
        self.assertEqual(len(data_upload_request[0]['uploadRequestURLs']), 1)
        # Upload an upload request entry"""
        query_url = self.base_test_upload_request_url
        file_path = 'Linagora-logo.png'
        filesize = os.path.getsize(file_path)
        with open(file_path, 'rb') as file_stream:
            encoder = MultipartEncoder(
                fields={
                    'flowTotalChunks' : '1',
                    'flowChunkSize': str(filesize),
                    'flowTotalSize': str(filesize),
                    'file': ('Linagora-logo.png.new', file_stream),
                    'flowIdentifier' : 'entry',
                    'flowFilename' : 'Linagora-logo.png',
                    "flowRelativePath" : file_path,
                    'requestUrlUuid' : data_upload_request[0]['uploadRequestURLs'][0]['uuid'],
                    'password' : '',
                    'body':'Test upload an upload request entry',
                    'flowChunkNumber':'1',
                    'flowCurrentChunkSize':str(filesize)
                }
            )
            monitor = MultipartEncoderMonitor(encoder, create_callback(encoder))
            headers = {
                'Accept': 'application/json',
                'Content-Type': monitor.content_type
            }
            req = requests.post(
                query_url,
                data=monitor,
                headers=headers,
                auth=HTTPBasicAuth(self.email_external1, self.password_external1),
                verify=self.verify)
        self.assertEqual(req.status_code, 200)
        LOGGER.debug("status_code : %s", req.status_code)
        LOGGER.debug("result : %s", req.text)
        # Find upload request entry
        query_url = '{base_url}/upload_requests/{upload_req_uuid}/entries'.format_map({
            'base_url': self.base_url,
            'upload_req_uuid' : data_upload_request[0]['uuid']
            })
        data_entry = self.request_get(query_url)
        # Get thumbnail of an upload request entry by an external
        query_url = '{base_external_url}/requests/{upload_req_url}/entries/{upload_req_entry_uuid}/thumbnail'.format_map({
            'base_external_url': self.base_external_url,
            'upload_req_url' : data_upload_request[0]['uploadRequestURLs'][0]['uuid'],
            'upload_req_entry_uuid' : data_entry[0]['uuid']
            })
        req = requests.get(
            query_url,
            headers=self.headers,
            auth=HTTPBasicAuth(self.email_external1, self.email_external1),
            verify=self.verify
        )
        self.assertEqual(req.status_code, 200)
        LOGGER.debug("status_code : %s", req.status_code)
        LOGGER.debug("result : %s", req.text)

@unittest.skip
class TestUserApiUploadRequest(UserTestCase):
    """"Test user API upload request """
    #upload_request_group = TestUserApiUploadRequestGroup()
    def test_find_upload_request(self):
        expected = ['activationDate', 'body','canClose','canDeleteDocument', 'creationDate',
                     'modificationDate','closed','collective', 'enableNotification',
                    'expiryDate', 'label', 'pristine','locale', 'protectedByPassword',
                    'maxFileCount', 'maxDepositSize','maxFileSize','notificationDate', 'owner',
                    'recipients', 'status', 'usedSpace', 'nbrUploadedFiles','uuid']
        # Test find an upload request
        upload_request = self.upload_request_group.test_find_all_upload_requests_of_URG()
        query_url = '{base_url}/upload_requests/{upload_req_uuid}'.format_map({
            'base_url': self.base_url,
            'upload_req_uuid' : upload_request[0]['uuid']
            })
        req = requests.get(
            query_url,
            headers=self.headers,
            auth=HTTPBasicAuth(self.email, self.password),
            verify=self.verify
        )
        self.assertEqual(req.status_code, 200)
        LOGGER.debug("status_code : %s", req.status_code)
        LOGGER.debug("result : %s", req.text)
        data = req.json()
        LOGGER.debug("data : %s", json.dumps(req.json(), sort_keys=True, indent=2))
        self._assertJsonPayload(expected, data)
        return data

    def test_update_status_upload_request(self):
        """Test update status of an upload request."""
        upload_request = self.test_find_upload_request()
        self.assertEqual(upload_request['status'], 'ENABLED')
        query_url = '{base_url}/upload_requests/{upload_req_uuid}/status/{status}'.format_map({
            'base_url': self.base_url,
            'upload_req_uuid' : upload_request['uuid'],
            'status' : 'CLOSED'
            })
        req = requests.put(
            query_url,
            headers=self.headers,
            auth=HTTPBasicAuth(self.email, self.password),
            verify=self.verify
        )
        LOGGER.debug("status_code : %s", req.status_code)
        LOGGER.debug("result : %s", req.text)
        self.assertEqual(req.status_code, 200)
        data = req.json()
        self.assertEqual(data['status'], 'CLOSED')
        self.assertEqual(upload_request['nbrUploadedFiles'], 0)
        self.assertEqual(upload_request['usedSpace'], 0)
        return data

    def test_update_status_upload_request_copy_true(self):
        """"Test create upload request group"""
        query_url = '{base_url}/upload_request_groups'.format_map({
            'base_url': self.base_url
            })
        payload = {
            "label": "upload request group",
            "canDelete":True,
            "canClose":True,
            "contactList":["external1@linshare.org"],
            "body":"test body",
            "enableNotification":False,
       }
        req = requests.post(
            query_url,
            data=json.dumps(payload),
            headers=self.headers,
            auth=HTTPBasicAuth(self.email, self.password),
            verify=self.verify)
        LOGGER.debug("status_code : %s", req.status_code)
        LOGGER.debug("result : %s", req.text)
        self.assertEqual(req.status_code, 200)
        upload_request_group = req.json()
        self.assertEqual (upload_request_group['label'],"upload request group")
        # find upoadRequest all uploadRequests of an URG
        query_url = '{base_url}/upload_requests_groups/{upload_req_group_uuid}/upload_requests'.format_map({
            'base_url': self.base_test_url,
            'upload_req_group_uuid' : upload_request_group['uuid']
            })
        req = requests.get(
            query_url,
            headers=self.headers,
            auth=HTTPBasicAuth(self.email, self.password),
            verify=self.verify
        )
        self.assertEqual(req.status_code, 200)
        LOGGER.debug("status_code : %s", req.status_code)
        LOGGER.debug("result : %s", req.text)
        upload_requests = req.json()
        self.assertEqual(len(upload_requests[0]['uploadRequestURLs']), 1)
        # Upload an upload request entry
        query_url = self.base_test_upload_request_url
        file_path = 'file10M'
        filesize = os.path.getsize(file_path)
        with open(file_path, 'rb') as file_stream:
            encoder = MultipartEncoder(
                fields={
                    'flowTotalChunks' : '1',
                    'flowChunkSize': str(filesize),
                    'flowTotalSize': str(filesize),
                    'file': ('file10M.new', file_stream),
                    'flowIdentifier' : 'entry',
                    'flowFilename' : 'file10M',
                    "flowRelativePath" : file_path,
                    'requestUrlUuid' : upload_requests[0]['uploadRequestURLs'][0]['uuid'],
                    'password' : 'test',
                    'body':'Test upload an upload request entry',
                    'flowChunkNumber':'1'
                }
            )
            monitor = MultipartEncoderMonitor(encoder, create_callback(encoder))
            headers = {
                'Accept': 'application/json',
                'Content-Type': monitor.content_type
            }
            req = requests.post(
                query_url,
                data=monitor,
                headers=headers,
                auth=HTTPBasicAuth(self.email, self.password),
                verify=self.verify)
        self.assertEqual(req.status_code, 200)
        # Test close an upload request.
        self.assertEqual(upload_requests[0]['status'], 'ENABLED')
        query_url = '{base_url}/upload_requests/{upload_req_uuid}/status/{status}'.format_map({
            'base_url': self.base_url,
            'upload_req_uuid' : upload_requests[0]['uuid'],
            'status' : 'CLOSED'
            })
        req = requests.put(
            query_url,
            headers=self.headers,
            auth=HTTPBasicAuth(self.email, self.password),
            verify=self.verify
        )
        LOGGER.debug("status_code : %s", req.status_code)
        LOGGER.debug("result : %s", req.text)
        self.assertEqual(req.status_code, 200)
        data = req.json()
        self.assertEqual(data['status'], 'CLOSED')
        # Before copying an entries we need to update status to PURGED
        query_url = '{base_url}/upload_requests/{upload_req_uuid}/status/{status}?copy=true'.format_map({
            'base_url': self.base_url,
            'upload_req_uuid' : upload_requests[0]['uuid'],
            'status' : 'ARCHIVED'
            })
        req = requests.put(
            query_url,
            headers=self.headers,
            auth=HTTPBasicAuth(self.email, self.password),
            verify=self.verify
        )
        LOGGER.debug("status_code : %s", req.status_code)
        LOGGER.debug("result : %s", req.text)
        self.assertEqual(req.status_code, 200)
        data = req.json()
        self.assertEqual(data['status'], 'ARCHIVED')
        return data

    def test_update_upload_request(self):
        """Test update an upload request."""
        upload_request = self.test_find_upload_request()
        # Use the method test_create_upload_request returned data
        self.assertEqual(upload_request['enableNotification'], True)
        query_url = '{base_url}/upload_requests/{upload_req_uuid}'.format_map({
            'base_url': self.base_url,
            'upload_req_uuid' : upload_request['uuid']
            })
        payload = {
            "label": upload_request['label'],
            "canClose":upload_request['canClose'],
            "body":upload_request['body'],
            "enableNotification":False
       }
        req = requests.put(
            query_url,
            json.dumps(payload),
            headers= self.headers,
            auth=HTTPBasicAuth(self.email, self.password),
            verify=self.verify
        )
        LOGGER.debug("status_code : %s", req.status_code)
        LOGGER.debug("result : %s", req.text)
        self.assertEqual(req.status_code, 200)
        data = req.json()
        self.assertEqual(data['enableNotification'], False)
        return data

    def test_find_all_upload_request_entries(self):
        """"Test find all upload request entries"""
        upload_request = self.test_find_upload_request()
        query_url = '{base_url}/upload_requests/{upload_req_uuid}/entries'.format_map({
            'base_url': self.base_url,
            'upload_req_uuid' : upload_request['uuid']
            })
        req = requests.get(
            query_url,
            headers=self.headers,
            auth=HTTPBasicAuth(self.email, self.password),
            verify=self.verify
        )
        self.assertEqual(req.status_code, 200)
        LOGGER.debug("status_code : %s", req.status_code)
        LOGGER.debug("result : %s", req.text)
        data = req.json()
        LOGGER.debug("data : %s", json.dumps(req.json(),
                     sort_keys=True, indent=2))
        return data


class TestAdminApiUserProvider(AdminTestCase):

    def create_test_domain(self, name="TopDomainUserProvider"):
        query_url = '{base_url}/domains'.format_map({
            'base_url': self.base_admin_v5_url,
            })
        payload = {
            "parent": {"uuid": "LinShareRootDomain"},
            "type": "TOPDOMAIN",
            "name": name,
            "description": "Description of top domain 'test user provider'"
        }
        domain = self.request_post(query_url, payload)
        self.assertIsNotNone(domain)
        self.assertIsNotNone(domain['uuid'])
        return domain

    def create_test_user_provider(self, domain, domainDiscriminator):
        query_url = '{base_url}/domains/{uuid}/user_providers'.format_map({
            'base_url': self.base_admin_v5_url,
            'uuid': domain['uuid']
            })
        payload = {
            "type": "OIDC_PROVIDER",
            "domainDiscriminator": domainDiscriminator,
            "checkExternalUserID": True
        }
        provider = self.request_post(query_url, payload)
        LOGGER.debug("provider : %s", json.dumps(provider, sort_keys=True,
                     indent=2))
        return provider

    def test_create_oidc_user_provider(self):
        domain = self.create_test_domain()
        provider = self.create_test_user_provider(domain, "DOM_TO_1")
        self.assertIsNotNone(provider)
        self.assertIsNotNone(provider['uuid'])
        self.assertEqual(provider['type'], "OIDC_PROVIDER")
        self.assertEqual(provider['checkExternalUserID'], True)
        self.assertEqual(provider['useAccessClaim'], False)
        self.assertEqual(provider['useRoleClaim'], False)
        self.assertEqual(provider['useEmailLocaleClaim'], False)
        self.assertEqual(provider['domainDiscriminator'], "DOM_TO_1")

    def test_creating_two_oidc_user_providers_with_same_domain_discriminator_should_fail(self):
        domain = self.create_test_domain()
        self.create_test_user_provider(domain, "DOM_TO_2")

        otherDomain = self.create_test_domain(name="OtherDomain")
        query_url = '{base_url}/domains/{uuid}/user_providers'.format_map({
            'base_url': self.base_admin_v5_url,
            'uuid': otherDomain['uuid']
            })
        payload = {
            "type": "OIDC_PROVIDER",
            "domainDiscriminator": "DOM_TO_2",
            "checkExternalUserID": True
        }
        self.request_post(query_url, payload, expected_status=400, busines_err_code=38100)

    def test_update_oidc_user_provider(self):
        domain = self.create_test_domain()
        provider = self.create_test_user_provider(domain, "DOM_TO_3")
        query_url = '{base_url}/domains/{uuid}/user_providers/{up_uuid}'.format_map({
            'base_url': self.base_admin_v5_url,
            'uuid': domain['uuid'],
            'up_uuid': provider['uuid']
            })
        provider['checkExternalUserID'] = True
        provider['useAccessClaim'] = True
        provider['useRoleClaim'] = True
        provider['useEmailLocaleClaim'] = True
        provider['domainDiscriminator'] = "DOM_TO_3_UPDATE"
        provider = self.request_put(query_url, provider)
        LOGGER.debug("provider : %s", json.dumps(provider, sort_keys=True,
                     indent=2))
        self.assertEqual(provider['checkExternalUserID'], True)
        self.assertEqual(provider['useAccessClaim'], True)
        self.assertEqual(provider['useRoleClaim'], True)
        self.assertEqual(provider['useEmailLocaleClaim'], True)
        self.assertEqual(provider['domainDiscriminator'], "DOM_TO_3_UPDATE")

    def test_update_oidc_user_provider_should_succeed_when_same_domain_discriminator(self):
        domain = self.create_test_domain()
        provider = self.create_test_user_provider(domain, "DOM_TO_31")

        query_url = '{base_url}/domains/{uuid}/user_providers/{up_uuid}'.format_map({
            'base_url': self.base_admin_v5_url,
            'uuid': domain['uuid'],
            'up_uuid': provider['uuid']
            })
        provider['domainDiscriminator'] = "DOM_TO_31"
        provider = self.request_put(query_url, provider)
        LOGGER.debug("provider : %s", json.dumps(provider, sort_keys=True,
                     indent=2))
        self.assertEqual(provider['domainDiscriminator'], "DOM_TO_31")

    def test_update_oidc_user_provider_should_fail_when_domain_discriminator_already_used(self):
        otherDomain = self.create_test_domain(name="OtherDomain")
        self.create_test_user_provider(otherDomain, "OtherDomainDiscriminator")

        domain = self.create_test_domain()
        provider = self.create_test_user_provider(domain, "DOM_TO_32")

        query_url = '{base_url}/domains/{uuid}/user_providers/{up_uuid}'.format_map({
            'base_url': self.base_admin_v5_url,
            'uuid': domain['uuid'],
            'up_uuid': provider['uuid']
            })
        provider['domainDiscriminator'] = "OtherDomainDiscriminator"
        self.request_put(query_url, provider, expected_status=400, busines_err_code=38100)

    def test_delete_oidc_user_provider(self):
        domain = self.create_test_domain()
        provider = self.create_test_user_provider(domain, "DOM_TO_4")
        query_url = '{base_url}/domains/{uuid}/user_providers'.format_map({
            'base_url': self.base_admin_v5_url,
            'uuid': domain['uuid']
            })
        provider = self.request_delete(query_url, provider)
        LOGGER.debug("provider : %s", json.dumps(provider, sort_keys=True,
                     indent=2))
        self.assertEqual(provider['checkExternalUserID'], True)
        self.assertEqual(provider['useAccessClaim'], False)
        self.assertEqual(provider['useRoleClaim'], False)
        self.assertEqual(provider['useEmailLocaleClaim'], False)
        self.assertEqual(provider['domainDiscriminator'], "DOM_TO_4")


    def test_delete_oidc_user_provide2(self):
        domain = self.create_test_domain()
        provider = self.create_test_user_provider(domain, "DOM_TO_5")
        query_url = '{base_url}/domains/{uuid}/user_providers/{up_uuid}'.format_map({
            'base_url': self.base_admin_v5_url,
            'uuid': domain['uuid'],
            'up_uuid': provider['uuid']
            })
        self.request_delete(query_url)

@unittest.skip
class TestAdminApiDriveProvider(AdminTestCase):

    def create_ldap_connection(self):
        """Create ldap connection"""
        query_url = '{base_url}/ldap_connections'.format_map({
            'base_url': self.base_url,
            })
        payload = {
            "label":"local_ldap",
            "providerUrl":self.local_ldap_url,
            "securityPrincipal":self.local_ldap_user_dn,
            "securityCredentials":self.local_ldap_password
        }
        data = self.request_post(query_url, payload)
        return data

    def create_ldap_pattern(self):
        """Create ldap pattern"""
        query_url = '{base_url}/group_patterns/{pattern_uuid}'.format_map({
            'base_url': self.base_url,
            'pattern_uuid' : self.default_drive_pattern
            })
        default_drive_pattern = self.request_get(query_url)
        payload = {
            "uuid":default_drive_pattern["uuid"],
            "label":"drive_pattern_test",
            "description":default_drive_pattern["description"],
            "searchPageSize":default_drive_pattern["searchPageSize"],
            "searchAllGroupsQuery":default_drive_pattern["searchAllGroupsQuery"],
            "searchGroupQuery":default_drive_pattern["searchGroupQuery"],
            "groupPrefix":default_drive_pattern["groupPrefix"],
            "groupName":default_drive_pattern["groupName"],
            "groupMember":default_drive_pattern["groupMember"],
            "memberMail":default_drive_pattern["memberMail"],
            "memberFirstName":default_drive_pattern["memberFirstName"],
            "memberLastName":default_drive_pattern["memberLastName"]
        }
        query_url = '{base_url}/group_patterns'.format_map({
            'base_url': self.base_url,
            })
        data = self.request_post(query_url, payload)
        return data

    def test_create_abstract_domain_create_drive_provider(self):
        """Get linShareRootDomain"""
        ldap_connection = self.create_ldap_connection()
        drive_pattern = self.create_ldap_pattern()
        query_url = '{base_url}/domains/{Domain}'.format_map({
            'base_url': self.base_url,
            'Domain' : 'LinShareRootDomain'
            })
        domain = self.request_get(query_url)
        # Create an abstract domain
        query_url = '{base_url}/domains'.format_map({
            'base_url': self.base_url,
            })
        payload = {
            "parent":domain['identifier'],
            "type":"TOPDOMAIN",
            "providers":[],
            "driveProviders":[{
                "baseDn": self.local_ldap_group_base_dn,
                "connection":{"label":ldap_connection["label"],"uuid":ldap_connection["uuid"]},
                "pattern":{"label":drive_pattern["label"],"uuid":drive_pattern["uuid"]},
                "searchInOtherDomains":False
                }],
            "externalMailLocale":"ENGLISH",
            "language":"ENGLISH",
            "mailConfigUuid":domain['mailConfigUuid'],
            "currentWelcomeMessage":domain['currentWelcomeMessage'],
            "mimePolicyUuid":domain['mimePolicyUuid'],
            "userRole":"SIMPLE",
            "policy":{"identifier":"DefaultDomainPolicy"},
            "label":"TopDomain",
            "description":"test creating top domain"
        }
        data = self.request_post(query_url, payload)
        self.assertTrue(data['driveProviders'])
        return data

    def test_update_abstract_domain_update_drive_provider(self):
        """update_abstract_domain_update"""
        domain = self.test_create_abstract_domain_create_drive_provider()
        self.assertEqual(domain['driveProviders'][0]["searchInOtherDomains"], False)
        query_url = '{base_url}/domains'.format_map({
            'base_url': self.base_url
            })
        payload = {
            "identifier":domain['identifier'],
            "parent":domain["parent"],
            "type":"TOPDOMAIN",
            "providers":[],
            "driveProviders":[{
                "uuid": domain["driveProviders"][0]["uuid"],
                "baseDn": self.local_ldap_group_base_dn,
                "connection":{"label":domain["driveProviders"][0]["connection"]["label"],"uuid":domain["driveProviders"][0]['connection']["uuid"]},
                "pattern":{"label":domain["driveProviders"][0]["pattern"]["label"],"uuid":domain["driveProviders"][0]["pattern"]["uuid"]},
                "searchInOtherDomains":True
                }],
            "externalMailLocale":"ENGLISH",
            "language":"ENGLISH",
            "mailConfigUuid":domain['mailConfigUuid'],
            "currentWelcomeMessage":domain['currentWelcomeMessage'],
            "mimePolicyUuid":domain['mimePolicyUuid'],
            "userRole":"SIMPLE",
            "policy":{"identifier":"DefaultDomainPolicy"},
            "label":"TopDomain",
            "description":"test updating top domain",
            "authShowOrder": domain['authShowOrder']
        }
        data = self.request_put(query_url, payload)
        self.assertEqual(data['driveProviders'][0]["searchInOtherDomains"], True)
        return data

class TestUserApiFunctionalties(UserTestCase):
    """Test API User for functionalities"""
    def test_find_all_functionalites(self):
        """Test find all functionalites for a giving user in API V4"""
        query_url = '{base_url}/functionalities'.format_map({
            'base_url': self.base_url
            })
        data = self.request_get(query_url)
        return data

    def test_find_all_functionalites_v2(self):
        """Test find all functionalites for a giving user in API V2"""
        query_url = '{base_url}/functionalities'.format_map({
            'base_url': self.base_url_v2
            })
        data = self.request_get(query_url)
        return data

    def test_find_functionality_integer_type(self):
        """Test find a functionality Integer type for a giving user API V4"""
        identifier = 'UPLOAD_REQUEST__MAXIMUM_FILE_COUNT'
        query_url = '{base_url}/functionalities/{identifier}'.format_map({
            'base_url': self.base_url,
            'identifier' : identifier
            })
        data = self.request_get(query_url)
        self._assertJsonPayload(['type', 'identifier', 'enable' ,'canOverride', 'value', 'maxValue'], data)

    def test_find_functionality_unit_type(self):
        """Test find a functionality Unit type for a giving user API V4"""
        identifier = 'UPLOAD_REQUEST__DELAY_BEFORE_ACTIVATION'
        query_url = '{base_url}/functionalities/{identifier}'.format_map({
            'base_url': self.base_url,
            'identifier' : identifier
            })
        data = self.request_get(query_url)
        self._assertJsonPayload(['type', 'identifier', 'enable' ,'canOverride', 'value', 'maxUnit','unit', 'units'], data)

    def test_find_functionality_string_type(self):
        """Test find a functionality String type for a giving user API V4"""
        identifier = 'ANONYMOUS_URL__NOTIFICATION_URL'
        query_url = '{base_url}/functionalities/{identifier}'.format_map({
            'base_url': self.base_url,
            'identifier' : identifier
            })
        data = self.request_get(query_url)
        self._assertJsonPayload(['type', 'identifier', 'enable' ,'canOverride', 'value'], data)

    def test_find_functionality_boolean_type(self):
        """Test find a functionality Boolean type for a giving user API V4"""
        identifier = 'ANONYMOUS_URL__NOTIFICATION'
        query_url = '{base_url}/functionalities/{identifier}'.format_map({
            'base_url': self.base_url,
            'identifier' : identifier
            })
        data = self.request_get(query_url)
        self._assertJsonPayload(['type', 'identifier', 'enable' ,'canOverride', 'value'], data)

    def test_find_functionality_lang_type(self):
        """Test find a functionality Lang type for a giving user API V4"""
        identifier = 'UPLOAD_REQUEST__NOTIFICATION_LANGUAGE'
        query_url = '{base_url}/functionalities/{identifier}'.format_map({
            'base_url': self.base_url,
            'identifier' : identifier
            })
        data = self.request_get(query_url)
        self._assertJsonPayload(['type', 'identifier', 'enable' ,'canOverride', 'value', 'units'], data)

    def test_find_functionality_integer_type_api_v2(self):
        """Test find a functionality Integer type for a giving user API V2"""
        identifier = 'UPLOAD_REQUEST__MAXIMUM_FILE_COUNT'
        query_url = '{base_url}/functionalities/{identifier}'.format_map({
            'base_url': self.base_url_v2,
            'identifier' : identifier
            })
        data = self.request_get(query_url)
        self._assertJsonPayload(['type', 'identifier', 'enable' ,'canOverride', 'value'], data)

    def test_find_functionality_unit_type_api_v2(self):
        """Test find a functionality Unit type for a giving user API V2"""
        identifier = 'UPLOAD_REQUEST__DELAY_BEFORE_ACTIVATION'
        query_url = '{base_url}/functionalities/{identifier}'.format_map({
            'base_url': self.base_url_v2,
            'identifier' : identifier
            })
        data = self.request_get(query_url)
        self._assertJsonPayload(['type', 'identifier', 'enable' ,'canOverride', 'value', 'unit', 'units'], data)

    def test_find_functionality_string_type_api_v2(self):
        """Test find a functionality String type for a giving user API V2"""
        identifier = 'ANONYMOUS_URL__NOTIFICATION_URL'
        query_url = '{base_url}/functionalities/{identifier}'.format_map({
            'base_url': self.base_url_v2,
            'identifier' : identifier
            })
        data = self.request_get(query_url)
        self._assertJsonPayload(['type', 'identifier', 'enable' ,'canOverride', 'value'], data)

    def test_find_functionality_boolean_type_api_v2(self):
        """Test find a functionality Boolean type for a giving user API V2"""
        identifier = 'ANONYMOUS_URL__NOTIFICATION'
        query_url = '{base_url}/functionalities/{identifier}'.format_map({
            'base_url': self.base_url_v2,
            'identifier' : identifier
            })
        data = self.request_get(query_url)
        self._assertJsonPayload(['type', 'identifier', 'enable' ,'canOverride', 'value'], data)

    def test_find_functionality_lang_type_api_v2(self):
        """Test find a functionality Lang type for a giving user API V4"""
        identifier = 'UPLOAD_REQUEST__NOTIFICATION_LANGUAGE'
        query_url = '{base_url}/functionalities/{identifier}'.format_map({
            'base_url': self.base_url_v2,
            'identifier' : identifier
            })
        data = self.request_get(query_url)
        self._assertJsonPayload(['type', 'identifier', 'enable' ,'canOverride', 'value', 'units'], data)

class TestUserApiEnums(UserTestCase):

    def test_find_all_enums_get_verb(self):
        """"Test find all enums"""
        query_url = '{base_url}/enums'.format_map({
            'base_url': self.base_url
            })
        data = self.request_get(query_url)
        self.assertTrue(len(data) != 0, "The returned enums' list is empty")

    def test_find_all_enums_head_verb(self):
        """"Test find all enums"""
        query_url = '{base_url}/enums'.format_map({
            'base_url': self.base_url
            })
        self.request_head(query_url)

class TestSharedSpaceAdminV5Api(AdminTestCase):
    def test_find_all_shared_spaces(self):
        """Test admin find all sharedSpaces."""
        nodeTypes = ['WORK_GROUP', 'DRIVE']
        query_url = '{baseUrl}/shared_spaces'.format_map({
            'baseUrl' : self.base_admin_v5_url
        })
        nodes = self.request_get(query_url)
        if len(nodes) != 0:
            for node in nodes:
                self.assertTrue(node['nodeType'] in nodeTypes)

    def test_find_all_drives(self):
        """Test admin find all Drives."""
        encoded_url = urllib.parse.urlencode({'nodeType': "DRIVE"})
        query_url = '{baseUrl}/shared_spaces?{encode}'.format_map({
            'baseUrl' : self.base_admin_v5_url,
            'encode': encoded_url})
        nodes = self.request_get(query_url)
        if len(nodes) != 0:
            for node in nodes:
                self.assertEqual(node['nodeType'], "DRIVE")

    def test_find_all_workgroups(self):
        """Test admin find all workgroups."""
        encoded_url = urllib.parse.urlencode({'nodeType': "WORK_GROUP"})
        query_url = '{baseUrl}/shared_spaces?{encode}'.format_map({
            'baseUrl' : self.base_admin_v5_url,
            'encode': encoded_url})
        nodes = self.request_get(query_url)
        if len(nodes) != 0:
            for node in nodes:
                self.assertEqual(node['nodeType'], "WORK_GROUP")

    def test_filter_shared_space_by_role_and_name(self):
        # Create 3 Drives
        query_url = self.user_base_url + '/shared_spaces'
        payload = {
            "name": "First Drive test",
            "nodeType": "DRIVE"
        }
        drive = self.request_post(query_url, payload)
        payload = {
            "name": "Second  Drive test",
            "nodeType": "DRIVE"
        }
        drive2 = self.request_post(query_url, payload)
        payload = {
            "name": "Third  Drive test",
            "nodeType": "DRIVE"
        }
        drive3 = self.request_post(query_url, payload)
        # Add member to first Drive with DRIVE_WRITER role
        user1 = self.get_user1()
        parameters = {
            'base_url': self.user_base_url,
            'name':'ADMIN'
            }
        url = '{base_url}/shared_space_roles/role/{name}'.format_map(parameters)
        nestedRole = self.request_get(url)
        parameters = {
            'base_url': self.user_base_url,
            'name':'DRIVE_WRITER'
            }
        url = '{base_url}/shared_space_roles/role/{name}'.format_map(parameters)
        role = self.request_get(url)
        query_url = '{baseUrl}/shared_spaces/{driveUuid}/members'.format_map({
            'baseUrl' : self.user_base_url,
            'driveUuid': drive["uuid"]})
        payload = {
            "account" : {
                "uuid" : user1['uuid'],
                "firstName" : user1['firstName'],
                "lastName" : user1['lastName'],
                "mail" : user1['mail'],
                },
            "role" : {
                "uuid" : role['uuid'],
                },
            "nestedRole": {
                "uuid": nestedRole['uuid'],
            },
            "node" : {
                "uuid" : drive['uuid'],
                "name" : drive['name'],
                "nodeType" : drive['nodeType']
                },
            "type" : "DRIVE"
        }
        members = self.request_post(query_url, payload)
        members = self.request_get(query_url)
        self.assertEqual(2, len(members))
        # Test admin find all sharedSpaces by role DRIVE_WRITER
        encoded_url = urllib.parse.urlencode({'role': "DRIVE_WRITER"})
        query_url = '{baseUrl}/shared_spaces?{encode}'.format_map({
            'baseUrl' : self.base_admin_v5_url,
            'encode': encoded_url})
        nodes = self.request_get(query_url)
        self.assertEqual(1, len(nodes))
        for node in nodes:
            self.assertEqual(node['nodeType'], "DRIVE")
        # Test admin find all sharedSpaces by name
        encoded_url = urllib.parse.urlencode({'name': "First"})
        query_url = '{baseUrl}/shared_spaces?{encode}'.format_map({
            'baseUrl' : self.base_admin_v5_url,
            'encode': encoded_url})
        nodes = self.request_get(query_url)
        self.assertEqual(nodes[0]["name"], "First Drive test")
        # Delete drives
        query_url = '{baseUrl}/shared_spaces/{driveUuid}'.format_map({
            'baseUrl' : self.base_admin_v5_url,
            'driveUuid': drive["uuid"]})
        self.request_delete(query_url)
        query_url = '{baseUrl}/shared_spaces/{driveUuid}'.format_map({
            'baseUrl' : self.base_admin_v5_url,
            'driveUuid': drive2["uuid"]})
        self.request_delete(query_url)
        query_url = '{baseUrl}/shared_spaces/{driveUuid}'.format_map({
            'baseUrl' : self.base_admin_v5_url,
            'driveUuid': drive3["uuid"]})
        self.request_delete(query_url)


class TestDomainUserFilterAdminv5Api(AdminTestCase):

    def test_find_all_default_models_domain_user_filters(self):
        #Test admin find all default domain user filters models
        encoded_url = urllib.parse.urlencode({'model': "true"})
        query_url = '{baseUrl}/user_filters?{encode}'.format_map({
            'baseUrl' : self.base_admin_v5_url,
            'encode': encoded_url})
        user_filters = self.request_get(query_url)
        self.assertEqual(len(user_filters),4)

    def test_find_all_created_domain_user_filters(self):
        #Test admin find all domain user filters
        query_url = '{baseUrl}/user_filters'.format_map({
            'baseUrl' : self.base_admin_v5_url})
        self.request_get(query_url)

    def test_create_domain_user_filter(self):
        #Test admin create domain user filter.
        payload ={
            "name": "local_domain_user_filter",
            "description": "This is domain user filter pattern for the OpenLdap structure.",
            "type": "LDAP",
            "authenticationQuery": "ldap.search(domain, \"(&(objectClass=inetOrgPerson)(mail=*)(givenName=*)(sn=*)(|(mail=\"+login+\")(uid=\"+login+\")))\");",
            "searchUserQuery": "ldap.search(domain, \"(&(objectClass=inetOrgPerson)(mail=\"+mail+\")(givenName=\"+first_name+\")(sn=\"+last_name+\"))\");",
            "autoCompleteCommandOnAllAttributes": "ldap.search(domain, \"(&(objectClass=inetOrgPerson)(mail=*)(givenName=*)(sn=*)(|(mail=\" + pattern + \")(sn=\" + pattern + \")(givenName=\" + pattern + \")))\");",
            "autoCompleteCommandOnFirstAndLastName": "ldap.search(domain, \"(&(objectClass=inetOrgPerson)(mail=*)(givenName=*)(sn=*)(|(&(sn=\" + first_name + \")(givenName=\" + last_name + \"))(&(sn=\" + last_name + \")(givenName=\" + first_name + \"))))\");",
            "searchPageSize": 100,
            "searchSizeLimit": 100,
            "completionPageSize": 10,
            "completionSizeLimit": 10,
            "userFirstNameAttribute": "givenname",
            "userLastNameAttribute": "sn",
            "userMailAttribute": "mail",
            "userUidAttribute": "uid"
        }
        query_url = '{baseUrl}/user_filters'.format_map({
            'baseUrl' : self.base_admin_v5_url})
        user_filter = self.request_post(query_url, payload)
        self.assertEqual(user_filter['name'], payload['name'])
        return user_filter

    def test_find_domain_user_filter(self):
        #Test admin find domain user filter.
        user_filter = self.test_create_domain_user_filter()
        query_url = '{baseUrl}/user_filters/{user_filter_uuid}'.format_map({
            'baseUrl' : self.base_admin_v5_url,
            'user_filter_uuid' : user_filter['uuid']})
        self.request_get(query_url)

    def test_update_domain_user_filter(self):
        #Test admin update domain user filter.
        user_filter = self.test_create_domain_user_filter()
        query_url = '{baseUrl}/user_filters/{user_filter_uuid}'.format_map({
            'baseUrl' : self.base_admin_v5_url,
            'user_filter_uuid' : user_filter['uuid']})
        payload ={
            "name": "updated domain user filter name",
            "description": user_filter['description'],
            "type": user_filter['type'],
            "authenticationQuery": user_filter['authenticationQuery'],
            "searchUserQuery": user_filter['searchUserQuery'],
            "autoCompleteCommandOnAllAttributes": user_filter['autoCompleteCommandOnAllAttributes'],
            "autoCompleteCommandOnFirstAndLastName": user_filter['autoCompleteCommandOnFirstAndLastName'],
            "searchPageSize": user_filter['searchPageSize'],
            "searchSizeLimit": user_filter['searchSizeLimit'],
            "completionPageSize": user_filter['completionPageSize'],
            "completionSizeLimit": user_filter['completionSizeLimit'],
            "userFirstNameAttribute": user_filter['userFirstNameAttribute'],
            "userLastNameAttribute": user_filter['userLastNameAttribute'],
            "userMailAttribute": user_filter['userMailAttribute'],
            "userUidAttribute": user_filter['userUidAttribute']
        }
        user_filter = self.request_put(query_url, payload)
        self.assertEqual(user_filter['name'], payload['name'])

    def test_delete_domain_user_filter_with_payload(self):
        #Test admin delete domain user filter.
        user_filter = self.test_create_domain_user_filter()
        query_url = '{baseUrl}/user_filters/{user_filter_uuid}'.format_map({
            'baseUrl' : self.base_admin_v5_url,
            'user_filter_uuid' : user_filter['uuid']})
        payload ={
            "name": user_filter['name'],
            "description": user_filter['description'],
            "type": user_filter['type']
        }
        self.request_delete(query_url, payload)

    def test_delete_domain_user_filter_no_payload(self):
        #Test admin delete domain user filter.
        user_filter = self.test_create_domain_user_filter()
        query_url = '{baseUrl}/user_filters/{user_filter_uuid}'.format_map({
            'baseUrl' : self.base_admin_v5_url,
            'user_filter_uuid' : user_filter['uuid']})
        self.request_delete(query_url)


class TestRemoteServerAdminv5Api(AdminTestCase):

    def test_find_all_remote_servers(self):
        #Test admin find all remote servers.
        query_url = '{baseUrl}/remote_servers'.format_map({
            'baseUrl' : self.base_admin_v5_url})
        servers = self.request_get(query_url)

    def test_create_remote_server(self):
        #Test admin create remote server.
        payload = {
            "name": "new connection",
            "bindDn": self.local_ldap_user_dn,
            "url": self.local_ldap_url,
            "bindPassword":self.local_ldap_password
        }
        query_url = '{baseUrl}/remote_servers'.format_map({
            'baseUrl' : self.base_admin_v5_url})
        server = self.request_post(query_url, payload)
        self.assertEqual(server['name'], payload['name'])
        return server

    def test_create_remote_server_without_binddn_and_pwd(self):
        #Test admin create remote server.
        payload = {
            "name": "new connection",
            "url": self.local_ldap_url,
        }
        query_url = '{baseUrl}/remote_servers'.format_map({
            'baseUrl' : self.base_admin_v5_url})
        server = self.request_post(query_url, payload)
        self.assertEqual(server['name'], payload['name'])
        return server

    def test_find_remote_servers(self):
        #Test admin find remote server.
        remote_server = self.test_create_remote_server()
        query_url = '{baseUrl}/remote_servers/{remote_server_uuid}'.format_map({
            'baseUrl' : self.base_admin_v5_url,
            'remote_server_uuid' : remote_server['uuid']})
        self.request_get(query_url)

    def test_delete_remote_server_with_payload(self):
        #Test admin delete remote server.
        remote_server = self.test_create_remote_server()
        query_url = '{baseUrl}/remote_servers/{remote_server_uuid}'.format_map({
            'baseUrl' : self.base_admin_v5_url,
            'remote_server_uuid' : remote_server['uuid']})
        payload = {
            "name": "new connection",
            "bindDn": remote_server['bindDn'],
            "url": remote_server['url'],
        }
        self.request_delete(query_url, payload)

    def test_delete_remote_server_no_payload(self):
        #Test admin delete remote server no payload.
        remote_server = self.test_create_remote_server()
        query_url = '{baseUrl}/remote_servers/{remote_server_uuid}'.format_map({
            'baseUrl' : self.base_admin_v5_url,
            'remote_server_uuid' : remote_server['uuid']})
        self.request_delete(query_url)

    def test_update_remote_servers(self):
        #Test admin update remote server.
        remote_server = self.test_create_remote_server()
        query_url = '{baseUrl}/remote_servers/{remote_server_uuid}'.format_map({
            'baseUrl' : self.base_admin_v5_url,
            'remote_server_uuid' : remote_server['uuid']})
        payload = {
            "name": "updated connection name",
            "bindDn": remote_server['bindDn'],
            "url": remote_server['url'],
            "bindPassword":'test'
        }
        server = self.request_put(query_url, payload)
        self.assertEqual(server['name'], payload['name'])
        self.assertEqual(server['bindPassword'], payload['bindPassword'])

    def test_update_remote_servers_without_binddn_and_pwd(self):
        #Test admin update remote server.
        remote_server = self.test_create_remote_server()
        query_url = '{baseUrl}/remote_servers/{remote_server_uuid}'.format_map({
            'baseUrl' : self.base_admin_v5_url,
            'remote_server_uuid' : remote_server['uuid']})
        payload = {
            "name": "updated connection name",
            "url": remote_server['url'],
        }
        server = self.request_put(query_url, payload)
        self.assertEqual(server['name'], payload['name'])
        self.assertFalse(hasattr(server, "bindPassword"))


class TestDomainGroupFilterAdminv5Api(AdminTestCase):

    def test_find_all_default_models_domain_group_filters(self):
        """Test admin find all default domain group filters models"""
        encoded_url = urllib.parse.urlencode({'model': "true"})
        query_url = '{baseUrl}/group_filters?{encode}'.format_map({
            'baseUrl' : self.base_admin_v5_url,
            'encode': encoded_url})
        group_filters = self.request_get(query_url)
        self.assertEqual(len(group_filters),1)

    def test_find_all_created_domain_created_group_filters(self):
        """Test admin find all domain group filters"""
        query_url = '{baseUrl}/group_filters'.format_map({
            'baseUrl' : self.base_admin_v5_url})
        self.request_get(query_url)

    def test_create_domain_group_filter(self):
        """Test admin create domain group filter."""
        payload = {
            "description": "Test domain workgroup filter",
            "name": "Group filter name",
            "searchAllGroupsQuery": "ldap.search(baseDn, \"(&(objectClass=groupOfNames)(cn=workgroup-*))\");",
            "searchGroupQuery": "ldap.search(baseDn, \"(&(objectClass=groupOfNames)(cn=workgroup-\" + pattern + \"))\");",
            "searchPageSize": 100,
            "groupMemberAttribute": "member",
            "groupNameAttribute": "cn",
            "groupPrefixToRemove": "workgroup-",
            "memberFirstNameAttribute": "givenname",
            "memberLastNameAttribute": "sn",
            "memberMailAttribute": "mail"
        }
        query_url = '{baseUrl}/group_filters'.format_map({
            'baseUrl' : self.base_admin_v5_url})
        group_filter = self.request_post(query_url, payload)
        self.assertEqual(group_filter['name'], payload['name'])
        return group_filter

    def test_find_domain_group_filter(self):
        """Test admin find domain group filter."""
        group_filter = self.test_create_domain_group_filter()
        query_url = '{baseUrl}/group_filters/{group_filter_uuid}'.format_map({
            'baseUrl' : self.base_admin_v5_url,
            'group_filter_uuid' : group_filter['uuid']})
        self.request_get(query_url)

    def test_update_domain_group_filter(self):
        """Test admin update domain group filter."""
        group_filter = self.test_create_domain_group_filter()
        query_url = '{baseUrl}/group_filters/{group_filter_uuid}'.format_map({
            'baseUrl' : self.base_admin_v5_url,
            'group_filter_uuid' : group_filter['uuid']})
        payload = {
            "description": group_filter["description"],
            "name": "Updated group filter name",
            "searchAllGroupsQuery": group_filter["searchAllGroupsQuery"],
            "searchGroupQuery": group_filter["searchGroupQuery"],
            "searchPageSize": group_filter["searchPageSize"],
            "groupMemberAttribute": group_filter["groupMemberAttribute"],
            "groupNameAttribute": group_filter["groupNameAttribute"],
            "groupPrefixToRemove": group_filter["groupPrefixToRemove"],
            "memberFirstNameAttribute": group_filter["memberFirstNameAttribute"],
            "memberLastNameAttribute": group_filter["memberLastNameAttribute"],
            "memberMailAttribute": group_filter["memberMailAttribute"]
          }
        group_filter = self.request_put(query_url, payload)
        self.assertEqual(group_filter['name'], payload['name'])

    def test_delete_domain_group_filter_with_payload(self):
        """Test admin delete domain group filter."""
        group_filter = self.test_create_domain_group_filter()
        query_url = '{baseUrl}/group_filters/{group_filter_uuid}'.format_map({
            'baseUrl' : self.base_admin_v5_url,
            'group_filter_uuid' : group_filter['uuid']})
        payload ={
            "name": group_filter['name'],
            "description": group_filter['description'],
            "type": group_filter['type']
        }
        self.request_delete(query_url, payload)

    def test_delete_domain_group_filter_no_payload(self):
        """Test admin delete domain group filter."""
        group_filter = self.test_create_domain_group_filter()
        query_url = '{baseUrl}/group_filters/{group_filter_uuid}'.format_map({
            'baseUrl' : self.base_admin_v5_url,
            'group_filter_uuid' : group_filter['uuid']})
        self.request_delete(query_url)


class TestAdminApiDriveProvider(AdminTestCase):

    def test_create_drive_provider(self):
        """Test admin create drive provider."""
        payload = {
            "name": "new connection",
            "bindDn": self.local_ldap_user_dn,
            "url": self.local_ldap_url,
            "bindPassword":self.local_ldap_password
        }
        query_url = '{baseUrl}/remote_servers'.format_map({
            'baseUrl' : self.base_admin_v5_url})
        ldap_server = self.request_post(query_url, payload)
        self.assertEqual(ldap_server['name'], payload['name'])
        payload = {
            "description": "Test domain drive filter",
            "name": "drive filter name",
            "searchAllGroupsQuery": "ldap.search(baseDn, \"(&(objectClass=groupOfNames)(cn=drive-*))\");",
            "searchGroupQuery": "ldap.search(baseDn, \"(&(objectClass=groupOfNames)(cn=drive-\" + pattern + \"))\");",
            "searchPageSize": 100,
            "groupMemberAttribute": "member",
            "groupNameAttribute": "cn",
            "groupPrefixToRemove": "drive-",
            "memberFirstNameAttribute": "givenname",
            "memberLastNameAttribute": "sn",
            "memberMailAttribute": "mail",
            "type": "LDAP"
        }
        query_url = '{baseUrl}/drive_filters'.format_map({
            'baseUrl' : self.base_admin_v5_url})
        drive_filter = self.request_post(query_url, payload)
        self.assertEqual(drive_filter['name'], payload['name'])
        """Create domain"""
        query_url = '{base_url}/domains'.format_map({
            'base_url': self.base_admin_v5_url,
            })
        payload = {
            "parent": {"uuid": "LinShareRootDomain"},
            "type": "TOPDOMAIN",
            "name": "TopDomainDriveProvider",
            "description": "Description of top domain 'test group provider'"
        }
        domain = self.request_post(query_url, payload)
        self.assertIsNotNone(domain)
        self.assertIsNotNone(domain['uuid'])
        query_url = '{base_url}/domains/{uuid}/drive_providers'.format_map({
            'base_url': self.base_admin_v5_url,
            'uuid': domain['uuid']
            })
        payload = {
            "domain": {
                "uuid": domain['uuid'],
                "name": domain['name']
            },
            "ldapServer": {
                "uuid": ldap_server['uuid'],
                "name": ldap_server['name']
            },
            "driveFilter": {
                "uuid": drive_filter['uuid'],
                "name": drive_filter['name']
            },
            "baseDn": self.local_ldap_group_base_dn,
            "type": "LDAP_PROVIDER"
        }
        drive_provider = self.request_post(query_url, payload)
        self.assertIsNotNone(drive_provider)
        self.assertEqual(drive_provider['baseDn'], payload['baseDn'])
        self.assertEqual(drive_provider['type'], payload['type'])
        self.assertEqual(drive_provider['ldapServer']['uuid'], payload['ldapServer']['uuid'])


    def test_find_all_drive_providers(self):
        """Test admin find all created drive providers"""
        query_url = '{base_url}/domains'.format_map({
            'base_url': self.base_admin_v5_url,
            })
        payload = {
            "parent": {"uuid": "LinShareRootDomain"},
            "type": "TOPDOMAIN",
            "name": "TopDomainDriveProvider",
            "description": "Description of top domain 'test group provider'"
        }
        domain = self.request_post(query_url, payload)
        query_url = '{base_url}/domains/{uuid}/drive_providers'.format_map({
            'base_url': self.base_admin_v5_url,
            'uuid': domain['uuid']
            })
        self.request_get(query_url)

    def test_find_drive_provider(self):
        """Test admin find drive provider."""
        payload = {
            "name": "new connection",
            "bindDn": self.local_ldap_user_dn,
            "url": self.local_ldap_url,
            "bindPassword":self.local_ldap_password
        }
        query_url = '{baseUrl}/remote_servers'.format_map({
            'baseUrl' : self.base_admin_v5_url})
        ldap_server = self.request_post(query_url, payload)
        self.assertEqual(ldap_server['name'], payload['name'])
        payload = {
            "description": "Test domain drive filter",
            "name": "drive filter name",
            "searchAllGroupsQuery": "ldap.search(baseDn, \"(&(objectClass=groupOfNames)(cn=drive-*))\");",
            "searchGroupQuery": "ldap.search(baseDn, \"(&(objectClass=groupOfNames)(cn=drive-\" + pattern + \"))\");",
            "searchPageSize": 100,
            "groupMemberAttribute": "member",
            "groupNameAttribute": "cn",
            "groupPrefixToRemove": "drive-",
            "memberFirstNameAttribute": "givenname",
            "memberLastNameAttribute": "sn",
            "memberMailAttribute": "mail",
            "type": "LDAP"
        }
        query_url = '{baseUrl}/drive_filters'.format_map({
            'baseUrl' : self.base_admin_v5_url})
        drive_filter = self.request_post(query_url, payload)
        self.assertEqual(drive_filter['name'], payload['name'])
        """Create domain"""
        query_url = '{base_url}/domains'.format_map({
            'base_url': self.base_admin_v5_url,
            })
        payload = {
            "parent": {"uuid": "LinShareRootDomain"},
            "type": "TOPDOMAIN",
            "name": "TopDomainDriveProvider",
            "description": "Description of top domain 'test group provider'"
        }
        domain = self.request_post(query_url, payload)
        self.assertIsNotNone(domain)
        self.assertIsNotNone(domain['uuid'])
        query_url = '{base_url}/domains/{uuid}/drive_providers'.format_map({
            'base_url': self.base_admin_v5_url,
            'uuid': domain['uuid']
            })
        payload = {
            "domain": {
                "uuid": domain['uuid'],
                "name": domain['name']
            },
            "ldapServer": {
                "uuid": ldap_server['uuid'],
                "name": ldap_server['name']
            },
            "driveFilter": {
                "uuid": drive_filter['uuid'],
                "name": drive_filter['name']
            },
            "baseDn": self.local_ldap_group_base_dn,
            "type": "LDAP_PROVIDER"
        }
        drive_provider = self.request_post(query_url, payload)
        self.assertIsNotNone(drive_provider)
        self.assertEqual(drive_provider['baseDn'], payload['baseDn'])
        query_url = '{base_url}/domains/{uuid}/drive_providers/{drive_provider_uuid}'.format_map({
            'base_url': self.base_admin_v5_url,
            'uuid': drive_provider['domain']['uuid'],
            'drive_provider_uuid': drive_provider['uuid']
            })
        recovered_drive_provider = self.request_get(query_url)
        self.assertEqual(drive_provider['uuid'], recovered_drive_provider['uuid'])

    def test_update_drive_provider(self):
        """Test admin update drive provider."""
        payload = {
            "name": "new connection",
            "bindDn": self.local_ldap_user_dn,
            "url": self.local_ldap_url,
            "bindPassword":self.local_ldap_password
        }
        query_url = '{baseUrl}/remote_servers'.format_map({
            'baseUrl' : self.base_admin_v5_url})
        ldap_server = self.request_post(query_url, payload)
        self.assertEqual(ldap_server['name'], payload['name'])
        payload = {
            "description": "Test domain drive filter",
            "name": "drive filter name",
            "searchAllGroupsQuery": "ldap.search(baseDn, \"(&(objectClass=groupOfNames)(cn=drive-*))\");",
            "searchGroupQuery": "ldap.search(baseDn, \"(&(objectClass=groupOfNames)(cn=drive-\" + pattern + \"))\");",
            "searchPageSize": 100,
            "groupMemberAttribute": "member",
            "groupNameAttribute": "cn",
            "groupPrefixToRemove": "drive-",
            "memberFirstNameAttribute": "givenname",
            "memberLastNameAttribute": "sn",
            "memberMailAttribute": "mail",
            "type": "LDAP"
        }
        query_url = '{baseUrl}/drive_filters'.format_map({
            'baseUrl' : self.base_admin_v5_url})
        drive_filter = self.request_post(query_url, payload)
        self.assertEqual(drive_filter['name'], payload['name'])
        """Create domain"""
        query_url = '{base_url}/domains'.format_map({
            'base_url': self.base_admin_v5_url,
            })
        payload = {
            "parent": {"uuid": "LinShareRootDomain"},
            "type": "TOPDOMAIN",
            "name": "TopDomainDriveProvider",
            "description": "Description of top domain 'test group provider'"
        }
        domain = self.request_post(query_url, payload)
        self.assertIsNotNone(domain)
        self.assertIsNotNone(domain['uuid'])
        query_url = '{base_url}/domains/{uuid}/drive_providers'.format_map({
            'base_url': self.base_admin_v5_url,
            'uuid': domain['uuid']
            })
        payload = {
            "domain": {
                "uuid": domain['uuid'],
                "name": domain['name']
            },
            "ldapServer": {
                "uuid": ldap_server['uuid'],
                "name": ldap_server['name']
            },
            "driveFilter": {
                "uuid": drive_filter['uuid'],
                "name": drive_filter['name']
            },
            "baseDn": self.local_ldap_group_base_dn,
            "type": "LDAP_PROVIDER"
        }
        drive_provider = self.request_post(query_url, payload)
        self.assertIsNotNone(drive_provider)
        self.assertEqual(drive_provider['baseDn'], payload['baseDn'])
        """Create new ldap server"""
        payload = {
            "name": "new connection",
            "bindDn": self.local_ldap_user_dn,
            "url": self.local_ldap_url,
            "bindPassword":self.local_ldap_password
        }
        query_url = '{baseUrl}/remote_servers'.format_map({
            'baseUrl' : self.base_admin_v5_url})
        new_ldap_server = self.request_post(query_url, payload)
        self.assertEqual(ldap_server['name'], payload['name'])
        query_url = '{base_url}/domains/{uuid}/drive_providers'.format_map({
            'base_url': self.base_admin_v5_url,
            'uuid': drive_provider['domain']['uuid']
            })
        payload = {
            "uuid" : drive_provider['uuid'],
            "ldapServer": {
                "uuid": new_ldap_server['uuid'],
                "name": new_ldap_server['name']
            },
            "driveFilter": {
                "uuid": drive_provider['driveFilter']['uuid'],
                "name": drive_provider['driveFilter']['name']
            },
            "baseDn": drive_provider['baseDn'],
            "type": drive_provider['type']
        }
        updated_drive_provider = self.request_put(query_url, payload)
        self.assertEqual(new_ldap_server['uuid'], updated_drive_provider['ldapServer']['uuid'], "The ldap server was not updated")

    def test_delete_domain_drive_provider_no_payload(self):
        """Test admin delete drive provider."""
        payload = {
            "name": "new connection",
            "bindDn": self.local_ldap_user_dn,
            "url": self.local_ldap_url,
            "bindPassword":self.local_ldap_password
        }
        query_url = '{baseUrl}/remote_servers'.format_map({
            'baseUrl' : self.base_admin_v5_url})
        ldap_server = self.request_post(query_url, payload)
        self.assertEqual(ldap_server['name'], payload['name'])
        payload = {
            "description": "Test domain drive filter",
            "name": "drive filter name",
            "searchAllGroupsQuery": "ldap.search(baseDn, \"(&(objectClass=groupOfNames)(cn=drive-*))\");",
            "searchGroupQuery": "ldap.search(baseDn, \"(&(objectClass=groupOfNames)(cn=drive-\" + pattern + \"))\");",
            "searchPageSize": 100,
            "groupMemberAttribute": "member",
            "groupNameAttribute": "cn",
            "groupPrefixToRemove": "drive-",
            "memberFirstNameAttribute": "givenname",
            "memberLastNameAttribute": "sn",
            "memberMailAttribute": "mail",
            "type": "LDAP"
        }
        query_url = '{baseUrl}/drive_filters'.format_map({
            'baseUrl' : self.base_admin_v5_url})
        drive_filter = self.request_post(query_url, payload)
        self.assertEqual(drive_filter['name'], payload['name'])
        """Create domain"""
        query_url = '{base_url}/domains'.format_map({
            'base_url': self.base_admin_v5_url,
            })
        payload = {
            "parent": {"uuid": "LinShareRootDomain"},
            "type": "TOPDOMAIN",
            "name": "TopDomainDriveProvider",
            "description": "Description of top domain 'test group provider'"
        }
        domain = self.request_post(query_url, payload)
        self.assertIsNotNone(domain)
        self.assertIsNotNone(domain['uuid'])
        query_url = '{base_url}/domains/{uuid}/drive_providers'.format_map({
            'base_url': self.base_admin_v5_url,
            'uuid': domain['uuid']
            })
        payload = {
            "domain": {
                "uuid": domain['uuid'],
                "name": domain['name']
            },
            "ldapServer": {
                "uuid": ldap_server['uuid'],
                "name": ldap_server['name']
            },
            "driveFilter": {
                "uuid": drive_filter['uuid'],
                "name": drive_filter['name']
            },
            "baseDn": self.local_ldap_group_base_dn,
            "type": "LDAP_PROVIDER"
        }
        drive_provider = self.request_post(query_url, payload)
        self.assertIsNotNone(drive_provider)
        self.assertEqual(drive_provider['baseDn'], payload['baseDn'])
        """Delete drive provider"""
        query_url = '{base_url}/domains/{uuid}/drive_providers/{drive_provider_uuid}'.format_map({
            'base_url': self.base_admin_v5_url,
            'uuid': drive_provider['domain']['uuid'],
            'drive_provider_uuid': drive_provider['uuid']
            })
        deleted_drive_provider = self.request_delete(query_url)
        self.assertEqual(deleted_drive_provider['uuid'], drive_provider['uuid'], "The drive provider is not deleted")


if __name__ == '__main__':
    unittest.main()
