#!/usr/bin/env python3
# -*- coding: utf-8 -*-


import configparser
import json
import logging
import os
import requests
import sys
import unittest
import urllib

from requests.auth import HTTPBasicAuth
from requests_toolbelt.utils import dump
from requests_toolbelt import (MultipartEncoder, MultipartEncoderMonitor)
from clint.textui.progress import Bar as ProgressBar

# Import the global configuration
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

# Import the configuration related to LinShare user API 
CONFIG_USER = configparser.ConfigParser()
CONFIG_USER.read('linshare.user.ini')

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
    email = CONFIG['DEFAULT']['email']
    password = CONFIG['DEFAULT']['password']
    verify = not NO_VERIFY
    headers = {
        'Accept': 'application/json',
        'Content-Type': 'application/json'
    }

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

    def request_put(self, query_url, payload):
        """Do PUT request"""
        req = requests.put(
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
    base_url = host + '/linshare/webservice/rest/user/v2'
    base_test_url = host + '/linshare/webservice/rest/test/user/v2'
    base_test_upload_request_url = host + '/linshare/webservice/rest/uploadrequest/v2/flow/upload'
    base_external_url = host + '/linshare/webservice/rest/uploadrequest/v2'
    email = CONFIG_USER['DEFAULT']['email']
    password = CONFIG_USER['DEFAULT']['password']
    email_external1 = CONFIG_USER['DEFAULT']['email_external1']
    password_external1 = CONFIG_USER['DEFAULT']['password_external1']
    email_external2 = CONFIG_USER['DEFAULT']['email_external2']
    email_external3 = CONFIG_USER['DEFAULT']['email_external3']
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
                    'enableForAll': 'False',
                    'enable':'True',
                    'mail_config':'946b190d-4c95-485f-bfe6-d288a2de1edd',
                    'cid':'logo.mail.attachment.test',
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
        LOGGER.debug("data : %s", json.dumps(data, sort_keys=True, indent=2))
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
        self.assertEqual(data['enableForAll'], False)
        self.assertEqual(data['enable'], True)

    def test_mail_attachment_delete(self):
        """Trying to create and delete a mail attachment as an admin"""
        query_url = self.base_url + '/mail_attachments'
        data = self.test_mail_attachments_create()
        uuid = data['uuid']
        payload = {
            'description': 'Test mail attachment',
            'enableForAll': 'False',
            'enable':'True',
            'cid':'logo.mail.attachment.test'
        }
        req = requests.delete(
            query_url + '/' + uuid,
            data=json.dumps(payload),
            headers = self.headers,
            auth=HTTPBasicAuth(self.email, self.password),
            verify=self.verify)
        self.assertEqual(req.status_code, 200)
        data = req.json()
        self.assertEqual(data['description'], 'Test mail attachment')
        self.assertEqual(data['enableForAll'], False)
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
        self.assertEqual(data['enableForAll'], False)
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
        """Test user authentication."""
        query_url = self.base_url + '/mail_attachments?configUuid=946b190d-4c95-485f-bfe6-d288a2de1edd'
        req = requests.get(
            query_url,
            headers=self.headers,
            auth=HTTPBasicAuth(self.email, self.password),
            verify=self.verify)
        LOGGER.debug("status_code : %s", req.status_code)
        LOGGER.debug("result : %s", req.text)
        self.assertEqual(req.status_code, 200)
        LOGGER.debug("data : %s", req.json())

    def test_findAll_wrong_mail_config(self):
        """Test user authentication."""
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


class TestUserApiDocumentRevision(AdminTestCase):
    """Test User api"""

    host = CONFIG['DEFAULT']['host']
    base_url = host + '/linshare/webservice/rest/user/v2'

    def test_create_ss_node(self):
        """Test user create a shared space node."""
        query_url = self.base_url + '/shared_spaces'
        payload = {
            "name": "workgroup_test",
            "nodeType": "WORK_GROUP"
        }
        data = self.request_post(query_url, payload)
        self.assertEqual(data['name'], 'workgroup_test')
        return data

    def create_workgroup_document(self, workgroup_uuid):
        """create a workgroup document."""
        query_url = self.base_url + '/work_groups/' + workgroup_uuid + '/nodes'
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
        data = req.json()
        LOGGER.debug("data : %s", data)
        return data

    def update_workgroup_document(self, workgroup_uuid, workgroup_node_uuid):
        """create a workgroup document."""
        query_url = self.base_url + '/work_groups/' + workgroup_uuid + '/nodes'
        payload = {
            'uuid': workgroup_node_uuid,
            'name': 'test1',
            'type': 'DOCUMENT'
        }
        req = requests.put(
            query_url + '/' + workgroup_node_uuid,
            data=json.dumps(payload),
            headers = self.headers,
            auth=HTTPBasicAuth(self.email, self.password),
            verify=self.verify)
        LOGGER.debug("status_code : %s", req.status_code)
        LOGGER.debug("result : %s", req.text)
        self.assertEqual(200, req.status_code)
        data = req.json()
        LOGGER.debug("data : %s", data)
        return data

    def test_create_workgroup_document_revision(self):
        """Test user create a workgroup document revision."""
        workgroup_uuid = self.test_create_ss_node()['uuid']
        """Upload the same file twice"""
        first_upload = self.create_workgroup_document(workgroup_uuid)
        self.create_workgroup_document(workgroup_uuid)
        query_url = self.base_url + '/work_groups/' + workgroup_uuid + '/nodes?parent=' + first_upload['uuid']
        req = requests.get(
            query_url,
            headers={'Accept': 'application/json'},
            auth=HTTPBasicAuth(self.email, self.password),
            verify=self.verify)
        data = req.json()
        self.assertEqual(200, req.status_code)
        LOGGER.debug("data : %s", json.dumps(data, sort_keys=True, indent=2))

    def test_find_all_audit_document(self):
        """Test user create a workgroup document revision."""
        workgroup_uuid = self.test_create_ss_node()['uuid']
        """Upload the same file twice"""
        document = self.create_workgroup_document(workgroup_uuid)
        self.create_workgroup_document(workgroup_uuid)
        # update the name of document
        document = self.update_workgroup_document(workgroup_uuid, document['uuid'])
        query_url = self.base_url + '/work_groups/' + workgroup_uuid + '/nodes/' + document['uuid'] + '/audit'
        req = requests.get(
            query_url,
            headers={'Accept': 'application/json'},
            auth=HTTPBasicAuth(self.email, self.password),
            verify=self.verify)
        self.assertEqual(req.status_code, 200)
        self.assertEqual(3, len(req.json()))
        LOGGER.debug("data : %s", json.dumps(req.json(), sort_keys=True, indent=2))

    def test_find_all_shared_spaces(self):
        """Test user find all shared spaces."""
        query_url = self.base_url + '/shared_spaces'
        req = requests.get(
            query_url,
            headers={'Accept': 'application/json'},
            auth=HTTPBasicAuth(self.email, self.password),
            verify=self.verify)
        LOGGER.debug("status_code : %s", req.status_code)
        LOGGER.debug("result : %s", req.text)
        self.assertEqual(req.status_code, 200)
        LOGGER.debug("data : %s", req.json())


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
        token = self.create_jwt_permanent_token();
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
        token = self.create_jwt_permanent_token();
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


class TestUpdateCanCreateGuest(AdminTestCase):
    def test_update_can_create_guest(self):
        """Test update canCreateGuest for user"""
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
        folder = self.create_shared_space_node();
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

    def test_update_shared_space_node_with_nodeuuid_path(self):
        """Test create and update a shared space node."""
        folder = self.create_shared_space_node();
        query_url = self.base_url + '/shared_spaces/' + folder['workGroup'] + '/nodes/' + folder['uuid']
        payload = {
            "name": "Update_Node_Name",
            "type": "FOLDER",
        }
        data = self.request_put(query_url, payload)
        self.assertEqual(data['name'], "Update_Node_Name")
        return data

    def test_update_shared_space_node_without_nodeuuid_path(self):
        """Test create and update a shared space node."""
        folder = self.create_shared_space_node();
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
        folder = self.create_shared_space_node();
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
        folder = self.create_shared_space_node();
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
        folder = self.create_shared_space_node();
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
        folder = self.create_shared_space_node();
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
        folder = self.create_shared_space_node();
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
    """Test User api sharedSpace.
    This API is responsible of Drive and Workgroups management
    """
        
    def test_create_shared_space_Wg(self):
        """Test user API create a shared space WORKGROUP."""
        query_url = self.base_url + '/shared_spaces'
        payload = {
            "name": "workgroup_test",
            "nodeType": "WORK_GROUP"
        }
        data = requests.post(
            query_url,
            json.dumps(payload),
            headers=self.headers,
            auth=HTTPBasicAuth(self.email, self.password),
            verify=self.verify).json()
        self.assertEqual(data['name'], 'workgroup_test')
        LOGGER.debug("result : %s", data)
        return data
    
    def test_find_shared_space_Wg(self):
        """"Test user find a shared space WORKGROUP"""
        workgroup = self.test_create_shared_space_Wg();
        query_url = self.base_url + '/shared_spaces/' + workgroup['uuid']
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
        self.assertIsNotNone(data['quotaUuid'])
        LOGGER.debug("data : %s", json.dumps(req.json(), sort_keys=True, indent=2))

    def test_find_shared_space_quota(self):
        """"Test user find shared space WORKGROUP quota"""
        workgroup = self.test_create_shared_space_Wg();
        query_url = self.base_url + '/quota/' + workgroup['quotaUuid']
        req = requests.get(
            query_url,
            headers={'Accept': 'application/json'},
            auth=HTTPBasicAuth(self.email, self.password),
            verify=self.verify
        )
        LOGGER.debug("status_code : %s", req.status_code)
        LOGGER.debug("result : %s", req.text)
        self.assertEqual(req.status_code, 200)

    def test_create_shared_space_drive_forbidden(self):
        """Test user API create a shared space DRIVE fails.
        This Test should fails on core Drive feature branch
        because it is available only for LS versions not implementing Drive feature
        DRAFT: should be changed after DRIVE feature branch merge
        """
        query_url = self.base_url + '/shared_spaces'
        payload = {
            "name": "workgroup_test",
            "nodeType": "DRIVE"
        }
        req = requests.post(
            query_url,
            data=json.dumps(payload),
            headers=self.headers,
            auth=HTTPBasicAuth(self.email, self.password),
            verify=self.verify)
        LOGGER.debug("status_code : %s", req.status_code)
        LOGGER.debug("result : %s", req.text)
        self.assertEqual(req.status_code, 400)
        data = req.json()
        LOGGER.debug("data : %s", json.dumps(data, sort_keys=True, indent=2))
        return data

    def test_update_shared_space_with_uuid_path(self):
        """Test create and update a shared space."""
        shared_space = self.test_create_shared_space_Wg();
        query_url = self.base_url + '/shared_spaces/' + shared_space['uuid']
        payload = {
            "name": "Update_shared_space_Name",
            "nodeType": "WORK_GROUP",
            "versioningParameters": {
                "enable": "true",
            }
        }
        request = requests.put(
            query_url,
            json.dumps(payload),
            headers=self.headers,
            auth=HTTPBasicAuth(self.email, self.password),
            verify=self.verify
        )
        LOGGER.debug("status_code : %s", request.status_code)
        LOGGER.debug("result : %s", request.text)
        self.assertEqual(request.status_code, 200, "FAILED")
        self.assertEqual(request.json()['name'], payload['name'], "The name is the different")

    def test_update_shared_space_without_uuid_path(self):
        """Test create and update a shared space."""
        shared_space = self.test_create_shared_space_Wg();
        query_url = self.base_url + '/shared_spaces'
        payload = {
            "name": "Update_shared_space_Name",
            "nodeType": "WORK_GROUP",
            "uuid":shared_space['uuid'],
            "versioningParameters": {
                "enable": "true",
            }
        }
        request = requests.put(
            query_url,
            json.dumps(payload),
            headers=self.headers,
            auth=HTTPBasicAuth(self.email, self.password),
            verify=self.verify
        )
        data = request.json()
        self.assertEqual(data['name'], payload['name'])
        return data
        
    def test_shared_space_delete(self):
        """Trying to create and delete a shared_space WORKGROUP"""
        shared_space = self.test_create_shared_space_Wg();
        query_url = self.base_url + '/shared_spaces'
        payload = {
            "name": "workgroup_test",
            "nodeType": "WORK_GROUP",
            "uuid":shared_space['uuid'],
            "versioningParameters": {
                "enable": "true",
            }
        }
        req = requests.delete(
            query_url,
            data=json.dumps(payload),
            headers = self.headers,
            auth=HTTPBasicAuth(self.email, self.password),
            verify=self.verify)
        self.assertEqual(req.status_code, 200)
        data = req.json()
        self.assertEqual(data['name'], payload['name'])
        return data

    def test_shared_space_delete_no_payload(self):
        """Trying to create and delete a shared_space WORKGROUP with no payload"""
        shared_space = self.test_create_shared_space_Wg();
        query_url = self.base_url +'/shared_spaces/'+ shared_space['uuid']
        req = requests.delete(
            query_url,
            headers = self.headers,
            auth=HTTPBasicAuth(self.email, self.password),
            verify=self.verify)
        self.assertEqual(req.status_code, 200)
        data = req.json()
        self.assertEqual(data['name'], 'workgroup_test')
        return data

    def test_find_all_shared_spaces(self):
        """Test user find all shared spaces."""
        query_url = self.base_url + '/shared_spaces'
        req = requests.get(
            query_url,
            headers={'Accept': 'application/json'},
            auth=HTTPBasicAuth(self.email, self.password),
            verify=self.verify)
        self.assertEqual(req.status_code, 200)
        nodes = req.json()
        LOGGER.debug("status_code : %s", req.status_code)
        LOGGER.debug("result : %s", req.text)
        if len(nodes) != 0:
            for node in nodes:
                self.assertEqual(node['parent'], None, "One of returned Shared space is not on top level")
        LOGGER.debug("data : %s", req.json())
        
    def test_find_all_shared_spaces_with_role(self):
        """Test user api find all with the role of the member of this node shared spaces """
        encode = urllib.parse.urlencode({'withRole' : True})
        query_url = '{baseUrl}/shared_spaces/?{encode}'.format_map({
            'baseUrl' : self.base_url,
            'encode' : encode})
        req = requests.get(
            query_url,
            headers={'Accept': 'application/json'},
            auth=HTTPBasicAuth(self.email, self.password),
            verify=self.verify)
        self.assertEqual(req.status_code, 200)
        self.assertIn('role', req.json()[0])
        LOGGER.debug("status_code : %s", req.status_code)
        LOGGER.debug("data : %s", req.json())

    def test_find_all_shared_spaces_audit(self):
        """Test user find all shared space audit."""
        shared_space = self.test_create_shared_space_Wg();
        query_url = self.base_url + '/shared_spaces/' + shared_space['uuid'] + "/audit"
        req = requests.get(
            query_url,
            headers={'Accept': 'application/json'},
            auth=HTTPBasicAuth(self.email, self.password),
            verify=self.verify)
        LOGGER.debug("status_code : %s", req.status_code)
        LOGGER.debug("result : %s", req.text)
        self.assertEqual(req.status_code, 200)
        LOGGER.debug("data : %s", req.json())

    def test_create_shared_space_drive(self):
        """Test user API create a drive."""
        query_url = self.base_url + '/shared_spaces'
        payload = {
            "name": "Drive_test",
            "nodeType": "DRIVE"
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
        LOGGER.debug("data : %s", json.dumps(data, sort_keys=True, indent=2))
        return data
    
    def test_create_nested_wg_in_drive(self):
        """Test user API create a workgroup  into a drive."""
        drive = self.test_create_shared_space_drive()
        query_url = '{baseUrl}/shared_spaces'.format_map({
            'baseUrl' : self.base_url
            })
        payload = {
            "name": "Nested_workgroup",
            "nodeType": "WORK_GROUP",
            "parentUuid":drive["uuid"]
        }
        req = requests.post(
            query_url,
            data=json.dumps(payload),
            headers=self.headers,
            auth=HTTPBasicAuth(self.email, self.password),
            verify=self.verify)
        LOGGER.debug("status_code : %s", req.status_code)
        LOGGER.debug("result : %s", req.text)
        nested_wg = req.json()
        self.assertEqual(req.status_code, 200)
        self.assertEqual(nested_wg['parentUuid'], drive['uuid'])
        LOGGER.debug("data : %s", json.dumps(nested_wg, sort_keys=True, indent=2))
        return nested_wg

    def test_create_shared_space_member_workgroup_explicit_type(self):
        """ Test user API add a member to a WORKGROUP """
        user1 = self.get_user1()
        workgroup = self.test_create_shared_space_Wg()
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
        request = requests.post(
            query_url,
            json.dumps(payload),
            headers=self.headers,
            auth=HTTPBasicAuth(self.email, self.password),
            verify=self.verify)
        self.assertEqual(request.status_code, 200, "FAILED")
        
    def test_create_shared_space_member_workgroup_implicit_type(self):
        """ Test user API add a member to a WORKGROUP """
        user1 = self.get_user1()
        workgroup = self.test_create_shared_space_Wg()
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
        request = requests.post(
            query_url,
            json.dumps(payload),
            headers=self.headers,
            auth=HTTPBasicAuth(self.email, self.password),
            verify=self.verify)
        self.assertEqual(request.status_code, 200, "FAILED")          
            
    def test_create_shared_space_member_drive(self):
        """Test user API add a shared space member into a DRIVE """
        nestedRole = self.getRole('ADMIN')
        role = self.getRole('DRIVE_ADMIN')
        drive = self.test_create_shared_space_drive()
        user1 = self.get_user1()
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
                "uuid": nestedRole['uuid'],
            },
            "node" : {
                "uuid" : drive['uuid'],
                "name" : drive['name'],
                "nodeType" : drive['nodeType']
                },
            "type" : "DRIVE"
        }
        data = requests.post(
            query_url,
            json.dumps(payload),
            headers=self.headers,
            auth=HTTPBasicAuth(self.email, self.password),
            verify=self.verify).json()
        self.assertEqual (data['account']['firstName'], user1['firstName'])
        self.shared_space_delete(drive['uuid'])
        return data
    
    def test_add_shared_space_member_in_drive_and_its_nested_wg(self):
        """Test user API add a shared space member into a DRIVE and its nested workgroups"""
        nestedRole = self.getRole('ADMIN')
        role = self.getRole('DRIVE_ADMIN')
        
        """Create the Shared space DRIVE (parent)"""
        drive = self.test_create_shared_space_drive()
        
        """Get an LS internal user to add in Shared space"""
        user1 = self.get_user1()
        
        wg_create_query_url = '{baseUrl}/shared_spaces'.format_map({
            'baseUrl' : self.base_url
            })
        
        """Payload to create the first nested workgroup"""
        
        wg_payload_1 = {
            "name": "Nested_workgroup_1",
            "nodeType": "WORK_GROUP",
            "parentUuid":drive["uuid"]
        }
        
        """Payload to create the second nested workgroup"""
        wg_payload_2 = {
            "name": "Nested_workgroup_2",
            "nodeType": "WORK_GROUP",
            "parentUuid":drive["uuid"]
        }
        
        """Payload to create the third nested workgroup"""
        wg_payload_3 = {
            "name": "Nested_workgroup_3",
            "nodeType": "WORK_GROUP",
            "parentUuid":drive["uuid"]
        }
        
        """Add nested WG 1"""
        nested_wg_1 = requests.post(
            wg_create_query_url,
            data=json.dumps(wg_payload_1),
            headers=self.headers,
            auth=HTTPBasicAuth(self.email, self.password),
            verify=self.verify).json()
            
        """Add nested WG 2"""    
        nested_wg_2 = requests.post(
            wg_create_query_url,
            data=json.dumps(wg_payload_2),
            headers=self.headers,
            auth=HTTPBasicAuth(self.email, self.password),
            verify=self.verify).json()
            
        """Add nested WG 3"""    
        nested_wg_3 = requests.post(
            wg_create_query_url,
            data=json.dumps(wg_payload_3),
            headers=self.headers,
            auth=HTTPBasicAuth(self.email, self.password),
            verify=self.verify).json()
            
        """Add a member to the Drive (parent)"""
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
        
        """Get all the members of the node"""
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
        """Assertions"""
        self.assertEqual(request.status_code, 200)
        self.assertEqual (member_drive['account']['firstName'], user1['firstName'])
        self.assertEqual(member_1[0]['nested'], True, "FAILED, created member is not nested")
        self.assertEqual(member_2[0]['nested'], True, "FAILED, created member is not nested")
        self.assertEqual(member_3[0]['nested'], True, "FAILED, created member is not nested")
        return member_drive
    
    def test_add_shared_space_member_in_nested_wg(self):
        """Test user API add a shared space member into a nested WORKGROUP"""
        """The role that's given to the member in the nested node"""
        role = self.getRole('ADMIN')
        workgroup = self.test_create_nested_wg_in_drive()
        user1 = self.get_user1()
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
        add_request = requests.post(
            query_url,
            json.dumps(payload),
            headers=self.headers,
            auth=HTTPBasicAuth(self.email, self.password),
            verify=self.verify)
        member = add_request.json()
        self.assertEqual(add_request.status_code, 200 , 'FAILED shared space member not created')
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
        
        user1 = self.get_user1()
        drive = self.test_create_shared_space_drive()
        nestedRole = self.getRole('ADMIN')
        nestedRoleContributor = self.getRole('CONTRIBUTOR')
        role = self.getRole('DRIVE_ADMIN')
        
        """Create a workGroup into the drive."""
        
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
        data_workgroup = req.json()
        
        """Add  a member into the drive."""
        
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
        data_member = requests.post(
            query_url,
            json.dumps(payload),
            headers=self.headers,
            auth=HTTPBasicAuth(self.email, self.password),
            verify=self.verify).json()
        self.assertEqual (data_member['account']['firstName'], user1['firstName'])
        
        """Soft update of a member into the drive."""

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
        """Check the new created member into the nested workgroup."""
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
        user1 = self.get_user1()
        drive = self.test_create_shared_space_drive()
        nestedRole = self.getRole('ADMIN')
        nestedRoleContributor = self.getRole('CONTRIBUTOR')
        role = self.getRole('DRIVE_ADMIN')
        """Create a workGroup into the drive."""
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
        data_workgroup = req.json()
        """Create a a member into the drive."""
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
        """Soft update of a member into the drive."""
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
        """Check the new created member into the nested workgroup."""
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
        user1 = self.get_user1()
        drive = self.test_create_shared_space_drive()
        nestedRole = self.getRole('ADMIN')
        role = self.getRole('DRIVE_ADMIN')
        
        """Create new member into a drive."""
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

        """Create a workGroup into the drive."""
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

        """Check the new created member is into the nested workgroup."""
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
        drive = self.test_create_shared_space_drive()
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
        drive = self.test_create_shared_space_drive()
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
        user1 = self.get_user1()
        shared_space = self.test_create_shared_space_Wg();
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
        return data
     
    def test_delete_shared_space_member(self):
        """Test user API delete a shared space member from a WORKGROUP."""
        shared_space_member = self.test_create_shared_space_member();
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
        shared_space_member = self.test_create_shared_space_member();
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
        shared_space_member = self.test_create_shared_space_member();
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
        shared_space = self.test_create_shared_space_Wg();
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
        shared_space_member = self.test_create_shared_space_member();
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


class TestUserApiSharedSpaceMembers(UserTestCase):
    """Test User api sharedSpace Members TO DO : Use SharedSpaceMemberAPI to wirite tests"""


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
        req = requests.post(
            query_url,
            data=json.dumps(payload),
            headers=self.headers,
            auth=HTTPBasicAuth(self.user1_email, self.password),
            verify=self.verify)
        data = req.json()
        LOGGER.debug("status_code : %s", req.status_code)
        LOGGER.debug("result : %s", req.text)
        self.assertEqual(req.status_code, 200)
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
        data = req.json()
        LOGGER.debug("status_code : %s", req.status_code)
        LOGGER.debug("result : %s", req.text)
        self.assertEqual(req.status_code, 200)
        LOGGER.debug("data : %s", json.dumps(req.json(), sort_keys=True, indent=2))


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

class TestUserApiUploadRequestGroup(UserTestCase):
    """"Test user API upload request group """
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
            "enableNotification":False,
            "dirty":False
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
            "enableNotification":False,
            "dirty":False
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

    def test_create_upload_request_group_grouped_mode_true(self):
        """"Test create upload request group with grouped mode true"""
        query_url = '{base_url}/upload_request_groups?groupMode={groupMode}'.format_map({
            'base_url': self.base_url,
            'groupMode' : 'true'
            })
        payload = {
            "label": "upload request group",
            "canDelete":True,
            "canClose":True,
            "contactList":[self.email_external1, self.email_external2, self.email_external3],
            "body":"test body",
            "enableNotification":False,
            "dirty":False
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

    def test_create_upload_request_group_grouped_mode_false(self):
        """"Test create upload request group with grouped mode false"""
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
            "enableNotification":False,
            "dirty":False
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
        upload_request_group = self.test_create_upload_request_group();
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
        upload_request_group = self.test_create_upload_request_group();
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
        return data

    def test_find_all_closed_upload_requests_of_URG(self):
        """"Test findAll closed upload requests of an upload request group"""
        upload_request_group = self.test_create_upload_request_group();
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
        upload_request_group = self.test_create_upload_request_group();
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
        upload_request_group = self.test_create_upload_request_group();
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
        upload_request_group = self.test_create_upload_request_group();
        self.assertEqual(upload_request_group['enableNotification'], False)
        query_url = '{base_url}/upload_request_groups/{upload_req_group_uuid}'.format_map({
            'base_url': self.base_url,
            'upload_req_group_uuid' : upload_request_group['uuid']
            })
        payload = {
            "label": upload_request_group['label'],
            "canDelete":upload_request_group['canDelete'],
            "canClose":upload_request_group['canClose'],
            "body":upload_request_group['body'],
            "enableNotification":True
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
        self.assertEqual(data['enableNotification'], True)
        return data

    def test_add_recipient_upload_request_group_grouped_mode_false(self):
        """Test create upload request group and add a new recipient the grouped mode is false by default."""
        upload_request_group = self.test_create_upload_request_group();
        query_url = '{base_url}/upload_request_groups/{upload_req_group_uuid}/recipients'.format_map({
            'base_url': self.base_url,
            'upload_req_group_uuid' : upload_request_group['uuid']
            })
        payload = [
                {
                "firstName": "walker",
                "lastName": "mccallister",
                "mail": "external2@linshare.org"
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
        """"Test findAll upload requests of an upload request group"""
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

    def test_add_recipient_upload_request_group_grouped_mode_true(self):
        """Test create upload request group and add a new recipient the grouped mode is true"""
        query_url = '{base_url}/upload_request_groups?groupMode={groupMode}'.format_map({
            'base_url': self.base_url,
            'groupMode' : 'true'
            })
        payload = {
            "label": "upload request group",
            "canDelete":True,
            "canClose":True,
            "contactList":[self.email_external1, self.email_external2, self.email_external3],
            "body":"test body",
            "enableNotification":False,
            "dirty":False
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
        """Add new recipient to the upload request group with grouped mode is true"""
        query_url = '{base_url}/upload_request_groups/{upload_req_group_uuid}/recipients'.format_map({
            'base_url': self.base_url,
            'upload_req_group_uuid' : data['uuid']
            })
        payload = [
                {
                "firstName": "walker",
                "lastName": "mccallister",
                "mail": "external4@linshare.org"
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
        """"Test findAll upload requests of an upload request group"""
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


class TestUserApiUploadRequestEntry(UserTestCase):
    """"Test user API upload request entry """
    upload_request_group_class = TestUserApiUploadRequestGroup()
    def test_create_upload_request_entry(self):
        """"Test user API create an upload request entry """
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
        data = req.json()
        self.assertEqual(len(data[0]['uploadRequestURLs']), 1)
        LOGGER.debug("The upload requests of the upload request group are well recovered")
        """Upload an upload request entry"""
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
        """Upload an upload request entry"""
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
        """Find upload request entry"""
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
        return data

    def test_delete_upload_request_entry(self):
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
        """Upload an upload request entry"""
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
        """Find upload request entry"""
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
        """Before deleteing an upload request entry we need to close or archive the upload request"""
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
        """Delete an upload request entry"""
        query_url = '{base_url}/upload_request_entries/{upload_req_entry_uuid}'.format_map({
            'base_url': self.base_url,
            'upload_req_entry_uuid' : data_entry[0]['uuid'],
            })
        req = requests.delete(
            query_url,
            headers=self.headers,
            auth=HTTPBasicAuth(self.email, self.password),
            verify=self.verify
        )
        LOGGER.debug("status_code : %s", req.status_code)
        LOGGER.debug("result : %s", req.text)
        self.assertEqual(req.status_code, 200)
        data = req.json()
        return data

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
        """Upload an upload request entry"""
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
        """Find upload request entry"""
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
        """Download an upload request entry"""
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
        """"Test user API copy an upload request entry """
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
        """Upload an upload request entry"""
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
        """Find upload request entry"""
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
        """Before copying an upload request entry we need to close the upload request"""
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
        """Copy an upload request entry"""
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


class TestUserApiUploadRequestExternal(UserTestCase):
    """"Test user API upload request for externals """
    upload_request_group_class = TestUserApiUploadRequestGroup()
    def test_close_upload_request_by_external(self):
        """"Test close an upload request by an external user"""
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
        self.assertEqual(data_upload_request[0]['status'], 'ENABLED')
        self.assertEqual(len(data_upload_request[0]['uploadRequestURLs']), 1)
        """Close an uploadRequest by an external"""
        query_url = '{base_external_url}/requests/{upload_url_uuid}'.format_map({
            'base_external_url': self.base_external_url,
            'upload_url_uuid' : data_upload_request[0]['uploadRequestURLs'][0]['uuid']
            })
        req = requests.put(
            query_url,
            headers=self.headers,
            auth=HTTPBasicAuth(self.email_external1, self.password_external1),
            verify=self.verify
        )
        self.assertEqual(req.status_code, 200)
        LOGGER.debug("status_code : %s", req.status_code)
        LOGGER.debug("result : %s", req.text)
        data = req.json()
        """Check the updated status to CLOSED after the update by the external user"""
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
        self.assertEqual(data_upload_request[0]['status'], 'CLOSED')
        return data

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
        """Upload an upload request entry"""
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
        """Find upload request entry"""
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
        """Delete an upload request entry by an external"""
        query_url = '{base_external_url}/requests/{upload_req_url}/{upload_req_entry_uuid}'.format_map({
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
        self.assertEqual(req.status_code, 204)

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
        """Upload an upload request entry"""
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
        """Find upload request entry"""
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
        """Delete an upload request entry by an external"""
        query_url = '{base_external_url}/requests/{upload_req_url}'.format_map({
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
        self.assertEqual(req.status_code, 204)


if __name__ == '__main__':
    unittest.main()
