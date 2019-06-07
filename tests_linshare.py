#!/usr/bin/env python3
# -*- coding: utf-8 -*-


import configparser
import json
import logging
import os
import requests
import sys
import unittest

from requests.auth import HTTPBasicAuth
from requests_toolbelt.utils import dump
from requests_toolbelt import (MultipartEncoder, MultipartEncoderMonitor)
from clint.textui.progress import Bar as ProgressBar


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


def create_callback(encoder):
    """TODO"""
    encoder_len = encoder.len
    bar = ProgressBar(expected_size=encoder_len, filled_char='=')
    def callback(monitor):
        bar.show(monitor.bytes_read)
    return callback


class TestCase(unittest.TestCase):
    """Default test case class"""

    host = CONFIG['DEFAULT']['host']
    base_url = host + '/linshare/webservice/rest/admin'
    user1_email = CONFIG['DEFAULT']['user1_email']
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
        data = self.request_delete(query_url + '/' + uuid)
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


class TestUserApiDocuments(TestCase):
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


class TestMailAttachment(TestCase):

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


class TestUserApiDocumentRevision(TestCase):
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


class TestUserApiSharedSpace(TestCase):
    """Test User api"""

    host = CONFIG['DEFAULT']['host']
    base_url = host + '/linshare/webservice/rest/user/v2'

    def create_shared_space(self):
        """Test user create a shared space."""
        query_url = self.base_url + '/shared_spaces'
        payload = {
            "name": "workgroup_test",
            "nodeType": "WORK_GROUP"
        }
        data = self.request_post(query_url, payload)
        self.assertEqual(data['name'], 'workgroup_test')
        return data

    def test_find_sahred_space(self):
        """"Test user find a shared space """
        workgroup = self.create_shared_space();
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
        """"Test user find shared space quota"""
        workgroup = self.create_shared_space();
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


class TestUserApiJwtPermanentToken(TestCase):
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


class TestUpdateCanCreateGuest(TestCase):
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


class TestUserApiContactList(TestCase):
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

class TestUserApiSharedSpaceNode(TestCase):
    """Test User api sharedSpaceNode"""
    host = CONFIG['DEFAULT']['host']
    base_url = host + '/linshare/webservice/rest/user/v2'

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
        workgroup = self.create_shared_space();
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


if __name__ == '__main__':
    unittest.main()
