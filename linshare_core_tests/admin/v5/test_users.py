#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""Testing users endpoints of adminv5 API."""


import logging
# import json


def test_find_all(request_helper, base_url):
    """Test find all users on admin API v5"""
    query_url = '{baseUrl}/users'.format_map({
        'baseUrl': base_url
    })
    users = request_helper.get(query_url)
    log = logging.getLogger('tests.funcs.test_find_all')
    log.debug("users: %s", users)
    if len(users) > 0:
        for user in users:
            assert user['uuid'] != "root@localhost.localdomain"


def test_update_root_user_fail(request_helper, base_url):
    """Test failing update root user on admin API v5"""
    query_url = '{baseUrl}/users'.format_map({
        'baseUrl': base_url
    })
    payload = {
        "uuid": "root@localhost.localdomain",
        "firstName": "testRootUpdate",
        "lastName": "administrator",
        "mail": "root@localhost.localdomain",
        "role": "SUPERADMIN",
        "canUpload": True,
        "canCreateGuest": True,
        "accountType": "ROOT",
        "domain":
            {
                "uuid": "LinShareRootDomain",
                "name": "top1"
            },
        "externalMailLocale": "ENGLISH",
        "secondFAUuid": "27dbc951-763c-4d2c-8151-98dec3bc4ee7",
        "secondFAEnabled": False,
        "locked": False
    }
    request_helper.put(
        query_url,
        payload,
        expected_status=403,
        busines_err_code=17000
    )
