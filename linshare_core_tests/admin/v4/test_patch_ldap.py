#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""Testing functionalities endpoints of adminv5 API."""

import os
import logging
import pytest


@pytest.mark.run_test_if_env('gitlab')
def test_config(display_admin_cfg):
    """Just display current config."""
    display_admin_cfg()


@pytest.mark.run_test_if_env('gitlab')
def test_patch_ldap(request_helper, base_url):
    """Getting all domains from LinShare"""
    query_url = '{baseUrl}/ldap_connections'.format_map({
        'baseUrl': base_url
    })
    data = request_helper.get(query_url)
    log = logging.getLogger('tests.patch.test_patch_ldap')
    log.info("ldap: %s", data)
    assert data
    ldap_host = os.getenv("LDAP_PORT_1636_TCP_ADDR", None)
    if not ldap_host:
        log.warning(
            (
                "Patching ldap host ignored, "
                "env variable LDAP_PORT_1636_TCP_ADDR not found"
            )
        )
        return
    ldap_uri = 'ldap://' + ldap_host + ':1389'
    log.info("ldap uri: %s", ldap_uri)
    for ldap in data:
        if ldap['providerUrl'] == 'ldap://ldap:1389':
            ldap['providerUrl'] = ldap_uri
            request_helper.put(query_url, ldap)
