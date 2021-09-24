#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""Testing functionalities endpoints of adminv4 API."""


import pytest


@pytest.fixture(scope="module", name="base_url")
def fixture_base_url(admin_cfg):
    """Return base URL for all tests"""
    host = admin_cfg['DEFAULT']['host']
    base_url = host + '/linshare/webservice/rest/admin/v4'
    return base_url
