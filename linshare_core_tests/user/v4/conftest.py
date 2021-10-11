#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""Testing functionalities endpoints of userv4 API."""


import pytest


@pytest.fixture(scope="module", name="base_url")
def fixture_base_url(user_cfg):
    """Return base URL for all tests"""
    host = user_cfg['DEFAULT']['host']
    base_url = host + '/linshare/webservice/rest/user/v4'
    return base_url
