#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""Testing shared spaces endpoints of adminv5 API."""


import urllib
# import json


def test_find_all_shared_spaces(request_helper, base_url):
    """Test admin find all sharedSpaces."""
    node_types = ['WORK_GROUP', 'WORK_SPACE']
    query_url = '{baseUrl}/shared_spaces'.format_map({
        'baseUrl': base_url
    })
    nodes = request_helper.get(query_url)
    if len(nodes) > 0:
        for node in nodes:
            assert node['nodeType'] in node_types
            assert node['domainUuid'] is not None


def test_find_all_workgroups(request_helper, base_url):
    """Test admin find all workgroups."""
    encoded_url = urllib.parse.urlencode({'nodeType': "WORK_GROUP"})
    query_url = '{baseUrl}/shared_spaces?{encode}'.format_map({
        'baseUrl': base_url,
        'encode': encoded_url})
    nodes = request_helper.get(query_url)
    if len(nodes) > 0:
        for node in nodes:
            assert node['nodeType'] == "WORK_GROUP"
            assert node['domainUuid'] is not None


def test_find_all_work_spaces(request_helper, base_url):
    """Test admin find all Drives."""
    encoded_url = urllib.parse.urlencode({'nodeType': "WORK_SPACE"})
    query_url = '{baseUrl}/shared_spaces?{encode}'.format_map({
        'baseUrl': base_url,
        'encode': encoded_url})
    nodes = request_helper.get(query_url)
    if len(nodes) > 0:
        for node in nodes:
            assert node['nodeType'] == "WORK_SPACE"
            assert node['domainUuid'] is not None
