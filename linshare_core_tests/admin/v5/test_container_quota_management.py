#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""Testing container quota management of adminv5 API."""


import logging

from deepdiff import DeepDiff


def find_domain_quota(request_helper, base_url, domain):
    """Helper to find domain quotas."""
    query_url = '{baseUrl}/domains/{domain_uuid}/domain_quotas'.format_map({
        'baseUrl': base_url,
        'domain_uuid': domain['uuid']
    })
    domain_quotas = request_helper.get(query_url)
    query_url = '{baseUrl}/domains/{dm_id}/domain_quotas/{qt_id}'.format_map({
        'baseUrl': base_url,
        'dm_id': domain['uuid'],
        'qt_id': domain_quotas[0]['uuid']
    })
    quota = request_helper.get(query_url)
    log = logging.getLogger('tests.funcs.test_find')
    log.debug("Domain quotas: %s", quota)
    assert quota
    assert quota['uuid'] == domain_quotas[0]['uuid']
    assert quota['usedSpace'] == 0
    return quota


def test_find_all(request_helper, base_url, domain):
    """Test find all domains quotas on admin API v5"""
    domain_quota = find_domain_quota(request_helper, base_url, domain)
    url = '{baseUrl}/domains/{dm_id}/domain_quotas/{qt_id}/containers'
    query_url = url.format_map({
        'baseUrl': base_url,
        'dm_id': domain_quota['domain']['uuid'],
        'qt_id': domain_quota['uuid']
    })
    data = request_helper.get(query_url)
    log = logging.getLogger('tests.funcs.test_find_all')
    log.debug("Container quotas: %s", data)
    assert data
    assert len(data) == 2
    container_quotas = request_helper.get(query_url)
    assert not DeepDiff(data, container_quotas)


def test_find(request_helper, base_url, domain):
    """Test find container quota on admin API v5"""
    domain_quota = find_domain_quota(request_helper, base_url, domain)
    url = '{baseUrl}/domains/{dm_id}/domain_quotas/{qt_id}/containers'
    query_url = url.format_map({
        'baseUrl': base_url,
        'dm_id': domain_quota['domain']['uuid'],
        'qt_id': domain_quota['uuid']
    })
    container_quotas = request_helper.get(query_url)
    url = '{baseUrl}/domains/{dm_id}/domain_quotas/{qt_id}/containers/{cq_id}'
    query_url = url.format_map({
        'baseUrl': base_url,
        'dm_id': domain_quota['domain']['uuid'],
        'qt_id': domain_quota['uuid'],
        'cq_id': container_quotas[0]['uuid']
    })
    quota = request_helper.get(query_url)
    log = logging.getLogger('tests.funcs.test_find')
    log.debug("Container quota: %s", quota)
    assert quota
    assert quota['quota'] == 400000000000
    assert quota['usedSpace'] == 0


def test_update(request_helper, base_url, domain):
    """Test update container quota on admin API v5"""
    domain_quota = find_domain_quota(request_helper, base_url, domain)
    url = '{baseUrl}/domains/{dm_id}/domain_quotas/{qt_id}/containers'
    query_url = url.format_map({
        'baseUrl': base_url,
        'dm_id': domain_quota['domain']['uuid'],
        'qt_id': domain_quota['uuid']
    })
    container_quotas = request_helper.get(query_url)
    url = '{baseUrl}/domains/{dm_id}/domain_quotas/{qt_id}/containers/{cq_id}'
    query_url = url.format_map({
        'baseUrl': base_url,
        'dm_id': domain_quota['domain']['uuid'],
        'qt_id': domain_quota['uuid'],
        'cq_id': container_quotas[0]['uuid']
    })
    payload = {
        "quota": 2000000000000,
        "defaultQuota": 1000000000000,
        "defaultQuotaOverride": False,
        "maintenance": False
    }
    data = request_helper.put(query_url, payload)
    log = logging.getLogger('tests.funcs.test_update')
    log.debug("Domain quota: %s", data)
    assert data
    assert data['quota'] == 2000000000000
