#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""Testing domain quota management of adminv5 API."""


import logging


def test_find_all(request_helper, base_url, domain):
    """Test find all domain quotas on admin API v5"""
    query_url = '{baseUrl}/domains/{dm_id}/domain_quotas'.format_map({
        'baseUrl': base_url,
        'dm_id': domain['uuid']
    })
    data = request_helper.get(query_url)
    log = logging.getLogger('tests.funcs.test_find_all')
    log.debug("Domain quotas: %s", data)
    assert data


def test_find(request_helper, base_url, domain):
    """Test find domain quota on admin API v5"""
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
    assert quota['currentValueForSubdomains'] == 0
    assert quota['usedSpace'] == 0
    assert quota['defaultQuota'] == 1000000000000


def test_update(request_helper, base_url, domain):
    """Test update domains quota on admin API v5"""
    query_url = '{baseUrl}/domains/{dm_id}/domain_quotas'.format_map({
        'baseUrl': base_url,
        'dm_id': domain['uuid']
    })
    domain_quotas = request_helper.get(query_url)
    query_url = '{baseUrl}/domains/{dm_id}/domain_quotas/{qt_id}'.format_map({
        'baseUrl': base_url,
        'dm_id': domain_quotas[0]['domain']['identifier'],
        'qt_id': domain_quotas[0]['uuid']
    })
    payload = {
        "quota": 2000000000000,
        "defaultQuota": 1000000000000,
        "defaultQuotaOverride": False,
        "maintenance": False,
        "defaultDomainShared": False,
        "defaultDomainSharedOverride": False
    }
    data = request_helper.put(query_url, payload)
    log = logging.getLogger('tests.funcs.test_update')
    log.debug("Domain quota: %s", data)
    assert data
    assert data['quota'] == 2000000000000
