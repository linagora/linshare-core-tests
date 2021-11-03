#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""Testing user providers endpoints of adminv5 API."""


import logging


def create_remote_server(request_helper, base_url):
    """Helper to create remote server."""
    payload = {
        "name": "new connection",
        "bindDn": "cn=linshare,dc=linshare,dc=org",
        "url": "ldap://172.17.0.1:1389",
        "bindPassword": "linshare"
    }
    query_url = '{baseUrl}/remote_servers'.format_map({'baseUrl': base_url})
    remote_server = request_helper.post(query_url, payload)
    assert remote_server
    assert remote_server['url'] == "ldap://172.17.0.1:1389"
    assert remote_server['bindDn'] == "cn=linshare,dc=linshare,dc=org"
    return remote_server


def create_user_filter(request_helper, base_url):
    """Helper to create user filter."""
    auth_command = (
        "ldap.search(domain, \"(&(objectClass=inetOrgPerson) "
        "(mail=*)(givenName=*)(sn=*)(|(mail=\"+login+\") "
        "(uid=\"+login+\")))\");"
    )
    search_user_command = (
        "ldap.search(domain, "
        "\"(&(objectClass=inetOrgPerson) "
        "(mail=\"+mail+\")(givenName=\"+first_name+\") "
        "(sn=\"+last_name+\"))\");"
    )
    ac_on_all_attributes = (
        "ldap.search(domain, "
        " \"(&(objectClass=inetOrgPerson)(mail=*) "
        "(givenName=*)(sn=*) "
        "(|(mail=\" + pattern + \")(sn=\" + pattern + \") "
        "(givenName=\" + pattern + \")))\");"
    )
    ac_on_first_and_last_name = (
        "ldap.search(domain, \"(&(objectClass=inetOrgPerson)(mail=*) "
        "(givenName=*)(sn=*) "
        "(|(&(sn=\" + first_name + \") "
        "(givenName=\" + last_name + \"))"
        "(&(sn=\" + last_name + \") "
        "(givenName=\" + first_name + \"))))\");"
    )
    payload = {
        "description": "Test domain workgroup filter",
        "name": "User filter name",
        "authenticationQuery": auth_command,
        "searchUserQuery": search_user_command,
        "userMailAttribute": "mail",
        "userFirstNameAttribute": "givenName",
        "userLastNameAttribute": "sn",
        "userUidAttribute": "uid",
        "autoCompleteCommandOnAllAttributes": ac_on_all_attributes,
        "autoCompleteCommandOnFirstAndLastName": ac_on_first_and_last_name,
        "searchPageSize": 100,
        "searchSizeLimit": 100,
        "completionPageSize": 10,
        "completionSizeLimit": 10
    }
    query_url = '{baseUrl}/user_filters'.format_map({'baseUrl': base_url})
    user_filter = request_helper.post(query_url, payload)
    assert user_filter['userMailAttribute'] == "mail"
    return user_filter


def create_domain(request_helper, base_url, name="TopDomainUserProvider"):
    """Helper to create domain."""
    query_url = '{base_url}/domains'.format_map({
        'base_url': base_url,
    })
    payload = {
        "parent": {"uuid": "LinShareRootDomain"},
        "type": "TOPDOMAIN",
        "name": name,
        "description": "Description of top domain 'test user provider'"
    }
    domain = request_helper.post(query_url, payload)
    assert domain['type'] == "TOPDOMAIN"
    return domain


def create_ldap_user_provider(request_helper, base_url):
    """helper to create user provider."""
    ldap_server = create_remote_server(request_helper, base_url)
    user_filter = create_user_filter(request_helper, base_url)
    domain = create_domain(request_helper, base_url, "TopDomainUserProvider")
    query_url = '{base_url}/domains/{uuid}/user_providers'.format_map({
        'base_url': base_url,
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
        "userFilter": {
            "uuid": user_filter['uuid'],
            "name": user_filter['name']
        },
        "baseDn": "ou=people,dc=linshare,dc=org",
        "type": "LDAP_PROVIDER"
    }
    user_provider = request_helper.post(query_url, payload)
    assert user_provider
    assert user_provider['baseDn'] == "ou=people,dc=linshare,dc=org"
    assert user_provider['type'] == "LDAP_PROVIDER"
    return user_provider


def test_create(request_helper, base_url):
    """Test admin create user provider."""
    log = logging.getLogger('tests.user.providers.test_create')
    user_provider = create_ldap_user_provider(request_helper, base_url)
    log.debug("user provider created: %s", user_provider)
    assert user_provider
    assert user_provider['ldapServer']['name'] == "new connection"
    assert user_provider['userFilter']['name'] == "User filter name"


def test_find_all(request_helper, base_url):
    """Test admin find all created user providers"""
    entity = create_ldap_user_provider(request_helper, base_url)
    query_url = '{baseUrl}/domains/{uuid}/user_providers'.format_map({
        'baseUrl': base_url,
        'uuid': entity['domain']['uuid']
    })
    user_providers = request_helper.get(query_url)
    log = logging.getLogger('tests.user.providers.test_find_all')
    log.debug("user providers: %s", user_providers)
    if len(user_providers) != 0:
        assert user_providers
        for user_provider in user_providers:
            assert user_provider['baseDn'] == "ou=people,dc=linshare,dc=org"
            assert user_provider['type'] == "LDAP_PROVIDER"


def test_find(request_helper, base_url):
    """Test find existing user provider on API v5"""
    entity = create_ldap_user_provider(request_helper, base_url)
    query_url = '{baseUrl}/domains/{uuid}/user_providers/{provider_uuid}'
    query_url = query_url.format_map({
        'baseUrl': base_url,
        'uuid': entity['domain']['uuid'],
        'provider_uuid': entity['uuid']
    })
    data = request_helper.get(query_url)
    assert data
    assert data['baseDn'] == entity['baseDn']
    assert data['type'] == entity['type']


def test_delete(request_helper, base_url):
    """Test admin delete domain user provider."""
    log = logging.getLogger('tests.user.providers.test_delete')
    entity = create_ldap_user_provider(request_helper, base_url)
    query_url = '{baseUrl}/domains/{uuid}/user_providers/{provider_uuid}'
    query_url = query_url.format_map({
        'baseUrl': base_url,
        'uuid': entity['domain']['uuid'],
        'provider_uuid': entity['uuid']
    })
    data = request_helper.delete(query_url)
    log.debug("user provider deleted: %s", data)
    assert data
    query_url = '{baseUrl}/domains/{uuid}/user_providers/{provider_uuid}'
    query_url = query_url.format_map({
        'baseUrl': base_url,
        'uuid': entity['domain']['uuid'],
        'provider_uuid': entity['uuid']
    })
    request_helper.get(query_url, expected_status=404)


def test_delete_payload(request_helper, base_url):
    """Test admin delete domain user provider."""
    log = logging.getLogger('tests.user.providers.test_delete')
    entity = create_ldap_user_provider(request_helper, base_url)
    query_url = '{baseUrl}/domains/{uuid}/user_providers'.format_map({
        'baseUrl': base_url,
        'uuid': entity['domain']['uuid'],
    })
    data = request_helper.delete(query_url, entity)
    log.debug("user provider deleted: %s", data)
    assert data
    query_url = '{baseUrl}/domains/{uuid}/user_providers/{provider_uuid}'
    query_url = query_url.format_map({
        'baseUrl': base_url,
        'uuid': entity['domain']['uuid'],
        'provider_uuid': entity['uuid']
    })
    request_helper.get(query_url, expected_status=404)


def test_update(request_helper, base_url):
    """Test admin update domain user provider."""
    log = logging.getLogger('tests.user.providers.test_update')
    entity = create_ldap_user_provider(request_helper, base_url)
    query_url = '{baseUrl}/domains/{uuid}/user_providers'.format_map({
        'baseUrl': base_url,
        'uuid': entity['domain']['uuid']
    })
    data = request_helper.put(query_url, entity)
    log.debug("user provider update: %s", data)
    assert data
    assert data['userFilter']['name'] == entity['userFilter']['name']


def create_test_oidc_up(request_helper, base_url, domain, dm_discri):
    '''Helper to create OIDC user provider'''
    query_url = '{base_url}/domains/{uuid}/user_providers'.format_map({
        'base_url': base_url,
        'uuid': domain['uuid']
    })
    payload = {
        "type": "OIDC_PROVIDER",
        "domainDiscriminator": dm_discri,
        "checkExternalUserID": True
    }
    provider = request_helper.post(query_url, payload)
    return provider


def test_create_oidc_user_provider(request_helper, base_url):
    '''Test create OIDC user provider'''
    dom = create_domain(request_helper, base_url)
    provider = create_test_oidc_up(request_helper, base_url, dom, "DOM_TO_1")
    assert provider
    assert provider['type'] == "OIDC_PROVIDER"
    assert provider['domainDiscriminator'] == "DOM_TO_1"
    query_url = '{base_url}/domains/{uuid}/user_providers/{up_uuid}'
    query_url = query_url.format_map({
        'base_url': base_url,
        'uuid': dom['uuid'],
        'up_uuid': provider['uuid']
        })
    request_helper.delete(query_url)


def test_fail_creating_two_oidc_ups(request_helper, base_url):
    '''Two_oidc_user_providers_with_same_domain_discriminator'''
    dom = create_domain(request_helper, base_url, "DOM1")
    first_up = create_test_oidc_up(request_helper, base_url, dom, "DOM_TO_2")
    new_dom = create_domain(request_helper, base_url, name="OtherDomain")
    query_url = '{base_url}/domains/{uuid}/user_providers'.format_map({
        'base_url': base_url,
        'uuid': new_dom['uuid']
    })
    payload = {
        "type": "OIDC_PROVIDER",
        "domainDiscriminator": "DOM_TO_2",
        "checkExternalUserID": True
    }
    request_helper.post(query_url, payload, expected_status=400)
    query_url = '{base_url}/domains/{uuid}/user_providers/{up_uuid}'
    query_url = query_url.format_map({
        'base_url': base_url,
        'uuid': dom['uuid'],
        'up_uuid': first_up['uuid']
        })
    request_helper.delete(query_url)


def test_update_oidc_up(request_helper, base_url):
    '''Update OIDC user provider'''
    dom = create_domain(request_helper, base_url)
    provider = create_test_oidc_up(request_helper, base_url, dom, "DOM_TO_3")
    url = '{base_url}/domains/{uuid}/user_providers/{up_uuid}'.format_map({
        'base_url': base_url,
        'uuid': dom['uuid'],
        'up_uuid': provider['uuid']
    })
    provider['checkExternalUserID'] = True
    provider['useAccessClaim'] = True
    provider['useRoleClaim'] = True
    provider['useEmailLocaleClaim'] = True
    provider['domainDiscriminator'] = "DOM_TO_3_UPDATE"
    provider = request_helper.put(url, provider)
    assert provider['checkExternalUserID']
    assert provider['useAccessClaim']
    assert provider['useRoleClaim']
    assert provider['useEmailLocaleClaim']
    assert provider['domainDiscriminator'] == "DOM_TO_3_UPDATE"
    query_url = '{base_url}/domains/{uuid}/user_providers/{up_uuid}'
    query_url = query_url.format_map({
        'base_url': base_url,
        'uuid': dom['uuid'],
        'up_uuid': provider['uuid']
        })
    request_helper.delete(query_url)


def test_update_oidc_up_same_domain_discriminator(request_helper, base_url):
    '''test updated provider with same domain descriminator'''
    dom = create_domain(request_helper, base_url)
    provider = create_test_oidc_up(request_helper, base_url, dom, "DOM_TO_31")
    query_url = '{base_url}/domains/{uuid}/user_providers/{up_uuid}'
    query_url = query_url.format_map({
        'base_url': base_url,
        'uuid': dom['uuid'],
        'up_uuid': provider['uuid']
    })
    provider['domainDiscriminator'] = "DOM_TO_31"
    provider = request_helper.put(query_url, provider)
    assert provider['domainDiscriminator'] == "DOM_TO_31"
    query_url = '{base_url}/domains/{uuid}/user_providers/{up_uuid}'
    query_url = query_url.format_map({
        'base_url': base_url,
        'uuid': dom['uuid'],
        'up_uuid': provider['uuid']
        })
    request_helper.delete(query_url)


def test_fail_update_oidc_up_with_dm_discri_used(request_helper, base_url):
    '''Fail update oidc user provider when domain discriminator used'''
    new_dm = create_domain(request_helper, base_url, name="newDm")
    create_test_oidc_up(request_helper, base_url, new_dm, "NewDmDiscri")
    dom = create_domain(request_helper, base_url, name="DOM")
    provider = create_test_oidc_up(request_helper, base_url, dom, "DOM_TO_32")
    query_url = '{base_url}/domains/{uuid}/user_providers/{up_uuid}'
    query_url = query_url.format_map({
        'base_url': base_url,
        'uuid': dom['uuid'],
        'up_uuid': provider['uuid']
    })
    provider['domainDiscriminator'] = "NewDmDiscri"
    expected_status = 400
    busines_err_code = 38100
    request_helper.put(query_url, provider, expected_status, busines_err_code)
    query_url = '{base_url}/domains/{uuid}/user_providers/{up_uuid}'
    query_url = query_url.format_map({
        'base_url': base_url,
        'uuid': dom['uuid'],
        'up_uuid': provider['uuid']
        })
    request_helper.delete(query_url)


def test_delete_oidc_up(request_helper, base_url):
    '''Delete OIDC user provider'''
    dom = create_domain(request_helper, base_url)
    provider = create_test_oidc_up(request_helper, base_url, dom, "DOM_TO_4")
    query_url = '{base_url}/domains/{uuid}/user_providers'
    query_url = query_url.format_map({
        'base_url': base_url,
        'uuid': dom['uuid']
    })
    provider = request_helper.delete(query_url, provider)
    query_url = '{baseUrl}/domains/{uuid}/user_providers/{provider_uuid}'
    query_url = query_url.format_map({
        'baseUrl': base_url,
        'uuid': provider['domain']['uuid'],
        'provider_uuid': provider['uuid']
    })
    request_helper.get(query_url, expected_status=404)


def test_delete_oidc_up2(request_helper, base_url):
    '''Delete OIDC user provider using uuid in url'''
    dom = create_domain(request_helper, base_url)
    provider = create_test_oidc_up(request_helper, base_url, dom, "DOM_TO_5")
    query_url = '{base_url}/domains/{uuid}/user_providers/{up_uuid}'
    query_url = query_url.format_map({
        'base_url': base_url,
        'uuid': dom['uuid'],
        'up_uuid': provider['uuid']
        })
    request_helper.delete(query_url)
    query_url = '{baseUrl}/domains/{uuid}/user_providers/{provider_uuid}'
    query_url = query_url.format_map({
        'baseUrl': base_url,
        'uuid': provider['domain']['uuid'],
        'provider_uuid': provider['uuid']
    })
    request_helper.get(query_url, expected_status=404)
