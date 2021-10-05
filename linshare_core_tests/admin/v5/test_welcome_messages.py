#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""Testing WelcomeMessages endpoints of adminv5 API."""


import logging
import pytest


def find_default_welcome_message(request_helper, base_url):
    log = logging.getLogger('tests.funcs.find_default_welcome_message')
    query_url = '{baseUrl}/domains/{uuid}/welcome_messages'.format_map({
        'baseUrl': base_url,
        'uuid': 'LinShareRootDomain'
    })
    response = request_helper.get(query_url)
    log.debug("response: %s", response)
    assert response
    return response[0]['uuid']


@pytest.mark.domain_data("MyDomain")
def test_find_all_should_work(request_helper, base_url, domain):
    """Finding all WelcomeMessages should return the list of messages"""
    query_url = '{baseUrl}/domains/{uuid}/welcome_messages'.format_map({
        'baseUrl': base_url,
        'uuid': domain['uuid']
    })
    response = request_helper.get(query_url)
    assert response
    assert len(response) >= 1


@pytest.mark.domain_data("MyDomain")
def test_find_should_fail_when_welcome_message_doesnt_exists(request_helper, base_url, domain):
    """Finding a WelcomeMessage should fail when welcome message doesn't exists"""
    query_url = '{baseUrl}/domains/{uuid}/welcome_messages/{welcomeMessageUuid}'.format_map({
        'baseUrl': base_url,
        'uuid': domain['uuid'],
        'welcomeMessageUuid': "123-456-789"
    })
    request_helper.get(query_url, expected_status=404, busines_err_code=36004)


@pytest.mark.domain_data("MyDomain")
def test_find_should_fail_when_welcome_message_doesnt_belong_to_the_domain(request_helper, base_url, domain):
    """Finding a WelcomeMessage should fail when domain doesn't match"""
    # Given
    query_url = '{baseUrl}/domains/{uuid}/welcome_messages'.format_map({
        'baseUrl': base_url,
        'uuid': domain['uuid']
    })
    payload = {
        "uuid": find_default_welcome_message(request_helper, base_url),
        "name": "MyWelcomeMessage",
        "description": "Its description"
    }
    welcome_message = request_helper.post(query_url, payload)

    query_url = '{baseUrl}/domains'.format_map({
        'baseUrl': base_url,
    })
    payload = {
        "parent": {"uuid": "LinShareRootDomain"},
        "type": "TOPDOMAIN",
        "name": "OtherDomain",
        "description": "Description of top domain 'test user provider'"
    }
    other_domain = request_helper.post(query_url, payload)

    # When
    query_url = '{baseUrl}/domains/{uuid}/welcome_messages/{welcomeMessageUuid}'.format_map({
        'baseUrl': base_url,
        'uuid': other_domain['uuid'],
        'welcomeMessageUuid': welcome_message['uuid']
    })

    # Then
    request_helper.get(query_url, expected_status=404, busines_err_code=36004)


@pytest.mark.domain_data("MyDomain")
def test_find_should_work(request_helper, base_url, domain):
    """Finding a WelcomeMessage should work"""
    log = logging.getLogger('tests.funcs.test_find_should_work')
    query_url = '{baseUrl}/domains/{uuid}/welcome_messages'.format_map({
        'baseUrl': base_url,
        'uuid': domain['uuid']
    })
    payload = {
        "uuid": find_default_welcome_message(request_helper, base_url),
        "name": "MyWelcomeMessage",
        "description": "Its description",
    }
    welcome_message = request_helper.post(query_url, payload)
    log.debug("created message: %s", welcome_message)

    query_url = '{baseUrl}/domains/{uuid}/welcome_messages/{welcomeMessageUuid}'.format_map({
        'baseUrl': base_url,
        'uuid': domain['uuid'],
        'welcomeMessageUuid': welcome_message['uuid']
    })
    response = request_helper.get(query_url)
    log.debug("get response: %s", response)
    assert response
    assert response['uuid'] == welcome_message['uuid']


def test_create_should_fail_when_domain_doesnt_exists(request_helper, base_url):
    """Creating a WelcomeMessage should fail when domain doesn't exists"""
    query_url = '{baseUrl}/domains/{uuid}/welcome_messages'.format_map({
        'baseUrl': base_url,
        'uuid': "123-456-789"
    })
    payload = {
        "name": "MyWelcomeMessage",
        "description": "Its description",
        "entries": {}
    }
    request_helper.post(query_url, payload, expected_status=404, busines_err_code=13001)


@pytest.mark.domain_data("MyDomain")
def test_create_should_fail_when_uuid_is_not_given(request_helper, base_url, domain):
    """Creating a WelcomeMessage should fail when uuid is not in the payload"""
    query_url = '{baseUrl}/domains/{uuid}/welcome_messages'.format_map({
        'baseUrl': base_url,
        'uuid': domain['uuid']
    })
    payload = {
        "name": "MyWelcomeMessage",
        "description": "Its description",
        "entries": {}
    }
    request_helper.post(query_url, payload, expected_status=400)


@pytest.mark.domain_data("MyDomain")
def test_create_should_works(request_helper, base_url, domain):
    """Creating a WelcomeMessage should work and return all data"""
    # Given
    log = logging.getLogger('tests.funcs.test_create_should_works')
    query_url = '{baseUrl}/domains/{uuid}/welcome_messages'.format_map({
        'baseUrl': base_url,
        'uuid': domain['uuid']
    })
    payload = {
        "uuid": find_default_welcome_message(request_helper, base_url),
        "name": "MyWelcomeMessage",
        "description": "Its description",
        "entries": {
            "ENGLISH": "WelcomeMessagesEntry",
            "FRENCH": "WelcomeMessagesEntry"
        }
    }

    # When
    welcome_message = request_helper.post(query_url, payload)
    log.debug("welcome_message: %s", welcome_message)
    assert welcome_message

    # Then
    query_url = '{baseUrl}/domains/{uuid}/welcome_messages/{welcomeMessageUuid}'.format_map({
        'baseUrl': base_url,
        'uuid': domain['uuid'],
        'welcomeMessageUuid': welcome_message['uuid']
    })
    response = request_helper.get(query_url)
    assert response['uuid']
    assert response['name'] == "MyWelcomeMessage"
    assert response['description'] == "Its description"
    assert response['assignedToCurentDomain'] == False
    assert response['readOnly'] == False
    assert response['creationDate']
    assert response['modificationDate']
    assert len(response['entries']) == 4
