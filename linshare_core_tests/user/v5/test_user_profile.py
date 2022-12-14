#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""Testing user profile endpoints of userv5 API."""


import urllib


def test_config(display_user_cfg):
    """Just display current config."""
    display_user_cfg()


def test_find_user_profile_internal(request_helper, base_url):
    """Test find user profile API v5 - internal user"""
    query_url = '{baseUrl}/me/profile'
    query_url = query_url.format_map({
        'baseUrl': base_url
    })
    data = request_helper.get(query_url)
    assert data
    assert not data['canCreateGuest']
    assert data['uuid']
    assert data['firstName'] == 'Peter'
    assert data['lastName'] == 'WILSON'
    assert data['mail'] == 'peter.wilson@linshare.org'
    assert data['creationDate']
    assert data['modificationDate']
    assert data['mailLocale'] == 'ENGLISH'
    assert data['externalMailLocale'] == 'ENGLISH'
    assert data['personalSpaceEnabled']
    assert data['accountType'] == 'INTERNAL'


def test_find_user_profile_guest(request_helper, base_url, new_guest):
    """Test find user profile API v5 - guest"""
    query_url = '{baseUrl}/me/profile'
    query_url = query_url.format_map({
        'baseUrl': base_url
    })
    data = request_helper.get(
        query_url, email=new_guest['mail'], password='MyGuest@Password123')
    assert data
    assert data['expirationDate']
    assert not data['restricted']
    assert data['author']
    assert data['author']['firstName'] == 'Guest'
    assert data['author']['lastName'] == 'My'
    assert data['author']['mail'] == 'guest1@linshare.org'
    assert data['author']['uuid']
    assert data['uuid']
    assert data['firstName'] == 'Guest'
    assert data['lastName'] == 'My'
    assert data['mail'] == 'guest1@linshare.org'
    assert data['creationDate']
    assert data['modificationDate']
    assert data['mailLocale'] == 'ENGLISH'
    assert data['externalMailLocale'] == 'ENGLISH'
    assert not data['personalSpaceEnabled']
    assert data['accountType'] == 'GUEST'


def test_update_user_profile_first_name_fail_internal(
        request_helper, base_url):
    """Test updating a user profile first name should fail - internal"""
    query_url = '{baseUrl}/me/profile'
    query_url = query_url.format_map({
        'baseUrl': base_url
    })
    user = request_helper.get(query_url)

    query_url = '{baseUrl}/me/profile/{uuid}'
    query_url = query_url.format_map({
        'baseUrl': base_url,
        'uuid': user['uuid']
    })
    user['firstName'] = 'Pedro'
    request_helper.put(query_url, payload=user,
                       expected_status=400, busines_err_code=67001)


def test_update_user_profile_account_type_fail_internal(
        request_helper, base_url, new_guest):
    """Test updating a user profile account type should fail - internal"""
    query_url = '{baseUrl}/me/profile'
    query_url = query_url.format_map({
        'baseUrl': base_url
    })
    user = request_helper.get(query_url)

    query_url = '{baseUrl}/me/profile/{uuid}'
    query_url = query_url.format_map({
        'baseUrl': base_url,
        'uuid': user['uuid']
    })
    # Convert INTERNAL json into GUEST json
    del user['canCreateGuest']
    user['expirationDate'] = new_guest['creationDate']
    user['restricted'] = new_guest['restricted']
    user['author'] = new_guest['owner']
    del user['author']['domain']
    del user['author']['accountType']
    del user['author']['external']

    user['accountType'] = 'GUEST'
    request_helper.put(query_url, payload=user,
                       expected_status=400, busines_err_code=67000)


def test_update_user_profile_last_name_fail_guest(
        request_helper, base_url, new_guest):
    """Test updating a user profile last name should fail - guest"""
    query_url = '{baseUrl}/me/profile'
    query_url = query_url.format_map({
        'baseUrl': base_url
    })
    user = request_helper.get(
        query_url, email=new_guest['mail'], password='MyGuest@Password123')

    query_url = '{baseUrl}/me/profile/{uuid}'
    query_url = query_url.format_map({
        'baseUrl': base_url,
        'uuid': user['uuid']
    })
    user['lastName'] = 'Hawkins'
    request_helper.put(query_url, payload=user,
                       email=new_guest['mail'], password='MyGuest@Password123',
                       expected_status=400, busines_err_code=67001)


def test_update_user_profile_account_type_fail_guest(
        request_helper, base_url, new_guest):
    """Test updating a user profile account type should fail - guest"""
    query_url = '{baseUrl}/me/profile'
    query_url = query_url.format_map({
        'baseUrl': base_url
    })
    user = request_helper.get(
        query_url, email=new_guest['mail'], password='MyGuest@Password123')

    query_url = '{baseUrl}/me/profile/{uuid}'
    query_url = query_url.format_map({
        'baseUrl': base_url,
        'uuid': user['uuid']
    })
    # Convert GUEST json into INTERNAL json
    user['canCreateGuest'] = True
    del user['expirationDate']
    del user['restricted']
    del user['author']
    user['canCreateGuest'] = True
    user['accountType'] = 'INTERNAL'
    request_helper.put(query_url, payload=user,
                       email=new_guest['mail'], password='MyGuest@Password123',
                       expected_status=400, busines_err_code=67000)


def test_update_user_profile_locale_internal(
        request_helper, base_url):
    """Test updating a user profile locale - internal"""
    query_url = '{baseUrl}/me/profile'
    query_url = query_url.format_map({
        'baseUrl': base_url
    })
    user = request_helper.get(query_url)

    query_url = '{baseUrl}/me/profile/{uuid}'
    query_url = query_url.format_map({
        'baseUrl': base_url,
        'uuid': user['uuid']
    })
    user['mailLocale'] = 'RUSSIAN'
    request_helper.put(query_url, payload=user)

    query_url = '{baseUrl}/me/profile'
    query_url = query_url.format_map({
        'baseUrl': base_url
    })
    user = request_helper.get(query_url)
    assert user['mailLocale'] == 'RUSSIAN'


def test_update_user_profile_external_mail_locale_internal(
        request_helper, base_url):
    """Test updating a user profile external users mai locale - internal"""
    query_url = '{baseUrl}/me/profile'
    query_url = query_url.format_map({
        'baseUrl': base_url
    })
    user = request_helper.get(query_url)

    query_url = '{baseUrl}/me/profile/{uuid}'
    query_url = query_url.format_map({
        'baseUrl': base_url,
        'uuid': user['uuid']
    })
    user['externalMailLocale'] = 'RUSSIAN'
    request_helper.put(query_url, payload=user)

    query_url = '{baseUrl}/me/profile'
    query_url = query_url.format_map({
        'baseUrl': base_url
    })
    user = request_helper.get(query_url)
    assert user['externalMailLocale'] == 'RUSSIAN'


def test_update_user_profile_locale_guest(
        request_helper, base_url, new_guest):
    """Test updating a user profile locale - guest"""
    query_url = '{baseUrl}/me/profile'
    query_url = query_url.format_map({
        'baseUrl': base_url
    })
    user = request_helper.get(
        query_url, email=new_guest['mail'], password='MyGuest@Password123')

    query_url = '{baseUrl}/me/profile/{uuid}'
    query_url = query_url.format_map({
        'baseUrl': base_url,
        'uuid': user['uuid']
    })
    user['mailLocale'] = 'RUSSIAN'
    request_helper.put(query_url, payload=user,
                       email=new_guest['mail'], password='MyGuest@Password123')

    query_url = '{baseUrl}/me/profile'
    query_url = query_url.format_map({
        'baseUrl': base_url
    })
    user = request_helper.get(query_url)
    assert user['mailLocale'] == 'RUSSIAN'


def test_update_user_profile_external_mail_locale_guest(
        request_helper, base_url, new_guest):
    """Test updating a user profile external users mai locale - guest"""
    query_url = '{baseUrl}/me/profile'
    query_url = query_url.format_map({
        'baseUrl': base_url
    })
    user = request_helper.get(
        query_url, email=new_guest['mail'], password='MyGuest@Password123')

    query_url = '{baseUrl}/me/profile/{uuid}'
    query_url = query_url.format_map({
        'baseUrl': base_url,
        'uuid': user['uuid']
    })
    user['externalMailLocale'] = 'RUSSIAN'
    request_helper.put(query_url, payload=user,
                       email=new_guest['mail'], password='MyGuest@Password123')

    query_url = '{baseUrl}/me/profile'
    query_url = query_url.format_map({
        'baseUrl': base_url
    })
    user = request_helper.get(query_url)
    assert user['externalMailLocale'] == 'RUSSIAN'


def test_restricted_contacts_fail(
        request_helper, base_url):
    """Test loading restricted contacts should fail for internal users"""
    query_url = '{baseUrl}/me/restricted_contacts'
    query_url = query_url.format_map({
        'baseUrl': base_url
    })
    request_helper.get(query_url, expected_status=400, busines_err_code=67000)


def test_restricted_contacts_guest(
        request_helper, base_url, new_guest, new_restricted_contact):
    """Test loading restricted contacts for guest users"""
    query_url = '{baseUrl}/me/restricted_contacts'
    query_url = query_url.format_map({
        'baseUrl': base_url
    })
    contacts = request_helper.get(
        query_url, email=new_guest['mail'], password='MyGuest@Password123')

    assert contacts
    assert len(contacts) == 1
    assert contacts[0]['uuid'] == new_restricted_contact['uuid']
    assert contacts[0]['firstName'] == new_restricted_contact['firstName']
    assert contacts[0]['lastName'] == new_restricted_contact['lastName']
    assert contacts[0]['mail'] == new_restricted_contact['mail']


def test_favourite_recipients_internal(
        request_helper, base_url, new_upload_request):
    """Test loading favourite recipients - internal"""
    assert new_upload_request
    query_url = '{baseUrl}/me/favourite_recipients'
    query_url = query_url.format_map({
        'baseUrl': base_url
    })
    recipients = request_helper.get(query_url)

    assert recipients
    assert len(recipients) == 2


def test_favourite_recipients_guest(
        request_helper, base_url, new_guest, new_guest_upload_request):
    """Test loading favourite recipients - guest"""
    assert new_guest_upload_request
    query_url = '{baseUrl}/me/favourite_recipients'
    query_url = query_url.format_map({
        'baseUrl': base_url
    })
    recipients = request_helper.get(
        query_url, email=new_guest['mail'], password='MyGuest@Password123')

    assert recipients
    assert len(recipients) == 3


def test_favourite_recipients_filter_internal(
        request_helper, base_url, new_upload_request):
    """Test loading favourite recipients filtered - internal"""
    assert new_upload_request
    encoded_url = urllib.parse.urlencode({'mail': "xt1@li"})
    query_url = '{baseUrl}/me/favourite_recipients?{encode}'
    query_url = query_url.format_map({
        'baseUrl': base_url,
        'encode': encoded_url
    })
    recipients = request_helper.get(query_url)

    assert recipients
    assert len(recipients) == 1
    assert recipients[0]['recipient'] == 'ext1@linshare.org'


def test_favourite_recipients_filter_guest(
        request_helper, base_url, new_guest, new_guest_upload_request):
    """Test loading favourite recipients - guest"""
    assert new_guest_upload_request
    encoded_url = urllib.parse.urlencode({'mail': "xtguest"})
    query_url = '{baseUrl}/me/favourite_recipients?{encode}'
    query_url = query_url.format_map({
        'baseUrl': base_url,
        'encode': encoded_url
    })
    recipients = request_helper.get(
        query_url, email=new_guest['mail'], password='MyGuest@Password123')

    assert recipients
    assert len(recipients) == 2


def test_favourite_recipients_delete_should_fail(
        request_helper, base_url):
    """Test deleting favourite recipients
    fail when recipient don't exists - internal"""
    query_url = '{baseUrl}/me/favourite_recipients/{recipient}'
    query_url = query_url.format_map({
        'baseUrl': base_url,
        'recipient': 'wrong'
    })
    request_helper.delete(query_url,
                          expected_status=400, busines_err_code=68000)


def test_favourite_recipients_delete_internal(
        request_helper, base_url, new_upload_request):
    """Test deleting favourite recipients - internal"""
    assert new_upload_request
    query_url = '{baseUrl}/me/favourite_recipients/{recipient}'
    query_url = query_url.format_map({
        'baseUrl': base_url,
        'recipient': 'ext1@linshare.org'
    })
    recipient = request_helper.delete(query_url)
    assert recipient

    query_url = '{baseUrl}/me/favourite_recipients'
    query_url = query_url.format_map({
        'baseUrl': base_url
    })
    recipients = request_helper.get(query_url)
    assert recipients
    assert len(recipients) == 1
    assert recipients[0]['recipient'] == 'ext2@linshare.org'


def test_favourite_recipients_delete_guest(
        request_helper, base_url, new_guest, new_guest_upload_request):
    """Test deleting favourite recipients - guest"""
    assert new_guest_upload_request
    query_url = '{baseUrl}/me/favourite_recipients/{recipient}'
    query_url = query_url.format_map({
        'baseUrl': base_url,
        'recipient': 'extother@linshare.org'
    })
    recipient = request_helper.delete(
        query_url, email=new_guest['mail'], password='MyGuest@Password123')
    assert recipient

    query_url = '{baseUrl}/me/favourite_recipients'
    query_url = query_url.format_map({
        'baseUrl': base_url
    })
    recipients = request_helper.get(
        query_url, email=new_guest['mail'], password='MyGuest@Password123')
    assert recipients
    assert len(recipients) == 2
