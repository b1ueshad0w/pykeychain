#!/usr/bin/env python
# coding=utf-8

""" keychain.py: Access keychain
 
Created by gogleyin on 5/18/16.
"""

import os
import re
from subprocess import check_output, CalledProcessError

import logging
logger = logging.getLogger(__name__ if __name__ != '__main__' else os.path.splitext(os.path.basename(__file__))[0])
logger.setLevel(logging.DEBUG)


OS_TOOL = 'security'


def _parse_find_identity_output(output):
    dict_ = {}
    regex = '\d\) ([\dA-F]{40}) "(.+)"'
    for line in output.splitlines():
        line = line.strip()
        match = re.match(regex, line)
        if not match:
            continue
        values = match.groups()
        if len(values) != 2:
            continue
        dict_[values[0]] = values[1]
    return dict_


def _parse_list_keychains(output):
    ret = {}
    for line in output.splitlines():
        line = line.strip(' "')  # Remove leading (trailing) spaces and quotation marks.
        if line.endswith('login.keychain') or line.endswith('login.keychain-db'):
            ret['login'] = line
        elif line.endswith('System.keychain'):
            ret['system'] = line
        else:
            logger.error('Unexpected content: %s' % output)
    return ret


def add_p12_to_login_keychain(p12_path, password='""'):
    keychains = list_keychains()
    if 'login' not in keychains:
        logger.error('Cannot find login keychain!')
        return False
    return add_p12_to_keychain(p12_path, keychains['login'], password=password)


def add_p12_to_keychain(p12_path, keychain, password='""'):
    """
    Add p12 certificate to keychain.
    :param p12_path: p12 file path
    :param keychain: to which keychain ('/Users/newmonkey/Library/Keychains/login.keychain')
    :param password: keychain password. If empty, use empty string '""'.
    :return: Boolean value indicates a success or failure.
    """
    args = [OS_TOOL, 'import', '"%s"' % p12_path, '-k', keychain, '-P', password, '-T', '/usr/bin/codesign']
    cmd = ' '.join(args)
    logger.debug(cmd)
    try:
        logger.debug(check_output(cmd, shell=True))
        return True
    except CalledProcessError as e:
        logger.error(e.message)
        return False


def delete_certificate(name_or_hash):
    """ Delete a certificate from a keychain.
    Usage: delete-certificate [-c name] [-Z hash] [-t] [keychain...]
    -c  Specify certificate to delete by its common name
    -Z  Specify certificate to delete by its SHA-1 hash value
    -t  Also delete user trust settings for this certificate
    The certificate to be deleted must be uniquely specified either by a
    string found in its common name, or by its SHA-1 hash.
    If no keychains are specified to search, the default search list is used.
    :param name_or_hash:
    :param keychains:
    :return:
    """
    hash_regex = '[A-F0-9]{40}'
    option_str = 'Z' if re.match(hash_regex, name_or_hash) else 'c'
    cmd = '{0} {1} -{2} "{3}"'.format(OS_TOOL, 'delete-certificate', option_str, name_or_hash)
    logger.debug(cmd)
    try:
        logger.debug(check_output(cmd, shell=True))
        return True
    except CalledProcessError, e:
        logger.exception(e)
        return False


def find_identity(policy=None, string=None, valid=False, for_code_signing=False, keychains=[]):
    """ Find an identity (certificate + private key).
    Find identities in keychains using [security find-identity]
    Usage: find-identity [-p policy] [-s string] [-v] [keychain...]
    -p  Specify policy to evaluate (multiple -p options are allowed)
        Supported policies: basic, ssl-client, ssl-server, smime, eap,
        ipsec, ichat, codesigning, sys-default, sys-kerberos-kdc, macappstore, appleID
    -s  Specify optional policy-specific string (e.g. DNS hostname for SSL,
        or RFC822 email address for S/MIME)
    -v  Show valid identities only (default is to show all identities)
    If no keychains are specified to search, the default search list is used.
    :param for_code_signing: find identities that can be used for signing code
    :param policy: Specify policy to evaluate
    :param string: Specify optional policy-specific string
    :param valid: Show valid identities only (default is to show all identities)
    :param keychains: Keychains to search
    :return: key-value pairs (Dictionary)
    """
    # TODO Not all cases are considered here.
    sub_command = 'find-identity'
    args = [OS_TOOL, sub_command]
    args.append('-v') if valid else None
    args += ['-p', 'codesigning'] if for_code_signing else []
    keychain_info = ' '.join(keychains)
    args.append(keychain_info) if len(keychain_info) > 0 else None
    cmd = ' '.join(args)
    logger.debug(cmd)
    try:
        output = check_output(cmd, shell=True)
        logger.debug(output)
        return _parse_find_identity_output(output)
    except CalledProcessError as e:
        logger.error(e.message)
        return False


def list_keychains():
    sub_command = 'list-keychains'
    cmd = '{0} {1}'.format(OS_TOOL, sub_command)
    try:
        output = check_output(cmd, shell=True)
        return _parse_list_keychains(output)
    except CalledProcessError, e:
        logger.exception(e)
        return False


def is_code_sign_identity_installed(code_sign_identity, delete_if_outdated=False):
    all_identities = find_identity(for_code_signing=True, valid=False)

    if code_sign_identity not in all_identities.values():
        logger.debug('Code Signing Identity not found: %s' % (code_sign_identity,))
        return False

    valid_identities = find_identity(for_code_signing=True, valid=True)
    if code_sign_identity not in valid_identities.values():
        logger.debug('The Certificate of %s is outdated! Will delete the old one.' % (code_sign_identity,))
        if not delete_if_outdated:
            return False
        if not delete_certificate(code_sign_identity):
            raise RuntimeError('Cannot delete certificate: %s. Maybe write permissions error.' % (code_sign_identity,))
        logger.debug('Outdated certificate deleted.')
        return False
    return True


def install_code_sign_identity_if_needed(code_sign_identity, p12_path, password):
    from lib.macconfig.parsep12 import get_code_sign_identity_from_p12
    # code_sign_identity = get_code_sign_identity_from_p12(p12_path, password=password)
    if is_code_sign_identity_installed(code_sign_identity, delete_if_outdated=True):
        logger.debug('P12 already installed: %s' % p12_path)
        return
    if not add_p12_to_login_keychain(p12_path, password):
        raise RuntimeError('Install p12 failed: %s' % p12_path)

if __name__ == '__main__':
    logging.basicConfig(level=logging.DEBUG)
    from pprint import pprint
    p12_path = '/path/to/YourCertificate.p12'
    keychain = '/Users/username/Library/Keychains/login.keychain'
    sys_keychain = '/Library/Keychains/System.keychain'
    password = '""'  # leave it if password is empty
    logger.debug(add_p12_to_keychain(p12_path, keychain, password))
    pprint(find_identity(valid=False, for_code_signing=True, keychains=[]))
    pprint(list_keychains())
    print(delete_certificate('05036AE2B81DFA877F33A0E88CBF5C9834B40B95'))
    print is_code_sign_identity_installed('iPhone Developer: XXXXX (XXXXXXXXXX)')


