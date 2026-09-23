#!/usr/bin/env python3
"""andotp-decrypt.py

Usage:
  andotp-decrypt.py [-o|--old] [--debug] [-f FORMAT] [-h|--help] [--version] INPUT_FILE

Options:
  -o --old      Use old encryption (andOTP <= 0.6.2)
  -f FORMAT --format=FORMAT
                Output format [default: json]
                  json: the decrypted backup as-is
                  pass: one "NAME<TAB>otpauth://..." line per entry, for
                        importing into pass (pass-otp) or gopass
  --debug       Print debug info
  -h --help     Show this screen.
  --version     Show version.

"""

import os
import re
import sys
import json
import hashlib
import struct
from urllib.parse import quote, urlencode
from getpass import getpass

from Crypto.Cipher import AES
from Crypto.Hash import SHA256

from docopt import docopt


def bytes2Hex(bytes2encode):
    return '(%s) 0x%s' % (len(bytes2encode), ''.join('{:02x}'.format(x) for x in bytes2encode))


def decode(key, data, debug=False):
    """Decode function used for both the old and new style encryption"""
    # Raw data structure is IV[:12] + crypttext[12:-16] + auth_tag[-16:]
    iv = data[:12]
    crypttext = data[12:-16]
    tag = data[-16:]
    if debug:
        print("Input bytes: %", bytes2Hex(data))
        print("IV: %s" % bytes2Hex(iv))
        print("Crypttext: %s" % bytes2Hex(crypttext))
        print("Auth tag: %s" % bytes2Hex(tag))
    try:
        aes = AES.new(key, AES.MODE_GCM, nonce=iv)
    except Exception as e:
        print(e)
        return None

    try:
        dec = aes.decrypt_and_verify(crypttext, tag)
        if debug:
            print("Decrypted data: %s" % bytes2Hex(dec))
        return dec.decode('UTF-8')
    except ValueError as e:
        print(e)
        print("The passphrase was probably wrong")
        return None


def decrypt_aes_new_format(password, input_file, debug=False):
    input_bytes = None
    with open(input_file, 'rb') as f:
        input_bytes = f.read()

    if len(input_bytes) == 0:
        print("No data could be read. The input file is unreadable or empty")
        return None

    try:
        # Raw data structure is iterations[:4] + salt[4:16] + data[16:]
        iterations = struct.unpack(">I", input_bytes[:4])[0]
        salt = input_bytes[4:16]
        data = input_bytes[16:]
        try:
            pbkdf2_key = hashlib.pbkdf2_hmac('sha1', password, salt, iterations, 32)
        except OverflowError:
            print("Could not parse iterations from file, "
                  "either the file is broken or the format has changed.")
            return None
        if debug:
            print("Iterations: %s" % iterations)
            print("Salt: %s" % bytes2Hex(salt))
            print("Pbkdf2 key: %s" % bytes2Hex(pbkdf2_key))
        return decode(pbkdf2_key, data, debug)
    except struct.error:
        print("The input data could not be decrypted")
        return None


def decrypt_aes(password, input_file, debug=False):
    hash = SHA256.new(password)
    symmetric_key = hash.digest()
    if debug:
        print("Symmetric key: %s" % bytes2Hex(symmetric_key))
    input_bytes = None
    with open(input_file, 'rb') as f:
        input_bytes = f.read()

    return decode(symmetric_key, input_bytes, debug)


def get_password():
    # Read the backup password manually via a prompt if stdin is a tty,
    # otherwise read from stdin directly.
    if sys.stdin.isatty():
        pw = getpass('andOTP AES passphrase:')
    else:
        pw = sys.stdin.readline()
    return pw.strip().encode('UTF-8')


def find_entries(data, pattern, limit=None):
    result = []

    for entry in data:
        label = entry['label']
        # NOTE: issuer was not always part of the JSON structure
        issuer = entry.get('issuer', '')
        tags = "".join(entry.get('tags', []))
        key = label + issuer + tags
        if pattern.lower() in key.lower():
            result.append(entry)
            if limit and len(result) == limit:
                break

    return result


def descriptor(entry):
    label = entry.get('label')
    issuer = entry.get('issuer')
    if label and issuer:
        return f'{label}[{issuer}]'
    elif label:
        return label
    elif issuer:
        return f'[{issuer}]'
    else:
        return 'no label or issuer found'


def issuer_and_label(entry):
    issuer = entry.get('issuer')
    label = entry.get('label')
    # NOTE: before the issuer field existed, andOTP stored "issuer - label" in the label
    if not issuer and label and " - " in label:
        issuer, label = label.split(" - ", 1)
    return issuer or '', label or ''


def otpauth_uri(entry):
    """Build an otpauth:// key URI (Google Authenticator key URI format) for an entry.

    Returns None for types that have no otpauth representation (e.g. STEAM)."""
    otp_type = entry['type'].lower()
    if otp_type not in ('totp', 'hotp'):
        return None
    issuer, label = issuer_and_label(entry)
    path = quote(label, safe='@')
    if issuer:
        path = quote(issuer, safe='@') + ':' + path
    params = {'secret': entry['secret']}
    if issuer:
        params['issuer'] = issuer
    params['algorithm'] = entry.get('algorithm', 'SHA1')
    params['digits'] = entry.get('digits', 6)
    if otp_type == 'totp':
        params['period'] = entry.get('period', 30)
    else:
        params['counter'] = entry.get('counter', 0)
    return f'otpauth://{otp_type}/{path}?{urlencode(params, quote_via=quote)}'


def pass_name_component(text):
    # '/' would create extra directory levels, control characters would break the line format
    text = re.sub(r'[/\x00-\x1f\x7f]', '_', text).strip()
    # pass refuses '..' path components; also avoid hidden files
    return text.lstrip('.')


def pass_name(entry):
    issuer, label = issuer_and_label(entry)
    parts = [p for p in (pass_name_component(issuer), pass_name_component(label)) if p]
    return '/'.join(parts) or 'unnamed'


def format_pass(entries):
    """One "NAME<TAB>URI" line per entry, NAME being a unique pass/gopass entry name."""
    lines = []
    used = set()
    for entry in entries:
        uri = otpauth_uri(entry)
        if uri is None:
            print("Skipping %s: unsupported OTP type %s" % (descriptor(entry), entry['type']),
                  file=sys.stderr)
            continue
        base = name = pass_name(entry)
        counter = 1
        while name in used:
            counter += 1
            name = f'{base}_{counter}'
        used.add(name)
        lines.append(f'{name}\t{uri}')
    return '\n'.join(lines)


def main():
    arguments = docopt(__doc__, version='andotp-decrypt 0.1')
    input_file = arguments['INPUT_FILE']
    debug = arguments['--debug']
    old_encryption = arguments['--old']
    output_format = arguments['--format']
    if output_format not in ('json', 'pass'):
        print("Unknown output format: %s" % output_format)
        sys.exit(1)
    if not os.path.exists(input_file):
        print("Could not find input file: %s" % input_file)
        return None
    password = get_password()
    if old_encryption:
        text = decrypt_aes(password, input_file, debug)
    else:
        text = decrypt_aes_new_format(password, input_file, debug)
    if output_format == 'json':
        print(text)
        return
    if not text:
        sys.exit(1)
    print(format_pass(json.loads(text)))


if __name__ == '__main__':
    main()
