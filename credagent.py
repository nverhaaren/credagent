#!/usr/bin/env python
import argparse
import atexit
import base64
import getpass
import json
import os
import socket

from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


def contact_agent(sock, key):
    sock.sendall(key.encode('ascii') + b'\0')
    result = b''
    while True:
        msg = sock.recv(2048)
        result += msg
        if msg.endswith(b'\0'):
            break
    if result == b'\0':
        return None
    result = result[:-1].decode('ascii')
    return result


def main(command=None):
    # This uses a third party cryptography library as in its examples and OS permissions for security
    # Should be pretty secure way of storing credentials, but has not been professionally audited or anything
    # And of course anyone with root access on the machine could get the credentials out of the running agent
    # The 'right way' to do this probably involves a hardware security module or something.
    parser = argparse.ArgumentParser('Start credential agent')
    parser.add_argument('--credential_cache_path', required=True)
    parser.add_argument('--socket_address', required=True)
    args = parser.parse_args(command)

    with open(args.credential_cache_path) as f:
        credentials = json.load(f)

    available_credentials = {}
    credential_keys = {}
    while True:
        try:
            names = input('Names: ')
        except EOFError:
            print()
            break
        names = names.split(',')
        assert all(name in credentials for name in names)
        salts = {name: base64.urlsafe_b64decode(credentials[name]['salt']) for name in names}
        iterations = {name: credentials[name]['iterations'] for name in names}
        kdfs = {name: PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salts[name],
            iterations=iterations[name],
            backend=default_backend(),
        ) for name in names}
        password = getpass.getpass().encode('ascii')
        keys = {name: base64.urlsafe_b64encode(kdfs[name].derive(password)) for name in names}
        del password
        for name in names:
            decrypt = Fernet(keys[name])
            credential = decrypt.decrypt(credentials[name]['encrypted_token'].encode('ascii'))
            # This is a bit paranoid, but the idea is not to have the token in plaintext in memory in case it gets
            # paged out or something - of course all the information to retrieve the token has to be in memory, though
            key = Fernet.generate_key()
            encrypt = Fernet(key)
            credential_keys[name] = key
            available_credentials[name] = encrypt.encrypt(credential)
            del encrypt
            del decrypt
            del key
        del keys

    sock = socket.socket(socket.AF_UNIX)
    if os.path.exists(args.socket_address):
        os.remove(args.socket_address)
    sock.bind(args.socket_address)
    atexit.register(os.remove, args.socket_address)
    sock.listen(5)
    while True:
        connection, address = sock.accept()
        connection.settimeout(5)
        name = b''
        try:
            while True:
                msg = connection.recv(2048)
                name += msg
                if msg.endswith(b'\0'):
                    break
            name = name[:-1].decode('ascii')
        except (socket.timeout, UnicodeDecodeError):
            # Log something, todo
            connection.shutdown(socket.SHUT_RDWR)
            continue

        encrypted_value = available_credentials.get(name)
        if encrypted_value is None:
            try:
                connection.sendall(b'\0')
            except socket.timeout:
                connection.shutdown(socket.SHUT_RDWR)
                continue

        decrypt = Fernet(credential_keys[name])
        value = decrypt.decrypt(encrypted_value)

        response = value + b'\0'
        try:
            connection.sendall(response)
        except socket.timeout:
            pass
        connection.shutdown(socket.SHUT_RDWR)
        del value
        del response


if __name__ == '__main__':
    main()
