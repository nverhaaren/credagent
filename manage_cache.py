#!/usr/bin/env python
import argparse
import base64
import getpass
import json
import os
import sys

from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


def main(command=None):
    parser = argparse.ArgumentParser()
    parser.add_argument('--credential_cache_path', required=True)
    parser.add_argument('--operation', required=True, choices=['add', 'update', 'remove'])
    parser.add_argument('--name', required=True)
    parser.add_argument('--iterations', type=int, default=100_000)
    args = parser.parse_args(command)

    credential_cache_path = args.credential_cache_path
    operation = args.operation
    name = args.name
    iterations = args.iterations

    if not os.path.exists(credential_cache_path):
        existing = {}
    else:
        with open(credential_cache_path) as f:
            existing = json.load(f)

    if (operation == 'add' and name in existing) or (operation != 'add' and name not in existing):
        # logging
        raise RuntimeError()

    if operation == 'remove':
        del existing[args.name]
    else:
        salt = os.urandom(16)
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=iterations,
            backend=default_backend(),
        )
        password = getpass.getpass()
        key = base64.urlsafe_b64encode(kdf.derive(password.encode('ascii')))
        del password
        encrypt = Fernet(key)
        access_token = getpass.getpass(prompt='Token: ')
        encrypted_token = encrypt.encrypt(access_token.encode('ascii'))
        del access_token

        existing[name] = {
            'salt': base64.urlsafe_b64encode(salt).decode('ascii'),
            'iterations': iterations,
            'encrypted_token': encrypted_token.decode('ascii'),
        }

    tmp_path = credential_cache_path + '.tmp'
    with open(tmp_path, 'w') as f:
        json.dump(existing, f, indent=4)
    # Atomically overwrite to prevent data loss
    os.rename(tmp_path, credential_cache_path)


if __name__ == '__main__':
    sys.exit(main() or 0)