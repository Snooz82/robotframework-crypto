# Copyright 2018-  René Rohner
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import json
import os
import re
from contextlib import suppress

from nacl import exceptions, hash, pwhash, secret, utils
from nacl.encoding import Base64Encoder, RawEncoder
from nacl.public import PrivateKey, PublicKey, SealedBox


class CryptoUtility:
    PRIVATE_KEY_FILE = 'private_key.json'
    PUBLIC_KEY_FILE = 'public_key.key'
    PASSWORD_HASH_FILE = 'password_hash.json'
    CIPHER_PATTERN = '^crypt:(.*)'

    def __init__(self, key_path=None, password=None):
        self.private_key = None
        self.public_key = None
        self.ops = pwhash.argon2id.OPSLIMIT_MODERATE
        self.mem = pwhash.argon2id.MEMLIMIT_MODERATE
        self.private_key_store = None
        self.public_key_file = None
        self.password_hash_file = None
        self.password = password
        self._password_hash = None
        self._key_path = None
        if not key_path:
            path, file = os.path.split(os.path.abspath(__file__))
            self.key_path = os.path.join(path, '../keys/')
        else:
            self.key_path = key_path

    @property
    def key_path(self):
        if not self._key_path or not os.path.isdir(self._key_path):
            raise ValueError(f'key_path: "{self._key_path}" is not a valid directory!')
        if not os.access(self._key_path, os.W_OK | os.X_OK):
            raise PermissionError(
                f'Permission Denied.'
                f'key_path: "{self._key_path}" is not writeable or not executable.'
            )
        return self._key_path

    @key_path.setter
    def key_path(self, key_path):
        if not os.path.isdir(key_path):
            try:
                os.mkdir(key_path)
            except OSError as e:
                print(e)
        if not os.path.isdir(key_path):
            raise ValueError(f'key_path: "{key_path}" is not a valid directory!')
        if not os.access(key_path, os.W_OK | os.X_OK):
            raise PermissionError(
                f'Permission Denied.' f'key_path: "{key_path}" is not writeable or not executable.'
            )
        self._key_path = key_path
        self.private_key_store = os.path.join(self.key_path, self.PRIVATE_KEY_FILE)
        self.public_key_file = os.path.join(self.key_path, self.PUBLIC_KEY_FILE)
        self.password_hash_file = os.path.join(self.key_path, self.PASSWORD_HASH_FILE)

    @property
    def password(self):
        if not self._password_hash:
            self._import_password_hash_from_file(True)
        return self._password_hash

    @password.setter
    def password(self, password: str):
        if password and password != '':
            self._password_hash = self._base64(hash.sha512(str.encode(password), RawEncoder))

    def generate_key_pair(self):
        self.private_key = PrivateKey.generate()
        self.public_key = self.private_key.public_key

    def set_private_key(self, private_key_json):
        return self._decrypt_and_set_private_key(json.loads(private_key_json))

    def _write_bytes_as_b64_to_file(self, byte_sequence, file_path):
        b64bytes = self._base64(byte_sequence)
        with open(file_path, 'w') as key_file:
            key_file.write(b64bytes)
            return os.path.abspath(file_path)

    def _write_dict_as_json_file(self, dictionary, file_path):
        with open(file_path, 'w') as json_file:
            json.dump(dictionary, json_file)
            return os.path.abspath(file_path)

    def _read_dict_from_json_file(self, file_path, silent=False):
        try:
            with open(file_path) as json_file:
                return json.load(json_file)
        except Exception as e:
            if not silent:
                print(f'Opening file: {file_path}')
                print(e.args[1])

    def _read_bytes_as_b64_from_file(self, file_path, silent=False):
        try:
            with open(file_path) as read_file:
                return Base64Encoder.decode(read_file.read())
        except Exception as e:
            if not silent:
                print(f'Opening file: {file_path}')
                print(e.args[1])

    def delete_password_hash_file(self):
        with suppress(FileNotFoundError):
            os.remove(self.password_hash_file)
            return True
        return False

    def delete_key_store(self):
        with suppress(FileNotFoundError):
            os.remove(self.private_key_store)
        self.delete_public_key_file()
        self.delete_password_hash_file()
        return True

    def delete_public_key_file(self):
        with suppress(FileNotFoundError):
            os.remove(self.public_key_file)
            return True
        return False

    def export_password_hash_to_file(self):
        if not self._password_hash:
            raise ValueError('No password hash found. Password must be set ahead!')
        if not self.key_path:
            raise ValueError('No valid path found.')
        return self._write_dict_as_json_file(
            {'password_hash': self.password}, self.password_hash_file
        )

    def _import_password_hash_from_file(self, silent=False):
        if not self.key_path:
            raise ValueError('No valid path found.')
        file_content = self._read_dict_from_json_file(self.password_hash_file, silent)
        if isinstance(file_content, dict):
            self._password_hash = file_content['password_hash']
            return True
        return False

    def export_public_key_to_file(self):
        if not self.public_key:
            raise ValueError('No public key found to export. Generate or set public key first!')
        return self._write_bytes_as_b64_to_file(self.public_key._public_key, self.public_key_file)

    def import_public_key_from_file(self):
        try:
            self.public_key = PublicKey(self._read_bytes_as_b64_from_file(self.public_key_file))
        except exceptions.TypeError as e:
            print(e)
        if self.public_key:
            return self._base64(self.public_key._public_key)
        return None

    def set_public_key(self, b64_public_key):
        self.public_key = PublicKey(Base64Encoder.decode(b64_public_key))

    def export_private_key_to_file(self):
        if not self.private_key:
            raise AttributeError(
                'No private key found to export. Generate or set private key first!'
            )
        salt = utils.random(pwhash.argon2i.SALTBYTES)
        secure_key = pwhash.argon2i.kdf(
            secret.SecretBox.KEY_SIZE,
            Base64Encoder.decode(self.password),
            salt,
            opslimit=self.ops,
            memlimit=self.mem,
        )
        private_key_store = {
            'private_key': self._encrypt_private_key(secure_key),
            'salt': self._base64(salt),
            'ops': self.ops,
            'mem': self.mem,
        }
        return self._write_dict_as_json_file(private_key_store, self.private_key_store)

    def import_private_key_from_file(self):
        private_key_store = self._read_dict_from_json_file(self.private_key_store)
        return self._decrypt_and_set_private_key(private_key_store)

    def _encrypt_private_key(self, secure_key):
        box = secret.SecretBox(secure_key)
        return self._base64(box.encrypt(self.private_key._private_key))

    def _decrypt_and_set_private_key(self, private_key_store):
        if not self.password:
            raise AttributeError('No password found! Password must be set ahead!')
        secure_key = pwhash.argon2i.kdf(
            secret.SecretBox.KEY_SIZE,
            Base64Encoder.decode(self.password),
            Base64Encoder.decode(private_key_store['salt']),
            opslimit=private_key_store['ops'],
            memlimit=private_key_store['mem'],
        )
        encrypted = Base64Encoder.decode(private_key_store['private_key'])
        box = secret.SecretBox(secure_key)
        try:
            self.private_key = PrivateKey(box.decrypt(encrypted))
            self.public_key = self.private_key.public_key
            return True
        except Exception as e:
            print(e)

    def encrypt_text(self, text: str):
        if not self.public_key:
            self.import_public_key_from_file()
        if not self.public_key:
            raise AttributeError('No public key known. Import public key first!')
        sealed_box = SealedBox(self.public_key)
        cipher_byte = sealed_box.encrypt(str.encode(text))
        return f'crypt:{self._base64(cipher_byte)}'

    def decrypt_text(self, cipher_text):
        if not self.private_key:
            self.import_private_key_from_file()
        if not self.private_key:
            raise AttributeError(
                'No private key known or found in file. Generate private key first!'
            )
        unseal_box = SealedBox(self.private_key)
        if re.fullmatch(self.CIPHER_PATTERN, cipher_text):
            cipher_text = re.search(self.CIPHER_PATTERN, cipher_text).group(1)
        return unseal_box.decrypt(Base64Encoder.decode(cipher_text)).decode('utf-8')

    def _base64(self, data: bytes):
        return Base64Encoder.encode(data).decode('ASCII')
