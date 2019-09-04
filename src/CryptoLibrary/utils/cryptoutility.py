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

import os
#import nacl.hash
#import nacl.secret
from nacl import pwhash, secret, utils, secret, hash
import json
from nacl.encoding import Base64Encoder, RawEncoder
from nacl.public import PrivateKey, PublicKey, SealedBox


class CryptoUtility(object):

    def __init__(self, key_path=None, password=None):
        self.private_key = None
        self.public_key = None
        self.ops = pwhash.argon2id.OPSLIMIT_MODERATE
        self.mem = pwhash.argon2id.MEMLIMIT_MODERATE
        self.salt = None
        self.private_key_file = None
        self.public_key_file = None
        self.private_hash_file = None
        self._sym_key = None
        self._key_path = None
        if not key_path:
            path, file = os.path.split(os.path.abspath(__file__))
            self.key_path = os.path.join(path, '../keys/')
        pass

    @property
    def sym_key(self):
        if not self._sym_key:
            try:
                self._import_sym_key_from_file(True)
                return self._sym_key
            except ValueError:
                pass
        else:
            return self._sym_key

    @sym_key.setter
    def sym_key(self, sym_key):
        self._sym_key = sym_key

    @property
    def key_path(self):
        if not os.path.isdir(self._key_path):
            raise ValueError(f'key_path: "{self.key_path}" is not a valid directory!')
        elif not os.access(self._key_path, os.W_OK | os.X_OK):
            raise PermissionError(f'Permission Denied.'
                                  f'key_path: "{self.key_path}" is not writeable or not executable.')
        else:
            return self._key_path

    @key_path.setter
    def key_path(self, key_path):
        if not os.path.isdir(key_path):
            raise ValueError(f'"{key_path}" is not a valid directory!')
        elif not os.access(key_path, os.W_OK | os.X_OK):
            raise PermissionError(f'Permission Denied.'
                                  f'"{key_path}" is not writeable or not executable.')
        else:
            self._key_path = key_path
            self.private_key_file = os.path.join(self.key_path, 'private_key.key')
            self.public_key_file = os.path.join(self.key_path, 'public_key.key')
            self.private_hash_file = os.path.join(self.key_path, 'private_key.hash')

    @property
    def password(self):
        return ''

    @password.setter
    def password(self, password: str):
        if password and password != '':
            hasher = hash.sha256
            self.sym_key = hasher(str.encode(password), RawEncoder)

    def generate_key_pair(self):
        self.private_key = PrivateKey.generate()
        self.public_key = self.private_key.public_key

    def _write_bytes_as_b64_to_file(self, byte_sequence, file_path):
        b64bytes = Base64Encoder.encode(byte_sequence).decode('ASCII')
        with open(file_path, 'w') as key_file:
            key_file.write(b64bytes)

    def _write_dict_as_json_to_file(self, dictionary, filepath):
        with open(filepath, 'w') as json_file:
            json.dump(dictionary, json_file)

    def _read_bytes_as_b64_from_file(self, file_path, silent=False):
        try:
            with open(file_path, 'r') as read_file:
                return Base64Encoder.decode(read_file.read())
        except Exception as e:
            if not silent:
                print(f'Opening file: {file_path}')
                print(e.args[1])

    def export_sym_key_to_file(self):
        if not self.sym_key:
            raise ValueError('No symmetric key found. Password must be set ahead!')
        elif not self.key_path:
            raise ValueError('No valid path found.')
        else:
            self._write_bytes_as_b64_to_file(self.sym_key, self.private_hash_file)

    def _import_sym_key_from_file(self, silent=False):
        if not self.key_path:
            raise ValueError('No valid path found.')
        else:
            self.sym_key = self._read_bytes_as_b64_from_file(self.private_hash_file, silent)
            return True

    def export_public_key_to_file(self):
        if not self.public_key:
            raise ValueError('No public key found to export. Generate or set public key first!')
        else:
            self._write_bytes_as_b64_to_file(self.public_key._public_key, self.public_key_file)

    def import_public_key_from_file(self):
        self.public_key = PublicKey(self._read_bytes_as_b64_from_file(self.public_key_file))

    def export_private_key_to_file(self):
        if not self.private_key:
            raise AttributeError('No private key found to export. Generate or set private key first!')
        else:
            self._write_bytes_as_b64_to_file(self._encrypt_private_key(), self.private_key_file)

    def import_private_key_from_file(self):
        self._decrypt_and_set_private_key(self._read_bytes_as_b64_from_file(self.private_key_file))

    def _encrypt_private_key(self):
        box = self._create_secret_box()
        return box.encrypt(self.private_key._private_key)

    def _decrypt_and_set_private_key(self, encrypted):
        box = self._create_secret_box()
        self.private_key = PrivateKey(box.decrypt(encrypted))

    def _create_secret_box(self):
        if not self.sym_key:
            self._import_sym_key_from_file()
        if not self.sym_key:
            raise ValueError('No symmetric key found. Password must be set ahead!')
        else:
            return secret.SecretBox(self.sym_key)

    def encrypt_text(self, text: str):
        if not self.public_key:
            self.import_public_key_from_file()
        if not self.public_key:
            raise AttributeError('No public key known. Import public key first!')
        else:
            sealed_box = SealedBox(self.public_key)
            cipher_byte = sealed_box.encrypt(str.encode(text))
            return Base64Encoder.encode(cipher_byte).decode('ASCII')

    def decrypt_text(self, cipher_text):
        if not self.private_key:
            self.import_private_key_from_file()
        if not self.private_key:
            raise AttributeError('No private key known or found in file. Generate private key first!')
        else:
            unseal_box = SealedBox(self.private_key)
            return unseal_box.decrypt(Base64Encoder.decode(cipher_text)).decode('utf-8')

