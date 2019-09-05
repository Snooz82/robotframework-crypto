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

from CryptoLibrary.utils import CryptoUtility
from robot.libraries.BuiltIn import BuiltIn
from robot.api import logger
import re


__version__ = '0.0.1'


class CryptoLibrary(object):

    ROBOT_LIBRARY_SCOPE = 'GLOBAL'
    ROBOT_LIBRARY_VERSION = __version__
    ROBOT_LISTENER_API_VERSION = 3

    def __init__(self, password=None):
        self.ROBOT_LIBRARY_LISTENER = self
        self.value_list = list()
        self.crypto = CryptoUtility()
        self.original_log_level = 'INFO'
        self.disable_logging = False
        if password:
            self.crypto.password = password

    def decrypt_text_to_variable(self, variable_name, cipher_text):
        logger.info(f'Decrypting text into variable ${{{variable_name}}}')
        plaintext = self.crypto.decrypt_text(cipher_text)
        self.value_list.append(plaintext)
        name = BuiltIn()._get_var_name(f'${{{variable_name}}}')
        value = BuiltIn()._get_var_value(name, [plaintext])
        BuiltIn()._variables.set_test(name, value)

    def get_decrypted_text(self, cipher_text):
        logger.info(f'Decrypting text and return value.')
        plaintext = self.crypto.decrypt_text(cipher_text)
        self.value_list.append(plaintext)
        return plaintext

    def suppress_logging(self, disable:bool):
        if disable:
            logger.info('disable logging...')
            self.original_log_level = BuiltIn().set_log_level('NONE')
        else:
            BuiltIn().set_log_level(self.original_log_level)
            logger.info('enable logging...')
            logger.debug(f'Switching Loglevel from NONE to {self.original_log_level}.')

    def _log_message(self, message):
        if self.value_list:
            pattern = re.compile("|".join(self.value_list))
            message.message: message.message = pattern.sub('***', message.message)
