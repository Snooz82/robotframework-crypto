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

__version__ = '0.0.1'


class CryptoLibrary(object):

    ROBOT_LIBRARY_SCOPE = 'GLOBAL'
    ROBOT_LIBRARY_VERSION = __version__

    def __init__(self, password=None):
        self.crypto = CryptoUtility()
        if password:
            self.crypto.password = password

    def decrypt_text(self, variable_name, cipher_text):
        text = self.crypto.decrypt_text(cipher_text)
        name = BuiltIn()._get_var_name(f'${{{variable_name}}}')
        value = BuiltIn()._get_var_value(name, [text])
        BuiltIn()._variables.set_test(name, value)
