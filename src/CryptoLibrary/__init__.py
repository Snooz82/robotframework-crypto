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

__version__ = '0.1.0'


class CryptoLibrary(object):
    """|
|

===================================================
robotframework-crypto
===================================================

CryptoLibrary is a library for secure password handling.
`project page <https://github.com/Snooz82/robotframework-datadriver>`_

For more information about Robot Framework, see http://robotframework.org.

|

Installation
------------

If you already have Python >= 3.6 with pip installed, you can simply
run:

``pip install --upgrade robotframework-crypto``

or if you have Python 2 and 3 installed in parallel you may use

``pip3 install --upgrade robotframework-crypto``

If you have Python 2 ... i am very sorry! Please update!

|

How it works
------------

CryptoLibrary uses asymmetric crypto with elliptic curve cryptography to store confidential data securely.

With ``python -m CryptoLibrary`` you can generate a key pair (private and public key) for your test env.
You will get the public key after generating.

this public key can now be used to encrypt every data you do not want to be public.
Passwords, personal data, etc.

you can use ``python -m CryptoClient`` on you computer where you want to encrypt data.
Encrypted Data will look like this:

``tIdr5s65+ggfJZl46pJgljioCUePUdZLozgiwquznw+xSlmzT3dcvfrTL9wIdRwmNOJuONT7FBW5``

this encrypted data can now be decrypted with CryptoLibrary within RobotFramework.

CryptoLibrary need the private_key_store.json for this.
This is what is generated as key pair.
Private key can be imported in test env with ``python -m CryptoLibrary`` .

|

Suppressing encrypted Text from Logs
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

All Data that is decrypted by CryptoLibrary is replaced in the log by ``***``
This works always and can not be disabled.
No need to use special keywords for this.

|

Usage in Test
~~~~~~~~~~~~~

.. code :: robotframework

    *** Settings ***
    Resource    imports.resource
    Library     CryptoLibrary    ${decryption_password}    #private key which should be secret is also protected by a password

    *** Variables ***
    ${secret}=     KILL ALL HUMANS!!!
    ${enc_user}=   nkpEPOVKfOko3t04XxOupA+F/ANTEuR9aQuPaPeMBGBQenwYf6UNESEl9MWRKGuj60ZWd10=
    ${enc_pwd}=    TVpamLXCtrzRsl8UAgD0YuoY+lSJNV73+bTYhOP51zM1GQihgyCvSZ2CoGoKsUHLFjokyJLHxFzPEB4=

    *** Test Cases ***
    Valid Login
        Open Browser    ${BASE-URL}
        Suppress Logging                                  #disable Robot Framework logging
        ${var}=    set Variable   ${secret}
        Log    ${var}
        Suppress Logging    False                         #disable Robot Framework logging
        Decrypt Text To Variable    user    ${enc_user}   #puts the decrypted pain text into ${user}
        ${var2}=    set Variable    ${user}
        log    ${var2}
        Input Text      id:input_username    ${user}
        ${password}=    Get Decrypted Text    ${enc_pwd}  #decrypts cipher text and returns plain text
        Input Password    id:input_password    ${password}
        Click Button    id:button_login
        Page Should Contain Element    //a[text()='Logout']
        Location Should Be    ${BASE-URL}list
        [Teardown]   Close Browser

in this case the decryption password for the private key.
It can also be saved on test env persistently as a hash.


THIS IS JUST AN ALPHA VERSION !!11!!1
-------------------------------------
    """

    ROBOT_LIBRARY_DOC_FORMAT = 'reST'
    ROBOT_LIBRARY_SCOPE = 'GLOBAL'
    ROBOT_LIBRARY_VERSION = __version__
    ROBOT_LISTENER_API_VERSION = 3

    def __init__(self, password=None, variable_decryption=False):
        """Password for private key can be given as argument."""
        self.ROBOT_LIBRARY_LISTENER = self
        self.value_list = list()
        self.crypto = CryptoUtility()
        self.original_log_level = 'INFO'
        self.disable_logging = False
        if password:
            self.crypto.password = password
        self.variable_decryption = variable_decryption
        self.builtin = BuiltIn()

    def decrypt_text_to_variable(self, variable_name, cipher_text):
        """Decrypts cipher_text and stores the decrypted plain text into a scalar variable.
        Variable would be i.e. ${variable_name}"""
        logger.info(f'Decrypting text into variable ${{{variable_name}}}')
        plaintext = self.crypto.decrypt_text(cipher_text)
        self.value_list.append(plaintext)
        name = self.builtin._get_var_name(f'${{{variable_name}}}')
        value = self.builtin._get_var_value(name, [plaintext])
        self.builtin._variables.set_test(name, value)

    def get_decrypted_text(self, cipher_text):
        """Decrypts cipher text and returns the plain text."""
        logger.info(f'Decrypting text and return value.')
        plaintext = self.crypto.decrypt_text(cipher_text)
        self.value_list.append(plaintext)
        return plaintext

    def suppress_logging(self, disable: bool = True):
        """Disables the logging of robot framework until ``Suppress Logging    False`` has been called."""
        if disable:
            logger.info('disable logging...')
            self.original_log_level = self.builtin.set_log_level('NONE')
        else:
            self.builtin.set_log_level(self.original_log_level)
            logger.info('enable logging...')
            logger.debug(f'Switching Loglevel from NONE to {self.original_log_level}.')

    def _start_test(self, test, result):
        self._decrypt_variable_in_scope(self.builtin.set_test_variable)
        pass

    def _decrypt_variable_in_scope(self, set_scope_variable):
        if self.variable_decryption:
            variables = self.builtin.get_variables()
            for var in variables:
                value = self.builtin.get_variable_value(var)
                if isinstance(value, str) and re.fullmatch(self.crypto.CIPHER_PATTERN, value):
                    plain = self.get_decrypted_text(value)
                    set_scope_variable(var, plain)

    def _log_message(self, message):
        if self.value_list:
            pattern = re.compile("|".join(self.value_list))
            message.message = pattern.sub('***', message.message)
