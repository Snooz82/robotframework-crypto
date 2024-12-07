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

import re

from robot.api import logger
from robot.libraries.BuiltIn import BuiltIn

from CryptoLibrary.__main__ import Encrypter
from CryptoLibrary.utils import CryptoUtility

__version__ = '0.4.2'


def main():
    Encrypter().main()


class CryptoLibrary:
    """
    ===================================================
    robotframework-crypto
    ===================================================

    CryptoLibrary is a library for secure password handling.
    `project page <https://github.com/Snooz82/robotframework-crypto>`_

    For more information about Robot Framework, see http://robotframework.org.

    `Keyword Documentation <https://snooz82.github.io/robotframework-crypto/CryptoLibrary.html>`_

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

    With the command ``CryptoLibrary`` in console/terminal you can generate a key pair
    (private and public key) for your test env.
    You will get the public key after generating.

    This public key can now be used to encrypt every data you do not want to be public.
    Passwords, personal data, etc.

    You can use the command``CryptoClient`` on you computer where you want to encrypt data.

    Encrypted Data will look like this:

    ``crypt:tIdr5s65+ggfJZl46pJgljioCUePUdZLozgiwquznw+xSlmzT3dcvfrTL9wIdRwmNOJuONT7FBW5``

    This encrypted data can now be decrypted with CryptoLibrary within Robot Framework.

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
        Library     CryptoLibrary    %{private_key_password}    variable_decryption=False
        #private key which should be secret, should also be protected by a password

        *** Variables ***
        ${secret}=     KILL ALL HUMANS!!!
        ${enc_user}=   crypt:nkpEPOVKfOko3t04XxOupA+F/ANTEuR9aQuPaPeMBGBQenwYf6UNESEl9MWRKGuj60ZWd10=
        ${enc_pwd}=    crypt:TVpamLXCtrzRsl8UAgD0YuoY+lSJNV73+bTYhOP51zM1GQihgyCvSZ2CoGoKsUHLFjokyJLHxFzPEB4=

        *** Test Cases ***
        Valid Login
            Open Browser    ${BASE-URL}
            Suppress Logging                                  #disable Robot Framework logging
            ${var}=    set Variable   ${secret}
            Log    ${var}
            Unsuppress Logging                                #enable Robot Framework logging
            ${user}=    Get Decrypted Text    ${enc_user}     #decrypts cipher text and returns plain text
            Input Text      id:input_username    ${user}
            ${password}=    Get Decrypted Text    ${enc_pwd}  #decrypts cipher text and returns plain text
            Input Password    id:input_password    ${password}
            Click Button    id:button_login
            Page Should Contain Element    //a[text()='Logout']
            [Teardown]   Close Browser

    in this case the decryption password for the private key.
    It can also be saved on test env persistently as a hash.

    The parameter **variable_decryption** in the Library call, if set to true it will automatically decode ALL passwords defined in the variables section
    and then ``"Get Decrypted Text"`` isn't needed.

    |

    Importing of CryptoLibrary
    ~~~~~~~~~~~~~~~~~~~~~~~~~~

    +--------------------------+----------------------------------------------------------------------------------------------------------------------------------------------------------+
    | **password:**            | Password for private key can be given as argument. This should be stored as secret! Use environment variables instead of hard coding it here.            |
    +--------------------------+----------------------------------------------------------------------------------------------------------------------------------------------------------+
    | **variable_decryption:** | If set to ``True`` all variables that are available on Test Suite or on Test Case start,                                                                 |
    |                          | that contain a encrypted text, will be decrypted automatically.                                                                                          |
    +--------------------------+----------------------------------------------------------------------------------------------------------------------------------------------------------+
    | **key_path:**            | A path that defines where the key pair is stored physically.                                                                                             |
    |                          | Path needs to be an absolute path or relative to ``cryptoutility.py``.                                                                                   |
    +--------------------------+----------------------------------------------------------------------------------------------------------------------------------------------------------+

    |

    Menu walkthrough
    ----------------

    |

    CryptoLibrary Command Line Tool
    ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

    This Command Line tool has to be used to create a key pair.
    It can also show the public key and encrypt or decrypt data.

    ``python -m CryptoLibrary``::

     ? What do you want to do?  (Use arrow keys)
       Encrypt
       Decrypt
       Open config --->  ? What do you want to do?  (Use arrow keys)
       Quit                 Configure key pair    ----------------------------------------------------------------------------------------->  ? What do you want to do?  (Use arrow keys)
                            Configure public key  --->  ? What do you want to do?  (Use arrow keys)                                             Generate key pair
                            Back                          Set public key from string  --->   ? Input public_key as Base64:  ThePublicKey        Set key path
                                                          Get public key from string  --->   Public Key: ThePublicKey                           Set key pair from string
                                                          Delete public key           --->   ? Do you really want to delete public key?         Delete key pair
                                                          Back                                                                                  Save private key password
                                                                                                                                                Delete saved password
                                                                                                                                                Back
     ? What do you want to do?  (Use arrow keys)
       Encrypt     ------------------------------------------------------------------->   ? Enter the password to encrypt  YourPassword
       Decrypt     -----> ? Input encrypted cipher text:  crypt:TheEncryptedPassword      Encrypted password: (use inlc. "crypt:")
       Open config        ? Enter the password to decrypt  **********
       Quit               Your password is: YourPassword                                  crypt:TheEncryptedPassword=

    To start using the CryptoLibrary, start ``python -m CryptoLibrary`` and choose ``Open config`` -> ``Configure key pair``-> ``Generate key pair``.

    This generates the private and public keys in the ``private_key.json`` and ``public_key.key`` files.
    The ``private_key.json`` is needed to decrypt the values on your test server and has to be copied manually or added through the CLI interface.
    See ``Set key pair from...`` above.

    Next you can encrypt the values needed on your test server, looking something like ``crypt:nkpEPOVKfOko3t04XxOupA+F/ANTEuR9aQuPaPeMBGBQenwYf6UNESEl9MWRKGuj60ZWd10=``

    There are two options to decrypt your values in the robot file. When CryptoLibrary is loaded with ``variable_decryption=True``,
    ALL variables defined in that section, will automatically get decrypted.
    When the option is turned off (the default) the keyword ``Get Decrypted Text`` explicitly decrypts specific values.

    |

    CryptoClient Command Line Tool
    ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

    This CryptoClient command line tool is the tool for all test designers that want to encrypt data.
    I can only import and show the public key and encrypt data.

    ``python -m CryptoClient``::

     ? What do you want to do?  (Use arrow keys)
       Encrypt     --------------------------------------------------------------------------------------->   ? Enter the password to encrypt  YourPassword
       Open config -----> ? What do you want to do?  (Use arrow keys)                                           Encrypted password: (use inlc. "crypt:")
       Quit                 Set public key from string  --->   ? Input public_key as Base64:  ThePublicKey
                            Get public key from string  --->   Public Key: ThePublicKey                         crypt:TheEncryptedPassword
                            Delete public key           --->   ? Do you really want to delete public key?
                            Back

    |

    SeleniumLibrary Plugin
    ----------------------

    CryptoLibrary.Plugin is a SeleniumLibrary Plugin.
    When taken into usage, the ``Input Password`` Keyword can now handle decrypted cipher texts as well.

    Example:

    .. code :: robotframework

        *** Settings ***
        Library    SeleniumLibrary    plugins=CryptoLibrary.Plugin


        *** Variables ***
        ${Admins-Password}=    crypt:fQ5Iqn/j2lN8rXwimyz0JXlYzD0gTsPRwb0YJ3YSvDchkvDpfwYDmhHxsZ2i7bIQDlsWKJVhBb+Dz4w=


        *** Test Cases ***
        Decrypt as Plugin
            Open Browser      http://www.keyword-driven.de
            Input Text        input_username    admin
            Input Password    input_password    ${Admins-Password}

    |


    It may happen that keywords changes.
    i try not to do, but it can happen in major releases.
    Feel free to make a pull Request to improve docs or write some tests for it.

    """

    ROBOT_LIBRARY_DOC_FORMAT = 'reST'
    ROBOT_LIBRARY_SCOPE = 'GLOBAL'
    ROBOT_LIBRARY_VERSION = __version__
    ROBOT_LISTENER_API_VERSION = 3

    def __init__(self, password=None, variable_decryption=False, key_path=None):
        """
        +--------------------------+----------------------------------------------------------------------------------------------------------------------------------------------------------+
        | **password:**            | Password for private key can be given as argument. This should be stored as secret! Use environment variables instead of hard coding it here.            |
        +--------------------------+----------------------------------------------------------------------------------------------------------------------------------------------------------+
        | **variable_decryption:** | If set to ``True`` all variables that are available on Test Suite or on Test Case start,                                                                 |
        |                          | that contain a encrypted text, will be decrypted automatically.                                                                                          |
        +--------------------------+----------------------------------------------------------------------------------------------------------------------------------------------------------+
        | **key_path:**            | A path that defines where the key pair is stored physically.                                                                                             |
        |                          | Path needs to be an absolute path or relative to ``cryptoutility.py``.                                                                                   |
        +--------------------------+----------------------------------------------------------------------------------------------------------------------------------------------------------+
        """
        self.ROBOT_LIBRARY_LISTENER = self
        self.value_list = []
        self.crypto = CryptoUtility(key_path)
        self.original_log_level = 'INFO'
        self.disable_logging = False
        if password:
            self.crypto.password = password
        self.variable_decryption = variable_decryption
        self.builtin = BuiltIn()

    @property
    def secret_pattern(self):
        return re.compile('|'.join([re.escape(x) for x in self.value_list]))

    def conceal_text_in_logs(self, text):
        """This keyword conceals the password, passed as input, in the logs.
        Only ``***`` will be shown in the logs.

        Because CrytoLibrary is a global Library, this text will be hidden from the point
        where it is concealed until robot execution ends.
        Earlier appearances will be visible in the logs!"""
        logger.info('Conceal the text in the logs.')
        self.value_list.append(text)

    def get_decrypted_text(self, cipher_text: str) -> str:
        """Decrypts cipher text and returns the plain text.

        Example:

        .. code :: robotframework

            ${plain_text}=    Get Decrypted Text    crypt:sZ2i7bIQDlsWKJVhBb+Dz4w=

        """
        logger.info('Decrypting text and return value.')
        plaintext = self.crypto.decrypt_text(cipher_text)
        self.value_list.append(plaintext)
        return plaintext

    def suppress_logging(self, disable: bool = True):
        """Disables the logging of robot framework until ``Unsuppress Logging`` has been called."""
        if disable:
            logger.info('disable logging...')
            self.original_log_level = self.builtin.set_log_level('NONE')
        else:
            self.builtin.set_log_level(self.original_log_level)
            logger.info('enable logging...')
            logger.debug(f'Switching Loglevel from NONE to {self.original_log_level}.')

    def unsuppress_logging(self):
        """Enables the logging of robot framework and set it back to the original log level."""
        self.suppress_logging(False)

    def _start_test(self, test, result):
        self._decrypt_variable_in_scope(self.builtin.set_test_variable)

    def _start_suite(self, suite, result):
        self._decrypt_variable_in_scope(self.builtin.set_suite_variable)

    def _start_for_iteration(self, data, result):
        for variable in result.assign:
            if self._find_secret(self.builtin.get_variable_value(variable)):
                result.assign[variable] = '***'

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
            assignment_match = re.fullmatch(
                r'(?P<var>[\$@&]\{[^\}]*\})\s*=\s*(?P<value>.*)', message.message
            )
            if assignment_match:
                variable_value = self.builtin.get_variable_value(assignment_match.group('var'))
                if self._find_secret(variable_value):
                    message.message = f'{assignment_match.group("var")} = "***"'
                    return
            message.message = self.secret_pattern.sub('***', message.message)

    def _find_secret(self, value):
        if not self.value_list:
            return None
        return bool(
            self.secret_pattern.search(repr(value)) or self.secret_pattern.search(str(value))
        )
