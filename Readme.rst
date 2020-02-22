===================================================
robotframework-crypto
===================================================

CryptoLibrary is a library for secure password handling.
`project page <https://github.com/Snooz82/robotframework-crypto>`_

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

With ``python -m **CryptoLibrary**`` you can generate a key pair (private and public key) for your test env.
You will get the public key after generating.

this public key can now be used to encrypt every data you do not want to be public.
Passwords, personal data, etc.

you can use ``python -m **CryptoClient**`` on you computer where you want to encrypt data.
Encrypted Data will look like this:

``crypt:tIdr5s65+ggfJZl46pJgljioCUePUdZLozgiwquznw+xSlmzT3dcvfrTL9wIdRwmNOJuONT7FBW5``

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
    ${enc_user}=   crypt:nkpEPOVKfOko3t04XxOupA+F/ANTEuR9aQuPaPeMBGBQenwYf6UNESEl9MWRKGuj60ZWd10=
    ${enc_pwd}=    crypt:TVpamLXCtrzRsl8UAgD0YuoY+lSJNV73+bTYhOP51zM1GQihgyCvSZ2CoGoKsUHLFjokyJLHxFzPEB4=

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

THIS IS STILL AN ALPHA VERSION !!11!!1 ;-)
------------------------------------------

Feel free to make a pull Request to improve docs or write some tests for it.
