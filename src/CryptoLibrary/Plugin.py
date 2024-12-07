import re

from robot.libraries.BuiltIn import BuiltIn
from robot.utils.robottypes import is_truthy
from SeleniumLibrary.base import LibraryComponent, keyword

from CryptoLibrary.utils import CryptoUtility


class Plugin(LibraryComponent):
    def __init__(self, ctx):
        self.crypto = CryptoUtility()
        LibraryComponent.__init__(self, ctx)

    @keyword
    def input_password(self, locator, password, clear=True):
        """Types the given password into the text field identified by ``locator``.

        The `password` argument may be encrypted with CryptoLibrary.
        Then this Keyword decrypts it automatically.
        Be aware that the crypt: prefix is needed for automatic decryption.

        See the `Locating elements` section for details about the locator
        syntax. See `Input Text` for ``clear`` argument details.

        Difference compared to `Input Text` is that this keyword does not
        log the given password on the INFO level. Notice that if you use
        the keyword like

        | Input Password | password_field | password |

        the password is shown as a normal keyword argument. A way to avoid
        that is using variables like

        | Input Password | password_field | ${PASSWORD} |

        Please notice that Robot Framework logs all arguments using
        the TRACE level and tests must not be executed using level below
        DEBUG if the password should not be logged in any format.

        The `clear` argument is new in SeleniumLibrary 4.0. Hiding password
        logging from Selenium logs is new in SeleniumLibrary 4.2.
        """
        self.info(f"Typing password into text field '{locator}'.")
        if isinstance(password, str) and re.fullmatch(self.crypto.CIPHER_PATTERN, password):
            plaintext = self.crypto.decrypt_text(password)
        else:
            plaintext = password
        self._input_text_into_text_field(locator, plaintext, clear)

    def _input_text_into_text_field(self, locator, text, clear=True):
        element = self.find_element(locator)
        if is_truthy(clear):
            element.clear()
        previous_level = BuiltIn().set_log_level('NONE')
        try:
            element.send_keys(text)
        finally:
            BuiltIn().set_log_level(previous_level)
