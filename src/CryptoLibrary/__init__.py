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

__version__ = '0.0.0'


class CryptoLibrary(object):


    @staticmethod
    def main():
        crypto = CryptoUtility()
        crypto.generate_key_pair()
        crypto.password = 'fingolfin'
        crypto.export_sym_key_to_file()
        crypto.export_public_key_to_file()
        crypto.export_private_key_to_file()

    @staticmethod
    def enc():
        crypto = CryptoUtility()
        print(crypto.encrypt_text('Hallo'))

    @staticmethod
    def dec():
        crypto = CryptoUtility()
        print(crypto.decrypt_text('bjRv2SFS2cuTu+X3pczSlDeuxVL8K31tbLSTbr9pyjhCCDUUJlKgAsrklT9QnqAqmm6Oy8U='))
        print(crypto.decrypt_text('A0INoWBTVgMbOcvS/y5fMtJ7Mhfvb4dRxaKnA8hlUwdLWCrWQl/OSdRzN7d27pxN22Hnbgg='))


if __name__ == "__main__":
    # execute only if run as a script
    CryptoLibrary.dec()
    #CryptoLibrary.enc()
    #CryptoLibrary.main()
