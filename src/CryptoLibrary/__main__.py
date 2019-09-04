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

from PyInquirer import style_from_dict, Token, prompt
from CryptoLibrary.utils import CryptoUtility

__version__ = '0.0.0'


class Encrypter(object):

    def __init__(self):
        self.style = style_from_dict({
            Token.QuestionMark: '#fac731 bold',
            Token.Answer: '#06c8ff bold',
            Token.Instruction: '',  # default
            Token.Separator: '#cc5454',
            Token.Selected: '#0abf5b',  # default
            Token.Pointer: '#673ab7 bold',
            Token.Question: '',
        })

    def main(self):



        method = [
            {
                'type': 'list',
                'name': 'method',
                'message': 'What do you want to do?',
                'choices': ['Encrypt', 'Decrypt', 'Create key pair'],
                'filter': lambda val: val.lower()
            }
        ]
        answer = prompt(method, style=self.style)

        print(answer['method'])

        if answer['method'] == 'encrypt':
            questions = [
                {
                    'type': 'password',
                    'message': 'Enter the password to encrypt',
                    'name': 'password'
                }
            ]
            crypto = CryptoUtility()
            crypto.import_public_key_from_file()

            answers = prompt(questions, style=self.style)
            print('encrypted password:')

            cipher_text = crypto.encrypt_text(answers['password'])
            print(cipher_text)
        elif answer['method'] == 'decrypt':
            questions = [
                {
                    'type': 'input',
                    'name': 'cipher_text',
                    'message': 'Input encrypted password:',
                }
            ]

            input_password = [
                {
                    'type': 'password',
                    'message': 'Enter the password to decrypt',
                    'name': 'password'
                }
            ]
            answers = prompt(questions, style=self.style)
            crypto = CryptoUtility()
            if not crypto.sym_key:
                input_pwd = prompt(input_password, style=self.style)
                crypto.password = input_pwd['password']
            crypto.import_private_key_from_file()
            password = crypto.decrypt_text(answers['cipher_text'])
            print(f'Your password is: {password}')
        else:
            questions = [
                {
                    'type': 'list',
                    'name': 'regenerate',
                    'message': 'Do you want to regenerate the key pair?',
                    'choices': ['Yes', 'No'],
                    'filter': lambda val: val.lower()
                }
            ]
            crypto = CryptoUtility()

            answers = prompt(questions, style=self.style)

            if answers['regenerate'] == 'yes':
                crypto.generate_key_pair()
                print('Generating key pair...')
                crypto.password = self.set_password()
                crypto.export_sym_key_to_file()
                crypto.export_private_key_to_file()
                crypto.export_public_key_to_file()
                print('Key pair successfully generated!')

    def set_password(self):
        questions = [
            {
                'type': 'password',
                'message': 'Enter the password to secure the private key.',
                'name': 'password1'
            },
            {
                'type': 'password',
                'message': 'Reenter the password to secure the private key.',
                'name': 'password2'
            }
        ]
        answers = prompt(questions, style=self.style)
        if answers['password1'] != answers['password2']:
            print('The entered passwords are not equal. Please retry:')
            password = self.set_password()
        else:
            password = answers['password1']
        return password


if __name__ == "__main__":
    Encrypter().main()
