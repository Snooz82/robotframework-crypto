from CryptoLibrary import CryptoLibrary

with open('Readme.rst', 'w', encoding='utf-8') as readme:
    doc_string = CryptoLibrary.__doc__
    readme.write(str(doc_string).replace('\\', '\\\\').replace('\\\\*', '\\*'))
