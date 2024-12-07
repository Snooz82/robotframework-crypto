import re
from os.path import abspath, dirname, join

from setuptools import find_packages, setup

CURDIR = dirname(abspath(__file__))

with open('README.rst', encoding='utf-8') as fh:
    long_description = fh.read()

with open(join(CURDIR, 'src', 'CryptoLibrary', '__init__.py'), encoding='utf-8') as f:
    VERSION = re.search("\n__version__ = '(.*)'", f.read()).group(1)

setup(
    name='robotframework-crypto',
    version=VERSION,
    author='René Rohner(Snooz82)',
    author_email='snooz@posteo.de',
    description='A library for secure password handling.',
    long_description_content_type='text/x-rst',
    long_description=long_description,
    url='https://github.com/Snooz82/robotframework-crypto',
    package_dir={'': 'src'},
    packages=find_packages('src'),
    classifiers=[
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.9',
        'Programming Language :: Python :: 3.10',
        'Programming Language :: Python :: 3.11',
        'Programming Language :: Python :: 3.12',
        'License :: OSI Approved :: Apache Software License',
        'Operating System :: OS Independent',
        'Topic :: Software Development :: Testing',
        'Topic :: Software Development :: Testing :: Acceptance',
        'Framework :: Robot Framework',
    ],
    install_requires=[
        'robotframework >= 6.0.0',
        'PyNaCl >= 1.5.0',
        'questionary>=2.0.1',
    ],
    python_requires='>=3.9',
    entry_points={
        'console_scripts': [
            'CryptoLibrary = CryptoLibrary:main',
            'CryptoClient = CryptoClient:main',
        ]
    },
)
