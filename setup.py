#!/usr/bin/env python3

import codecs
import os
import re
import shlex
from setuptools import setup, find_packages
from setuptools.command.install import install

HERE = os.path.abspath(os.path.dirname(__file__))

# Read the version number from a source file.
# Why read it, and not import?
# see https://groups.google.com/d/topic/pypa-dev/0PkjVpcxTzQ/discussion
def find_version(*file_paths):
    """TODO"""
    # Open in Latin-1 so that we avoid encoding errors.
    # Use codecs.open for Python 2 compatibility
    with codecs.open(os.path.join(HERE, *file_paths), 'r') as fde2:
        version_file = fde2.read()

    # The version line must have the form
    # __version__ = 'ver'
    version_match = re.search(r"^__version__ = ['\"]([^'\"]*)['\"]",
                              version_file, re.M)
    if version_match:
        return version_match.group(1)
    raise RuntimeError("Unable to find version string.")


# Get the long description from the relevant file
with codecs.open('README.rst', encoding='utf-8') as fde:
    LONG_DESCRIPTION = fde.read()



setup(
    name = 'linshare_core_tests',
    version = find_version('linshare_core_tests', '__init__.py'),
    description = 'a collection of lazy commands',
    long_description=LONG_DESCRIPTION,
    entry_points={
        'console_scripts': [
            'trello=linshare_core_tests.commands:PROG',
            'trello-config=linshare_core_tests.commands:generate_config',
        ],
    },

    # Author details
    author = 'Frederic MARTIN',
    author_email = 'fmartin@linagora.com',

    # Choose your license
    license = "AGPL3",

    classifiers=[
        # How mature is this project? Common values are
        #   3 - Alpha
        #   4 - Beta
        #   5 - Production/Stable
        'Development Status :: 4 - Beta',

        # Indicate who your project is intended for
        'Intended Audience :: Developers',
        'Topic :: Software Development :: Build Tools',
        'Environment :: Console',

        # Specify the Python versions you support here. In particular, ensure
        # that you indicate whether you support Python 2, Python 3 or both.
        'Programming Language :: Python :: 3',
    ],

    # What does your project relate to?
    keywords='linshare command line interface',

    # You can just specify the packages manually here if your project is
    # simple. Or you can use find_packages.
    packages=find_packages(exclude=["contrib", "docs", "tests*"]),

    # List run-time dependencies here.  These will be installed by pip when your
    # project is installed.
    install_requires=[
        'pytest',
        'flake8',
        'tox',
        'clint==0.5.1',
        'requests==2.25.1',
        'requests-toolbelt==0.9.1',
        'pylint'
    ],
)
