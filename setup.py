#!/usr/bin/env python
# -*- coding: utf-8 -*-
# pylint: disable=C0111,W6005,W6100

import os
import re

from setuptools import setup


def get_version(*file_paths):
    """
    Extract the version string from the file at the given relative path.
    """
    filename = os.path.join(os.path.dirname(__file__), *file_paths)
    version_file = open(filename).read()
    version_match = re.search(r"^__version__ = ['\"]([^'\"]*)['\"]",
                              version_file, re.M)
    if version_match:
        return version_match.group(1)
    raise RuntimeError('Unable to find version string.')


VERSION = get_version('jigsawlabs_backends', '__init__.py')

README = open(os.path.join(os.path.dirname(__file__), 'README.rst')).read()

setup(
    name='oauth-auth0',
    version=VERSION,
    description=('An OAuth backend for auth0, '
                 'mostly used for Open edX but can be used elsewhere.'),
    long_description=README,
    author='Lawrence McDaniel',
    author_email='lpm0073@gmail.com',
    url='https://github.com/jigsaw-labs/edx.oauth.git',
    packages=[
        'jigsawlabs_backends',
    ],
    include_package_data=True,
    zip_safe=False,
    keywords='OAuth Auth0',
    classifiers=[
        'Intended Audience :: Developers',
        'License :: OSI Approved :: MIT License',
    ],
)
