#!/usr/bin/env python

from setuptools import find_packages, setup


def version():
    with open('octodns_fastly/__init__.py') as fh:
        for line in fh:
            if line.startswith('__version__'):
                return line.split("'")[1]
    raise Exception('failed to determine version number')


def descriptions():
    with open('README.md') as fh:
        ret = fh.read()
        first = ret.split('\n', 1)[0].replace('#', '')
        return first, ret


description, long_description = descriptions()

tests_require = ('pytest', 'pytest-cov', 'pytest-network')

setup(
    author='Ross McFarland',
    author_email='rwmcfa1@gmail.com',
    description=description,
    extras_require={
        'dev': tests_require
        + (
            'black>=23.1.0,<24.0.0',
            'build>=0.7.0',
            'isort>=5.11.5',
            'pyflakes>=2.2.0',
            'readme_renderer[md]>=26.0',
            'twine>=3.4.2',
        ),
        'test': tests_require,
    },
    install_requires=('octodns>=1.0.0', 'requests>=2.31.0'),
    license='MIT',
    long_description=long_description,
    long_description_content_type='text/markdown',
    name='octodns-fastly',
    packages=find_packages(),
    python_requires='>=3.6',
    tests_require=tests_require,
    url='https://github.com/octodns/octodns-fastly',
    version=version(),
)
