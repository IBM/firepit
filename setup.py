#!/usr/bin/env python

"""The setup script."""

from setuptools import setup, find_packages

with open('README.rst') as readme_file:
    readme = readme_file.read()

with open('HISTORY.rst') as history_file:
    history = history_file.read()

requirements = [
    'anytree',
    'python-dateutil',
    'ijson',
    'lark',
    'tabulate',
    'typer',
    'ujson'
]

setup_requirements = ['pytest-runner', 'wheel']

test_requirements = ['pytest>=3',]

extras_requirements = {
    'postgres': ['psycopg2-binary'],
    'async-postgres': ['asyncpg']
}

setup(
    author="IBM Security",
    author_email='pcoccoli@us.ibm.com',
    python_requires='>=3.8',
    classifiers=[
        'Development Status :: 4 - Beta',
        'Topic :: Security',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: Apache Software License',
        'Natural Language :: English',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.8',
        'Programming Language :: Python :: 3.9',
        'Programming Language :: Python :: 3.10',
        'Programming Language :: Python :: 3.11',
    ],
    description="Columnar storage for STIX 2.0 observations.",
    entry_points={
        'console_scripts': [
            'firepit=firepit.cli:app',
            'splint=firepit.splint:app',
        ],
    },
    install_requires=requirements,
    extras_require=extras_requirements,
    license="Apache Software License 2.0",
    long_description=readme + '\n\n' + history,
    include_package_data=True,
    keywords='stix stix-shifter sql python',
    name='firepit',
    packages=find_packages(include=['firepit', 'firepit.*']),
    setup_requires=setup_requirements,
    test_suite='tests',
    tests_require=test_requirements,
    url='https://github.com/opencybersecurityalliance/firepit',
    version='2.3.35',
    zip_safe=False,
)
