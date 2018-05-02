from setuptools import setup

setup(
    name='passwort',
    version='1.1',
    description='A simple password manager',
    author='Lukhnos Liu',
    author_email='lukhnos@lukhnos.org',
    url='https://github.com/lukhnos/passwort',
    license='MIT',
    packages=['passwort'],
    install_requires=[
        'pwgen >= 0.4',
        'pycryptodomex >=3.6.1',
        'six >=1.10.0',
    ],
    test_suite='passwort.tests',
    entry_points={
        'console_scripts': ['passwort = passwort:main']
    })
