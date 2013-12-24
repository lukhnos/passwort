from setuptools import setup

setup(
	name='passwort',
	version='1.0',
	author = 'Lukhnos Liu',
    author_email = 'lukhnos@lukhnos.org',
	license='MIT',
	packages=['passwort'],
	install_requires=[
		'pwgen >= 0.4',
		'pycrypto >= 2.6.1'
	],
	test_suite='passwort.tests',
	entry_points={
        'console_scripts': ['passwort = passwort:main']
    })
