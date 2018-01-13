from setuptools import setup
setup(
  name = 'OpenCA',
  packages = ['OpenCA'], # this must be the same as the name above
  version = '0.1.0',
  description = 'A library to easily manage Certification Authorities based on OpenSSL',
  license='MIT',
  author = 'Ashish Shukla',
  author_email = 'ash2shukla@gmail.com',
  url = 'https://github.com/ash2shukla/OpenCA',
  keywords = ['CA','pyOpenSSL','OpenSSL'],
  classifiers = [],
  install_requires=[
         'sqlalchemy',
		 'pyOpenSSL',
		 'cryptography'
          ]
)
