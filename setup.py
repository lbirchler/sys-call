import os

from setuptools import find_packages
from setuptools import setup


def read(rel_path: str) -> str:
  here = os.path.abspath(os.path.dirname(__file__))
  with open(os.path.join(here, rel_path)) as fp:
    return fp.read()


def get_version(rel_path: str) -> str:
  for line in read(rel_path).splitlines():
    if line.startswith('__version__'):
      delim = '"' if '"' in line else "'"
      return line.split(delim)[1]
  raise RuntimeError('Unable to find version string.')


long_description = read('README.md')

setup(
    name='sys-call',
    version=get_version('syscall/__init__.py'),
    description='Linux Syscall implementations, calling conventions, and shellcode examples.',
    long_description=long_description,
    long_description_content_type='text/markdown',
    packages=find_packages(include=['syscall', 'syscall.*']),
    author='Lawrence Birchler',
    author_email='bplyr@tutanota.com',
    url='http://github.com/lbirchler/sys-call/',
    install_requires=[
      'rich>13.4.0'
    ],
    classifiers=[
        'License :: OSI Approved :: MIT License',
        'Operating System :: OS Independent',
        'Programming Language :: Python',
    ],
    entry_points={
        'console_scripts': [
            'syscall-info=syscall.syscall:CLI.info',
            'syscall-shellcode=syscall.syscall:CLI.shellcode'
        ]
    }
)
