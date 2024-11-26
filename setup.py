from setuptools import setup, find_packages

with open('requirements.txt') as f:
    requirements = f.read().splitlines()

setup(
    name='py_arp_spoof',
    version='0.1.2',
    packages=find_packages(),
    url='',
    license='',
    author='###',
    author_email='',
    description='A simple and efficient Python script for ARP spoofing on Linux.',
    install_requires=requirements,
    entry_points={
        'console_scripts': [
            'py_arp_spoof = src.main:main'
        ]
    }
)
