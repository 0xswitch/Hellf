from setuptools import setup

setup(
    name='Hellf',
    version='1.0',    
    description='A library for patching ELF binary file',
    url='https://github.com/0xswitch/Hellf',
    author='0xswitch',
    author_email='',
    license='',
    packages=['Hellf', 'Hellf/lib'],
    install_requires=['lib'],
    classifiers=[
        'Programming Language :: Python :: 3',
    ],
)
