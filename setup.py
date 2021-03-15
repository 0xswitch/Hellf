from setuptools import find_packages, setup

setup(name='Hellf',
      version='1.1',
      description='The aim of this project is to provide a python library for patching ELF binary file. It only supports for the moment x86 and x86_64 architecture.',
      url='https://github.com/0xswitch/Hellf',
      author='switch',
      author_email='switch@switch.re',
      license='WTFPL',
      python_requires='>=3',
      packages=find_packages(),
      zip_safe=False)
