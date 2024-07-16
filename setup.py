from setuptools import setup, find_packages

setup(
    name='lfimap',
    version='0.1.4',
    packages=find_packages(include=['lfimap', 'lfimap.*']),
    package_dir={
        'lfimap': 'lfimap',
    },
    package_data={
        'lfimap': ['src/**/*'],
    },
    include_package_data=True,
    install_requires=[
        'argparse',
        'bs4',
        'pybase64',
        'requests',
        'urllib3'
    ],
    entry_points={
        'console_scripts': [
            'lfimap = lfimap.lfimap:main',
        ],
    },
    author='@h4nsmach1ne',
    author_email='therealpowa@gmail.com',
    description='Local File Inclusion discovery and exploitation tool',
    long_description=open('README.md').read(),
    long_description_content_type='text/markdown',
    url='https://github.com/hansmach1ne/LFImap',
    license='Apache',
    classifiers=[
        'Programming Language :: Python :: 3',
        'License :: OSI Approved :: Apache Software License',
        'Operating System :: OS Independent',
    ],
)
