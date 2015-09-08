# -*- coding: utf-8 -*-
from setuptools import setup, find_packages
import versioneer

setup(
    name='radula',
    version=versioneer.get_version(),
    cmdclass=versioneer.get_cmdclass(),
    packages=find_packages(),
    description='RadosGW client for Ceph S3 storage',
    author='bibby',
    author_email='andrew.bibby@nantomics.com',
    url='https://github.com/bibby/radula',
    include_package_data=False,
    install_requires=['boto', 'filechunkio'],
    entry_points={'console_scripts': ['radula = radula:main']},
    keywords='ceph radosgw s3',
    classifiers=[
        'Development Status :: 5 - Production/Stable',
        'Programming Language :: Python :: 2.7',
        'Environment :: Console',
        'Intended Audience :: Science/Research',
        'License :: OSI Approved :: MIT License',
        'Topic :: System :: Filesystems',
        'Operating System :: POSIX :: Linux',
    ]
)
