import os
from setuptools import setup


def read(fname):
    with open(os.path.join(os.path.dirname(__file__), fname), "rb")as fin:
        return fin.read()

setup(
    name="mast.datapower.deployment",
    version="2.3.4",
    author="Clifford Bressette",
    author_email="cliffordbressette@mcindi.com",
    description=("A utility to help manage deployments for IBM DataPower"),
    license="GPLv3",
    keywords="DataPower deployment migration",
    url="http://github.com/mcindi/mast.datapower.deployment",
    namespace_packages=["mast", "mast.datapower"],
    packages=['mast', 'mast.datapower', 'mast.datapower.deployment'],
    entry_points={
        'mast_web_plugin': [
            'deployment=mast.datapower.deployment:WebPlugin'
        ]
    },
    package_data={
        "mast.datapower.deployment": ["docroot/*"]
    },
    long_description=read('README.md'),
    classifiers=[
        "Development Status :: 5 - Production/Stable",
        "Topic :: Utilities",
        "License :: OSI Approved :: GPLv3",
    ],
)
