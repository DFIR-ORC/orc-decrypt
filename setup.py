import os
import subprocess
import sys
from pathlib import Path

from setuptools import find_packages
from setuptools import setup
from setuptools.command.install import install

here = Path(__file__).parent.resolve()


class MyInstall(install):
    def run(self):
        old_dir = Path.cwd()
        os.chdir("build")
        if subprocess.call(["cmake", ".."]) != 0:
            sys.exit(-1)
        if subprocess.call(["cmake", "--build", "."]) != 0:
            sys.exit(-1)
        # Try to install but ignore errors if permission is denied
        subprocess.call(["cmake", "--install", "."])
        os.chdir(old_dir)
        install.run(self)


setup(
    name="anssi-orcdecrypt",
    version="4.1",
    url="https://github.com/DFIR-ORC/orc-decrypt",
    license="LGPL-2.1+",
    author="Sebastien Chapiron",
    author_email="sebastien.chapiron@ssi.gouv.fr",
    description="Tool for decrypting DFIR-ORC archives",
    long_description=(here / "README.md").read_text(encoding="utf-8"),
    long_description_content_type="text/markdown",
    install_requires=["cryptography>=0.6"],
    packages=find_packages(where="src"),
    package_dir={"": "src"},
    zip_safe=False,
    entry_points={
        "console_scripts": [
            "orc-decrypt=anssi_orcdecrypt.cli:main",
        ],
    },
    classifiers=[  # Optional
        "Development Status :: 5 - Stable",
        "License :: OSI Approved :: GNU Lesser General Public License v2 or later (LGPLv2+)"
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3 :: Only",
        "Operating System :: Unix",
    ],
    python_requires=">=3.8, <4",
    cmdclass={
        "install": MyInstall,
    },
)
