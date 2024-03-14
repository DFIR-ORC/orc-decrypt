import os
import shutil
import subprocess
import sys
from pathlib import Path

from setuptools import find_packages
from setuptools import setup
from setuptools.command.build import build
from setuptools.command.install import install

here = Path(__file__).parent.resolve()
build_dir = here / "build"
build_type = "Release"


class MyBuild(build):
    def run(self):
        if subprocess.call(["cmake", "-S", ".", "-B", build_dir.resolve()]) != 0:
            sys.exit(-1)
        if (
            subprocess.call(
                ["cmake", "--build", build_dir.resolve(), "--config", build_type]
            )
            != 0
        ):
            sys.exit(-1)
        return super().run()


class MyInstall(install):
    def run(self):
        if "VIRTUAL_ENV" in os.environ and sys.platform == "win32":
            shutil.copy(
                build_dir / build_type / "unstream.exe",
                Path(os.environ["VIRTUAL_ENV"]) / "Scripts" / "unstream.exe",
            )
        return super().run()


setup(
    name="anssi-orcdecrypt",
    version="5.3.2",
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
    data_files=[
        (
            "bin",
            [
                (
                    str(build_dir / build_type / "unstream.exe")
                    if sys.platform == "win32"
                    else str(build_dir / "unstream")
                ),
            ],
        ),
    ],
    zip_safe=False,
    entry_points={
        "console_scripts": [
            "orc-decrypt=orcdecrypt.cli:entrypoint",
        ],
    },
    classifiers=[  # Optional
        "Development Status :: 5 - Stable",
        "License :: OSI Approved :: GNU Lesser General Public License v2 or later (LGPLv2+)"
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3 :: Only",
        "Operating System :: Unix",
    ],
    python_requires=">=3.8, <4",
    cmdclass={
        "build": MyBuild,
        "install": MyInstall,
    },
)
