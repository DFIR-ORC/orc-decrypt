#! /usr/bin/env python
# -*- coding:utf-8 -*-
#
# SPDX-License-Identifier: LGPL-2.1-or-later
#
# Copyright © 2011-2020 ANSSI. All Rights Reserved.
#
# Author(s): Ryad Benadjila (ANSSI), Sebastien Chapiron (ANSSI), Arnaud Ebalard (ANSSI)
#

import argparse
import logging
import multiprocessing
from datetime import datetime
from pathlib import Path
from shutil import which
from typing import Dict
from typing import List
from typing import Optional
from typing import Sequence

from cryptography.hazmat.primitives.serialization import load_pem_private_key

from .decrypt import decrypt_archive
from .utils import ContextFilter


def get_parser():
    def is_pkey(f: str) -> Path:
        try:
            load_pem_private_key(open(f, "rb").read(), password=None)
            return Path(f).resolve()
        except Exception as e:
            raise argparse.ArgumentTypeError(f'"{f}" is not a valid private key: {e}')

    def is_file(f):
        if Path(f).is_file():
            return Path(f).resolve()
        else:
            raise argparse.ArgumentTypeError(f'"{f}" is not a valid file')

    def is_path(p):
        if Path(p).exists():
            return Path(p).resolve()
        else:
            raise argparse.ArgumentTypeError(f'"{p}" does not exist')

    parser = argparse.ArgumentParser(
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
        add_help=True,
        description="Wrapper around the two possible methods of decrypting ORC archives",
    )
    parser.add_argument(
        "-k",
        "--key",
        metavar="file",
        type=is_pkey,
        help="PEM-encoded unencrypted key file",
        required=True,
    )
    parser.add_argument(
        "input",
        metavar="path",
        type=is_path,
        nargs="+",
        help="Input directories where the encrypted archives are stored or individual archives",
    )
    parser.add_argument(
        "--output-dir",
        metavar="dir",
        type=Path,
        default=Path.cwd(),
        help="Output directory where to store the decrypted archives. It will be created if it does "
        "not already exist. Defaults to the current working directory",
    )
    parser.add_argument(
        "--log-level",
        metavar="level",
        default="INFO",
        choices=["CRITICAL", "ERROR", "WARNING", "INFO", "DEBUG"],
        help="Print log messages of this level and higher, possible choices: %(choices)s",
    )
    parser.add_argument(
        "--log-file", metavar="file", help="Log file to store DEBUG level messages"
    )
    parser.add_argument(
        "-f",
        "--force",
        action="store_true",
        default=False,
        help="Force overwrite of existing files in output directory.",
    )
    parser.add_argument(
        "-j",
        "--jobs",
        metavar="N",
        type=int,
        help="Number of jobs to process in parallel. Defaults to Python implementation of multiprocessing.Pool",
    )
    parser.add_argument(
        "-m",
        "--method",
        metavar="method",
        type=str,
        choices=["auto", "openssl", "python"],
        default="auto",
        help="Method to use to decrypt archives. Default is 'auto' meaning the script will use "
        "openssl for archives smaller than 2GB and pure-python implementation for larger ones. "
        "Warning: forcing the usage of openssl for archives larger than 2GB will likely prevent "
        "the script from decrypting these archives as openssl cannot handle them in its current "
        "version (1.1.1f)",
    )
    parser.add_argument(
        "--unstream-path",
        metavar="file",
        type=is_file,
        help='Path to the "unstream" binary. If not set, unstream must be in the PATH.',
    )

    return parser


def setup_logging(
    log_file: Optional[str] = None,
    log_level: Optional[str] = None,
) -> None:
    """Do setup logging to redirect to log_file at DEBUG level."""
    if log_level is None:
        log_level = "INFO"
    # Setup logging
    if log_file:
        # Send everything (DEBUG included) in the log file
        # and keep only log_level messages on the console
        logging.basicConfig(
            level=logging.DEBUG,
            format="[%(asctime)s] %(levelname)-8s - %(name)s - %(ctx)s%(message)s",
            filename=log_file,
            filemode="w",
        )
        # define a Handler which writes messages of log_level
        # or higher to the sys.stderr
        console = logging.StreamHandler()
        console.setLevel(log_level)
        # set a format which is simpler for console use
        formatter = logging.Formatter(
            "[%(asctime)s] %(levelname)-8s - %(ctx)s%(message)s",
        )
        # tell the handler to use this format
        console.setFormatter(formatter)
        # add the handler to the root logger
        logging.root.addHandler(console)
    else:
        logging.basicConfig(
            level=log_level,
            format="[%(asctime)s] %(levelname)-8s - %(ctx)s%(message)s",
        )
    for h in logging.root.handlers:
        h.addFilter(ContextFilter())


def entrypoint(argv: Optional[Sequence[str]] = None) -> int:
    parser = get_parser()
    args = parser.parse_args(argv)
    setup_logging(args.log_file, args.log_level)
    begin = datetime.now()

    # unstream should be installed in the PATH or specified on the CLI with --unstream-path
    unstream_cmd = which("unstream")
    if args.unstream_path is None:
        if unstream_cmd is None:
            logging.critical(
                'Missing tool "unstream" in PATH, please provide the path to unstream binary with --unstream-path'
            )
            return -1
        else:
            unstream_cmd = Path(unstream_cmd)  # type: ignore[assignment]
    # args.unstream overrides unstream_cmd if it is a valid file
    else:
        unstream_cmd = args.unstream_path

    if which("openssl") is None:
        logging.warning(
            "OpenSSL binary was not found in your PATH, falling back to Python implementation."
        )
        args.method = "python"

    # Build the list of encrypted archives and the corresponding output path from the input paths given on the CLI.
    # Directories are recursively searched.
    output_dir = Path(args.output_dir)
    archives_list: List[Dict[str, Path]] = list()
    for path in args.input:
        if path.is_file():
            archives_list.append(
                {"input": path, "output": (output_dir / path.stem).resolve()}
            )
        elif path.is_dir():
            for subpath in path.rglob("*.p7b"):
                archives_list.append(
                    {
                        "input": subpath,
                        "output": (
                            output_dir / subpath.relative_to(path).parent / subpath.stem
                        ).resolve(),
                    }
                )
    if len(archives_list) == 0:
        logging.info(
            "No encrypted archives could be found in input path(s), nothing to do."
        )
        return 0
    logging.info(
        "Decrypting %d archives into %s using private key %s",
        len(archives_list),
        args.output_dir,
        args.key,
    )

    output_dir.mkdir(parents=True, exist_ok=True)
    with multiprocessing.Pool(args.jobs) as pool:
        results = pool.starmap(
            decrypt_archive,
            [
                (
                    a["input"],
                    Path(args.key),
                    a["output"],
                    unstream_cmd,
                    args.method,
                    args.force,
                )
                for a in archives_list
            ],
        )

    end = datetime.now()
    logging.info(
        "Finished processing %d archives in %s. %d failed, %d succeeded",
        len(archives_list),
        end - begin,
        results.count(False),
        results.count(True),
    )
    return 0
