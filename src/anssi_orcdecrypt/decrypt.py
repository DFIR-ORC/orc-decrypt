#! /usr/bin/env python
# -*- coding:utf-8 -*-
#
# SPDX-License-Identifier: LGPL-2.1-or-later
#
# Copyright © 2011-2020 ANSSI. All Rights Reserved.
#
# Author(s): Ryad Benadjila (ANSSI), Sebastien Chapiron (ANSSI), Arnaud Ebalard (ANSSI)
#

import logging
import re
import struct
import subprocess  # nosec B404 - checked
from pathlib import Path
from shutil import which

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers import Cipher
from cryptography.hazmat.primitives.ciphers import algorithms
from cryptography.hazmat.primitives.ciphers import modes
from cryptography.hazmat.primitives.hashes import HashAlgorithm
from cryptography.hazmat.primitives.serialization import load_pem_private_key

from anssi_orcdecrypt.utils import ContextFilter
from anssi_orcdecrypt.utils import decode_oid

rsa_oaep_oid = re.compile(re.escape(bytes.fromhex("06092a864886f70d010107")))
rsa_encryption_oid = re.compile(re.escape(bytes.fromhex("06092a864886f70d0101010500")))
pkcs7_data_oid = bytes.fromhex("06092a864886f70d010701")


def decrypt_archive(
    archive_path: Path,
    private_key: Path,
    output_file: Path,
    unstream_cmd: Path,
    method: str = "auto",
    force: bool = False,
) -> bool:
    logging.getLogger("").addFilter(ContextFilter(archive_path.name))
    logging.debug("Processing archive %s", archive_path)

    if output_file.exists() and not force:
        logging.error(
            "Output file %s already exists, skipping (use --force to overwrite)",
            output_file,
        )
        return False

    if archive_path.stat().st_size >= 2**32 / 2 - 1:
        if method == "auto" or method == "python":
            res = decrypt_archive_python(
                archive_path, private_key, output_file, unstream_cmd
            )
        else:
            logging.warning(
                "Processing archive %s with OpenSSL will likely fail because file is too big (%d bytes) !",
                archive_path,
                archive_path.stat().st_size,
            )
            res = decrypt_archive_openssl(
                archive_path, private_key, output_file, unstream_cmd
            )
    else:
        if method == "auto" or method == "openssl":
            res = decrypt_archive_openssl(
                archive_path, private_key, output_file, unstream_cmd
            )
        else:
            res = decrypt_archive_python(
                archive_path, private_key, output_file, unstream_cmd
            )

    if res:
        logging.info("Successfully decrypted archive into %s", output_file)
    else:
        logging.error("Failed to decrypt archive")
    return res


def decrypt_archive_python(
    archive_path: Path,
    private_key: Path,
    output_file: Path,
    unstream_cmd: Path,
    hash_algo: HashAlgorithm = hashes.SHA1(),  # nosec B303 - Not used for encryption, only decryption
) -> bool:
    logger = logging.getLogger(__name__)
    logger.addFilter(ContextFilter(archive_path.name))
    logger.debug(
        "Decrypting archive with private key %s using Python implementation",
        private_key,
    )

    # Load the private key and the base 64 ciphertext.
    pkey = load_pem_private_key(open(private_key, "rb").read(), password=None)

    # We grab the beginning of the file so that we can extract the
    # various information we need (RSA-encrypted symmetric key,
    # encryption algorithm, etc). After having decrypted the key
    # we open the file at the right offset (beginning of octet
    # strings containing data) and decrypt the data.
    s = open(archive_path, "rb").read(50 * 1024)

    symkey = None
    # First try with RSAES-OAEP OID
    for match in rsa_oaep_oid.finditer(s):
        # Next we should have 04|82|len|rsaencryptedsymkey
        key_offset = match.end() + 4
        encsymkeylen = struct.unpack(">H", s[key_offset : key_offset + 2])[0]
        encsymkey = s[key_offset + 2 : key_offset + 2 + encsymkeylen]
        try:
            symkey = pkey.decrypt(
                encsymkey,
                padding=padding.OAEP(
                    mgf=padding.MGF1(algorithm=hash_algo),
                    algorithm=hash_algo,
                    label=None,
                ),
            )
            logger.debug(
                "Successfully decrypted symmetric key found with RSAES-OAEP OID at offset 0x%x",
                match.start(),
            )
            break
        except ValueError:
            pass
    else:
        logger.warning(
            "Failed to decrypt any of the %d symmetric keys found with RSAES-OAEP OID",
            len(rsa_oaep_oid.findall(s)),
        )

    if not symkey:
        # Try with rsaEncryption OID
        for match in rsa_encryption_oid.finditer(s):
            # Next we should have 04|82|len|rsaencryptedsymkey
            key_offset = match.end() + 2
            encsymkeylen = struct.unpack(">H", s[key_offset : key_offset + 2])[0]
            encsymkey = s[key_offset + 2 : key_offset + 2 + encsymkeylen]
            try:
                symkey = pkey.decrypt(encsymkey, padding=padding.PKCS1v15())
                logger.debug(
                    "Successfully decrypted symmetric key found with rsaEncryption OID at offset 0x%x",
                    match.start(),
                )
                break
            except ValueError:
                pass
        else:
            logger.warning(
                "Failed to decrypt any of the %d symmetric keys found with rsaEncryption OID",
                len(rsa_encryption_oid.findall(s)),
            )

    if not symkey:
        return False

    # Next, we jump to pkcs7-data OID. It is followed by three bytes
    # before the beginning of symmetric encryption method OID
    pkcs7_offset = s.find(pkcs7_data_oid) + len(pkcs7_data_oid) + 2
    oidlen = s[pkcs7_offset + 1]
    sym_enc_oid = decode_oid(s[pkcs7_offset : pkcs7_offset + oidlen + 2])

    # Next elements is IV
    iv_offset = pkcs7_offset + oidlen + 2
    ivlen = s[iv_offset + 1]
    iv = s[iv_offset + 2 : iv_offset + ivlen + 2]

    if sym_enc_oid == "2.16.840.1.101.3.4.1.42":  # AES 256 CBC
        logger.debug("Using AES-256-CBC (OID %s) for decryption", sym_enc_oid)
        cipher = Cipher(algorithms.AES(symkey), modes.CBC(iv))
    elif sym_enc_oid == "2.16.840.1.101.3.4.1.2":  # AES 128 CBC
        logger.debug("Using AES-128-CBC (OID %s) for decryption", sym_enc_oid)
        cipher = Cipher(algorithms.AES(symkey), modes.CBC(iv))
    elif sym_enc_oid == "1.2.840.113549.3.7":  # dES-EDE3-CBC
        logger.debug("Using 3DES-CBC (OID %s) for decryption", sym_enc_oid)
        cipher = Cipher(algorithms.TripleDES(symkey), modes.CBC(iv))
    else:
        raise NotImplementedError(f"Unknown encryption algorithm w/ OID {sym_enc_oid}")

    # We should now have all our octet strings providing encrypted
    # content after a A0 80
    content_offset = iv_offset + ivlen + 2
    if s[content_offset : content_offset + 2] != b"\xA0\x80":
        logger.error(
            "File does not match what we expected (\\xA0\\x80) at offset %d: %s. Found at %d",
            content_offset,
            s[content_offset - 10 : content_offset + 20].hex(),
            s[813:].find(b"\xA0\x80"),
        )
        return False

    with open(archive_path, "rb") as f:
        f.seek(content_offset + 2)
        logger.debug("Writing to %s", output_file)
        # Remove output file if it exists so that unstream does not fail
        if output_file.exists():
            output_file.unlink()

        decryptor = cipher.decryptor()
        try:
            p = subprocess.Popen(  # nosec B603 - unstream_cmd is checked for type and existence, variables are quoted
                [unstream_cmd.resolve(), "-", output_file.resolve()],
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            assert p.stdin is not None  # nosec B101 - only for type hinting
            t, c = struct.unpack("BB", f.read(2))
            prev = bytes()
            while t == 0x04:
                if c & 0x80 == 0:
                    oslen = c
                else:
                    oslen = int.from_bytes(f.read(c & 0x7F), byteorder="big")
                # Revisit to deal with incomplete read
                p.stdin.write(prev)
                try:
                    prev = decryptor.update(f.read(oslen))
                except ValueError as e:
                    logger.error(
                        "Failed to decrypt %d bytes at offset %d: %s",
                        oslen,
                        f.tell(),
                        e,
                    )
                h = f.read(2)
                if not h:
                    break
                t, c = struct.unpack("BB", h)

            # We need to remove possible padding from last decrypted chunk
            if len(prev) > 1 and len(prev) > prev[-1]:
                prev = prev[: -prev[-1]]
                p.stdin.write(prev)
        except BrokenPipeError:
            pass
        out, err = p.communicate()
        if err:
            for line in err.splitlines():
                logger.error("[unstream] %s", line.decode("utf-8"))
        if p.returncode != 0:
            return False
    return True


def decrypt_archive_openssl(
    archive_path: Path, private_key: Path, output_file: Path, unstream_cmd: Path
) -> bool:
    openssl_cmd = which("openssl")
    if not openssl_cmd or not Path(openssl_cmd).exists():
        raise FileNotFoundError("OpenSSL binary could not be found in the PATH")
    openssl_cmd = Path(openssl_cmd).resolve()  # type: ignore[assignment]

    logger = logging.getLogger(__name__)
    logger.addFilter(ContextFilter(archive_path.name))
    logger.debug("Decrypting archive with private key %s using OpenSSL", private_key)

    # Remove output file if it exists so that unstream does not fail
    if output_file.exists():
        output_file.unlink()
    openssl_p = subprocess.Popen(  # nosec B603 - unstream_cmd is checked for type and existence, and variables are quoted
        [
            openssl_cmd,
            "cms",
            "-decrypt",
            "-in",
            archive_path.resolve(),
            "-inform",
            "DER",
            "-inkey",
            private_key.resolve(),
            "-binary",
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    unstream_p = subprocess.Popen(  # nosec B603 - unstream_cmd is checked for type and existence, and variables are quoted
        [unstream_cmd.resolve(), "-", output_file.resolve()],
        stdin=openssl_p.stdout,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    assert openssl_p.stdout is not None  # nosec B101 - only for type hinting
    openssl_p.stdout.close()

    _, err = openssl_p.communicate()
    if err:
        for line in err.splitlines():
            logger.error("[openssl stderr] %s", line.decode("utf-8"))

    out, err = unstream_p.communicate()
    if err:
        for line in err.splitlines():
            logger.error("[unstream stderr] %s", line.decode("utf-8"))

    if (
        openssl_p.returncode == 0
        and unstream_p.returncode == 0
        and output_file.exists()
        and output_file.stat().st_size > 0
    ):
        return True
    else:
        logger.error(
            "Decrypting archive %s with openssl (exit code: %d) and unstream (exit code: %d) failed. "
            "Decrypted output size was: %d",
            archive_path,
            openssl_p.returncode,
            unstream_p.returncode,
            output_file.stat().st_size,
        )
        if output_file.exists():
            output_file.unlink()
        return False
