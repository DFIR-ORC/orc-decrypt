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
import subprocess
import struct
import re
from datetime import datetime
from pathlib import Path
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP, AES

rsa_oaep_oid =          re.compile(re.escape(bytes.fromhex('06092a864886f70d010107')))
rsa_encryption_oid =    re.compile(re.escape(bytes.fromhex('06092a864886f70d0101010500')))
pkcs7_data_oid =        bytes.fromhex('06092a864886f70d010701301d')
unstream_cmd = (Path(__file__).parent / 'unstream').resolve()
openssl_cmd = 'openssl'


def decode_oid(oid):
    if not (oid[0] == 6 and oid[1] == len(oid) - 2):
        raise ValueError(f'Not an OID: {oid}')
    oid = oid[2:]

    res = []
    res.append(int(oid[0] / 40))
    res.append(oid[0] - (40 * res[0]))
    oid = oid[1:]

    cur = 0
    while oid:
        tmp = oid[0]
        cur <<= 7
        if (tmp & 0x80):
            cur |= tmp - 0x80
        else:
            cur |= tmp
            res.append(cur)
            cur = 0
        oid = oid[1:]

    return ".".join(map(lambda x: "%d" % x, res))


def decrypt_archive_python(archive_path: Path, private_key: Path, output_file: Path):
    ## Load the private key and the base 64 ciphertext.
    private_key = RSA.importKey(open(private_key, 'rb').read())

    # We grab the beginning of the file so that we can extract the
    # various information we need (RSA-encrypted symmetric key,
    # encryption algorithm, etc). After having decrypted the key
    # we open the file at the right offset (beginning of octet
    # strings containing data) and decrypt the data.
    s = open(archive_path, 'rb').read(50*1024)

    symkey = None
    # First try with RSAES-OAEP OID
    for match in rsa_oaep_oid.finditer(s):
        # Next we should have 04|82|len|rsaencryptedsymkey
        key_offset = match.end() + 4
        encsymkeylen = struct.unpack(">H", s[key_offset : key_offset + 2])[0]
        encsymkey = s[key_offset + 2 : key_offset + 2 + encsymkeylen]
        try:
            symkey = PKCS1_OAEP.new(private_key).decrypt(encsymkey)
            logging.debug('Successfully decrypted symmetric key found with RSAES-OAEP OID at offset 0x%x', match.start())
            break
        except ValueError as e:
            pass
    else:
        logging.warning('Failed to decrypt any of the %d symmetric keys found with RSAES-OAEP OID',
                        len(rsa_oaep_oid.findall(s)))

    if not symkey:
        # Try with rsaEncryption OID
        for match in rsa_encryption_oid.finditer(s):
            # Next we should have 04|82|len|rsaencryptedsymkey
            key_offset = match.end() + 2
            encsymkeylen = struct.unpack(">H", s[key_offset: key_offset + 2])[0]
            encsymkey = s[key_offset + 2: key_offset + 2 + encsymkeylen]
            try:
                symkey = PKCS1_OAEP.new(private_key).decrypt(encsymkey)
                logging.debug('Successfully decrypted symmetric key found with rsaEncryption OID at offset 0x%x',
                              match.start())
                break
            except ValueError as e:
                pass
        else:
            logging.warning('Failed to decrypt any of the %d symmetric keys found with rsaEncryption OID',
                            len(rsa_encryption_oid.findall(s)))

    if not symkey:
        return False

    # Next, we jump to pkcs7-data OID. It is followed by two bytes
    # before the beginning of symmetric encryption method OID
    pkcs7_offset = s.find(pkcs7_data_oid) + len(pkcs7_data_oid)
    oidlen = s[pkcs7_offset + 1]
    sym_enc_oid = decode_oid(s[pkcs7_offset:pkcs7_offset + oidlen + 2])

    # Next elements is IV
    iv_offset = pkcs7_offset + oidlen + 2
    ivlen = s[iv_offset + 1]
    iv = s[iv_offset + 2 : iv_offset + ivlen + 2]

    if sym_enc_oid == "2.16.840.1.101.3.4.1.42":  # AES 256 CBC
        if len(symkey) != 32:
            logging.critical('Expected a 256 bit key for AES-256-CBC (got %d instead)', len(symkey) * 8)
            return False
        logging.debug('Using AES-256-CBC (OID  %s) for decryption', sym_enc_oid)
        enc_alg = AES.new(symkey, AES.MODE_CBC, iv)
    elif sym_enc_oid == "2.16.840.1.101.3.4.1.2":  # AES 128 CBC
        if len(symkey) != 16:
            logging.critical('Expected a 128 bit key for AES-128-CBC (got %d instead)', len(symkey) * 8)
            return False
        logging.debug('Using AES-128-CBC (OID  %s) for decryption', sym_enc_oid)
        enc_alg = AES.new(symkey, AES.MODE_CBC, iv)
    else:
        logging.critical('Unknown encryption algorithm w/ OID %s', sym_enc_oid)
        return False

    # We should now have all our octet strings providing encrypted
    # content after a A0 80
    content_offset = iv_offset + ivlen + 2
    if s[content_offset:content_offset + 2] != b'\xA0\x80':
        logging.critical('File does not match what we expected (\\xA0\\x80) at offset %d: %s. Found at %d',
                         content_offset, s[content_offset-10:content_offset + 20].hex(), s[813:].find(b'\xA0\x80'))
        return False

    with open(archive_path, 'rb') as f:
        f.seek(content_offset + 2)
        logging.debug('Writing to %s', output_file)
        # Remove output file if it exists so that unstream does not fail
        if output_file.exists():
            output_file.unlink()

        # quick and dirty fixe
        # write a temporary file to avoid error: Unstream cannot read data...
        tmp_output = f'{str(output_file)}_tmp'
        tmp_file = open(tmp_output, "ab")
        if not tmp_file:
            logging.error(f"Can't open tmp file {tmp_output}")
            return False

        try:
            t, c = struct.unpack("BB", f.read(2))
            prev = bytes()
            while t == 0x04:
                if c & 0x80 == 0:
                    oslen = c
                else:
                    oslen = int.from_bytes(f.read(c & 0x7f), byteorder='big')
                # Revisit to deal with incomplete read
                tmp_file.write(prev)
                prev = enc_alg.decrypt(f.read(oslen))
                h = f.read(2)
                if not h:
                    break
                t, c = struct.unpack("BB", h)

            # We need to remove possible padding from last decrypted chunk
            if len(prev) > 1 and len(prev) > prev[-1]:
                prev = prev[:-prev[-1]]
                tmp_file.write(prev)
        except BrokenPipeError:
            pass

        #close file before use with unstream
        tmp_file.close()

        # remove shlex.quote, normally there is no command injection with this form
        p = subprocess.Popen([unstream_cmd, tmp_output, str(output_file)],
                                stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        out, err = p.communicate()
        if out:
            logging.info(out)
        if err:
            logging.error(err)
        
        Path(tmp_output).unlink()

    return True


def decrypt_archive_openssl(archive_path: Path, private_key: Path, output_file: Path):
    # Remove output file if it exists so that unstream does not fail
    if output_file.exists():
        output_file.unlink()

    # popen style without shell=True, normally no more command injection
    # and compatible Windows without quote (shlex.quote doesn't work with Windows)
    # but the form with PIPE to chain both processes like below doesn't work
    
    # openssl_process = subprocess.Popen([openssl_cmd, "cms", "-decrypt", "-in",
    #                        str(archive_path), "-inform", "DER", "-inkey",
    #                        str(private_key), "-binary"], stdout=subprocess.PIPE)
    #
    # unstream_process = subprocess.Popen([unstream_cmd, "-",
    #                              str(output_file)], stdin=openssl_process.stdout)
    # openssl_process.stdout.close()
    # unstream_process.communicate() -> unstream error cannot read data

    # Quick and Dirty tmp file to chain openssl and unstream
    tmp_output = f'{str(output_file)}_tmp'
    openssl_process = subprocess.Popen([openssl_cmd, "cms", "-decrypt", "-in",
                    str(archive_path), "-inform", "DER", "-inkey",
                    str(private_key), "-binary", "-out", tmp_output])
    out, err = openssl_process.communicate()
    if out:
        logging.info(out)
    if err:
        logging.error(err)

    unstream_process = subprocess.Popen([unstream_cmd, tmp_output, str(output_file)])

    out, err = unstream_process.communicate()
    if out:
        logging.info(out)
    if err:
        logging.error(err)

    if unstream_process.returncode == 0 and output_file.exists() and output_file.stat().st_size > 0:
        Path(tmp_output).unlink()
        return True
    else:
        logging.error('Decrypting archive %s with openssl and unstream failed. '
                      'Return code of shell process was %d and decrypted output size was: %d',
                      archive_path, unstream_process.returncode, output_file.stat().st_size)
        if output_file.exists():
            output_file.unlink()
        return False


def process_archive(archive_path: Path, private_key: Path, output_file: Path, method: str):
    if output_file.exists() and not args.force:
        logging.warning('Output file %s already exists, skipping (use --force to overwrite)', output_file)
        return False

    if archive_path.stat().st_size >= 2**32 / 2 - 1:
        if method == 'auto' or method == 'python':
            logging.debug('Processing archive %s with Python', archive_path)
            res = decrypt_archive_python(archive_path, private_key, output_file)
        else:
            logging.warning('Processing archive %s with OpenSSL will likely fail because it\'s too big !', archive_path)
            res = decrypt_archive_openssl(archive_path, private_key, output_file)
    else:
        if method == 'auto' or method == 'openssl':
            logging.debug('Processing archive %s with OpenSSL', archive_path)
            res = decrypt_archive_openssl(archive_path, private_key, output_file)
        else:
            logging.debug('Processing archive %s with Python', archive_path)
            res = decrypt_archive_python(archive_path, private_key, output_file)
    if res:
        logging.info('Successfully decrypted %s into %s', archive_path, output_file)
    else:
        logging.critical('Failed to decrypt archive %s', archive_path)
    return res


def parse_args():
    parser = argparse.ArgumentParser(formatter_class=argparse.ArgumentDefaultsHelpFormatter, add_help=True,
                                     description="Wrapper around the two possible methods of decrypting ORC archives")
    parser.add_argument("-k", "--key", metavar='file', type=str,
                        help="PEM-encoded unencrypted key file", required=True)
    parser.add_argument("input", metavar='input_dir', type=str,
                        help="Input directory where the encrypted archives are stored")
    parser.add_argument("output_dir", metavar='output_dir', type=str,
                        help="Output directory where to store the decrypted archives")
    parser.add_argument("--log-level", metavar='level', default='INFO',
                        choices=['CRITICAL', 'ERROR', 'WARNING', 'INFO', 'DEBUG'],
                        help="Print log messages of this level and higher, possible choices: %(choices)s")
    parser.add_argument('--log-file', metavar='file', help='Log file to store DEBUG level messages')
    parser.add_argument("-f", "--force", action="store_true", default=False,
                        help="Force overwrite of existing files in output directory.", )
    parser.add_argument("-j", "--jobs", metavar='N', type=int,
                        help="Number of jobs to process in parallel. Defaults to Python implementation of multiprocessing.Pool")
    parser.add_argument("-m", "--method", metavar='mode', type=str, choices=['auto', 'openssl', 'python'],
                        default='auto',
                        help="Method to use to decrypt archives. Default is 'auto' meaning the script will use "
                             "openssl for archives smaller than 2GB and pure-python implementation for larger ones. "
                             "Warning: forcing the usage of openssl for archives larger than 2GB will likely prevent "
                             "the script from decrypting these archives as openssl cannot handle them in its current "
                             "version (1.1.1f)")

    if not unstream_cmd.exists():
        parser.error(f'Missing tool "unstream" in path {Path(__file__).parent.resolve()}, '
                     f'please make sure you have compiled it first.')

    return parser.parse_args()


if __name__ == "__main__":
    args = parse_args()
    begin = datetime.now()

    # Setup logging
    log_level = getattr(logging, args.log_level)
    if args.log_file:
        # Send everything (DEBUG included) in the log file and keep only log_level messages on the console
        logging.basicConfig(level=logging.DEBUG,
                            format='[%(asctime)s] %(name)-12s - %(levelname)-8s - %(message)s',
                            filename=args.log_file,
                            filemode='w')
        # define a Handler which writes messages of log_level or higher to the sys.stderr
        console = logging.StreamHandler()
        console.setLevel(log_level)
        # set a format which is simpler for console use
        formatter = logging.Formatter('[%(asctime)s] - %(levelname)-8s - %(message)s')
        # tell the handler to use this format
        console.setFormatter(formatter)
        # add the handler to the root logger
        logging.getLogger('').addHandler(console)
    else:
        logging.basicConfig(level=getattr(logging, args.log_level), format='[%(asctime)s] - %(levelname)-8s - %(message)s')

    archives_list = list(Path(args.input).rglob('*.p7b'))
    logging.info('Decrypting %d archives from %s into %s using private key %s',
                 len(archives_list), args.input, args.output_dir, args.key)
    Path(args.output_dir).mkdir(parents=True, exist_ok=True)
    with multiprocessing.Pool(args.jobs) as pool:
        results = pool.starmap(process_archive,
                               [(f, Path(args.key), (Path(args.output_dir) / f.stem).resolve(), args.method)
                                for f in archives_list],)

    end = datetime.now()
    logging.info('Finished processing %d archives in %s. %d failed, %d succeeded',
                 len(archives_list), end-begin, results.count(False), results.count(True))

