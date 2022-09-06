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


def decode_oid(oid: bytes) -> str:
    if not (oid[0] == 6 and oid[1] == len(oid) - 2):
        raise ValueError(
            f"Not an OID: {oid.hex()}. Check first byte ({oid[0]}) and length {len(oid) - 2} with second byte ({oid[1]})."
        )
    orig_oid = oid
    oid = oid[2:]

    res = []
    res.append(int(oid[0] / 40))
    res.append(oid[0] - (40 * res[0]))
    oid = oid[1:]

    cur = 0
    while oid:
        tmp = oid[0]
        cur <<= 7
        if tmp & 0x80:
            cur |= tmp - 0x80
        else:
            cur |= tmp
            res.append(cur)
            cur = 0
        oid = oid[1:]

    logging.debug(
        "Decoded bytes %s as OID %s",
        orig_oid.hex(),
        ".".join(map(lambda x: "%d" % x, res)),
    )
    return ".".join(map(lambda x: "%d" % x, res))


class ContextFilter(logging.Filter):
    """
    This is a filter which injects contextual information into the log.
    """

    def __init__(self, ctx_str: str):
        self._ctx_str = ctx_str

    def filter(self, record):
        record.ctx = self._ctx_str
        return True
