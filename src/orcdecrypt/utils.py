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
from typing import Literal


class ContextFilter(logging.Filter):
    """Filter which injects contextual information into the log record."""

    def filter(self, record: logging.LogRecord) -> Literal[True]:
        """Add a ctx field to record based on extra fields."""
        base_keys = {
            "name",
            "msg",
            "args",
            "levelname",
            "levelno",
            "pathname",
            "filename",
            "message",
            "module",
            "exc_info",
            "exc_text",
            "stack_info",
            "lineno",
            "funcName",
            "created",
            "msecs",
            "relativeCreated",
            "thread",
            "threadName",
            "processName",
            "process",
            "asctime",
            "ctx",
        }
        extra: str = " ".join(
            f"{key}={str(getattr(record, key))!r}"
            for key in sorted(set(record.__dict__) - base_keys)
        )
        record.ctx = f"[{extra}] " if extra else ""
        return True
