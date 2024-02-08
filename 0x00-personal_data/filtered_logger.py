#!/usr/bin/env python3
""" Filtered Logger """
import re
from typing import (List)


def filter_datum(fields: List[str], redaction: str,
                 message: List, separator: str) -> List[str]:
    """ returns the log message obfuscated """
    for f in fields:
        message = re.sub(r'({})=.*?{}'.format(f, separator),
                         r'\1={}{}'.format(redaction, separator), message)
    return message
