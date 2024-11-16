"""
Inspired and copied from https://github.com/blacklanternsecurity/bbot
"""

import sys

loglevel_mapping = {
    "DEBUG": "DBUG",
    "TRACE": "TRCE",
    "VERBOSE": "VERB",
    "HUGEVERBOSE": "VERB",
    "INFO": "INFO",
    "HUGEINFO": "INFO",
    "SUCCESS": "SUCC",
    "HUGESUCCESS": "SUCC",
    "WARNING": "WARN",
    "HUGEWARNING": "WARN",
    "ERROR": "ERRR",
    "CRITICAL": "CRIT",
}
color_mapping = {
    "DEBUG": 242,  # grey
    "TRACE": 242,  # red
    "VERBOSE": 242,  # grey
    "INFO": 69,  # blue
    "HUGEINFO": 69,  # blue
    "SUCCESS": 118,  # green
    "HUGESUCCESS": 118,  # green
    "WARNING": 208,  # orange
    "HUGEWARNING": 208,  # orange
    "ERROR": 196,  # red
    "CRITICAL": 196,  # red
}
color_prefix = "\033[1;38;5;"
color_suffix = "\033[0m"


def colorize(s, level="INFO"):
    seq = color_mapping.get(level, 15)  # default white
    colored = f"{color_prefix}{seq}m{s}{color_suffix}"
    return colored


def log_to_stderr(msg, level="INFO", logname=True):
    """
    Print to stderr with BBOT logger colors
    """
    lvlName = level.upper()
    if not any(x in sys.argv for x in ("-s", "--silent")):
        lvlShort = f"[{loglevel_mapping.get(level, 'INFO')}]"
        lvlShort = f"{colorize(lvlShort, level=lvlName)}"
        if lvlName == "CRITICAL" or lvlName.startswith("HUGE"):
            msg = colorize(msg, level=lvlName)
        if logname:
            msg = f"{lvlShort} {msg}"
        print(msg, file=sys.stderr)
