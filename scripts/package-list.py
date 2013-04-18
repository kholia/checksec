#!/usr/bin/env python

"""Fast RPM analysis tool"""

import sys

try:
    import libarchive
except ImportError:
    print >> sys.stderr, "Please install python-libarchive from PyPI"
    sys.exit(-1)

try:
    import rpm
except ImportError:
    print >> sys.stderr, "Please install rpm-python package"
    sys.exit(-1)

import subprocess
import os
import json


def analyze(rpmfile):
    """Analyse single RPM file"""

    if not rpmfile.endswith(".rpm"):
        return

    try:
        ts = rpm.TransactionSet()
        fd = os.open(rpmfile, os.O_RDONLY)
        h = ts.hdrFromFdno(fd)
        os.close(fd)
    except Exception, exc:
        print >> sys.stderr, rpmfile, str(exc)
        return

    package = h[rpm.RPMTAG_NAME]

    print package

if len(sys.argv) < 2:
    print >> sys.stderr, "Usage: %s <path to RPM files> [output format (csv / json)]" % sys.argv[0]
    sys.exit(-1)

path = sys.argv[1]

if(os.path.isfile(path)):
    analyze(path)

for (path, dirs, files) in os.walk(path):
    for fname in files:
        rpmfile = os.path.join(path, fname)
        #print >> sys.stderr, "Analyzing %s ..." % rpmfile
        analyze(rpmfile)
