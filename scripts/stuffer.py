#!/usr/bin/env python

import sys

try:
    import pymongo
except ImportError:
    print >> sys.stderr, "Please install pymongo package"
    sys.exit(-1)

import subprocess
import os
import json

if len(sys.argv) < 2:
    print >> sys.stderr, "Usage: %s <analysis JSON file>" % sys.argv[0]
    sys.exit(-1)


from pymongo import Connection
connection = Connection()

db = connection.test_database
collection = db.test_collection

analysis = db.analysis

with open(sys.argv[1]) as f:
    for line in f.readlines():
        line = line.rstrip()
        try:
            data = json.loads(line)
            analysis.insert(data)
        except Exception, exc:
            print line, str(exc)
            sys.exit(1)




