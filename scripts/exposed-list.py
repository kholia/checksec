#!/usr/bin/env python

"""Output a list of "exposed" programs which are not hardened."""

import sys

try:
    import pymongo
except ImportError:
    print >> sys.stderr, "Please install pymongo package"
    sys.exit(-1)

import subprocess
import os
import json
import stat
from pymongo import Connection

groups = {}
connection = Connection()

def get_groups():
    global groups
    for build in analysis.find():
        groups[build["group"]] = groups.get(build["group"], 0) + 1

checklist = ["Applications/CGI", "Network/Daemons", "Applications/Communications", "System", "Applications/Internet", "System Environment/Base", "System Environment/Daemons", "Applications/Databases"]

def privileged_dangerous():
    for item in checklist:
        print "\n" + item + "\n"
        for build in analysis.find():
            for f in build["files"]:
                dangerous = False
                mode = f["mode"]
                if not build["group"] in item:
                    continue
                if f.get("directory", False):
                    #print "%s,%s,%s,directory,%s" % (build["package"], build["build"], f["name"], oct(f["mode"]))
                    continue
                if not f.get("PIE", None):
                    # print >> sys.stderr, "%s is not a an ELF file!" % f["name"]
                    continue
                if f["PIE"] == off or f["NX"] == off or f["CANARY"] == off or f["RELRO"] == off:
                    print "%s,%s,%s,%s,%s,%s,%s,%s" % (build["package"], build["build"], f["name"], f["NX"], f["CANARY"], f["RELRO"], f["PIE"], oct(f["mode"]))


import argparse

parser = argparse.ArgumentParser()

parser.add_argument('-v', action="store_true", dest="verbose", help="enable verbose mode")
parser.add_argument('-f', action="store", dest="prune_file", help="enable filter mode")

results = parser.parse_args()

off = "Disabled"
verbose = results.verbose

db = connection.test_database
collection = db.test_collection

analysis = db.analysis

get_groups()

privileged_dangerous()
