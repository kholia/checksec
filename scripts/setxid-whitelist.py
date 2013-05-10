#!/usr/bin/env python

"""
{"files": [{"name": "/usr/bin/tex", "RPATH": "Enabled", "RELRO": "Partial", "CANARY": "Enabled", "PIE": "Disabled", "NX": "Enabled", "RUNPATH": "Disabled", "mode": 33261, "size": 320800}], "build": "texlive-tex-bin-2012-0.svn26912.8.20121115_r28267.fc18.x86_64.rpm", "package": "texlive-tex-bin"}
{"files": [{"name": "/usr/bin/pbs_wish", "RPATH": "Disabled", "RELRO": "Partial", "CANARY": "Enabled", "PIE": "Disabled", "NX": "Enabled", "RUNPATH": "Disabled", "mode": 33261, "size": 31840}, {"name": "/usr/lib64/xpbs/bin/xpbs_datadump", "RPATH": "Disabled", "RELRO": "Partial", "CANARY": "Enabled", "PIE": "Disabled", "NX": "Enabled", "RUNPATH": "Disabled", "mode": 33261, "size": 23248}, {"name": "/usr/lib64/xpbs/bin/xpbs_scriptload", "RPATH": "Disabled", "RELRO": "Partial", "CANARY": "Enabled", "PIE": "Disabled", "NX": "Enabled", "RUNPATH": "Disabled", "mode": 33261, "size": 18896}], "build": "torque-gui-3.0.4-1.fc17.x86_64.rpm", "package": "torque-gui"}
"""

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

# we know what we are doing!
from stat import *
from pymongo import Connection

# stuff borrowed from Python 3.3
_filemode_table = (
    ((S_IFLNK,         "l"),
     (S_IFREG,         "-"),
     (S_IFBLK,         "b"),
     (S_IFDIR,         "d"),
     (S_IFCHR,         "c"),
     (S_IFIFO,         "p")),

    ((S_IRUSR,         "r"),),
    ((S_IWUSR,         "w"),),
    ((S_IXUSR|S_ISUID, "s"),
     (S_ISUID,         "S"),
     (S_IXUSR,         "x")),

    ((S_IRGRP,         "r"),),
    ((S_IWGRP,         "w"),),
    ((S_IXGRP|S_ISGID, "s"),
     (S_ISGID,         "S"),
     (S_IXGRP,         "x")),

    ((S_IROTH,         "r"),),
    ((S_IWOTH,         "w"),),
    ((S_IXOTH|S_ISVTX, "t"),
     (S_ISVTX,         "T"),
     (S_IXOTH,         "x"))
)

def filemode(mode):
    """Convert a file's mode to a string of the form '-rwxrwxrwx'."""
    perm = []
    for table in _filemode_table:
        for bit, char in table:
            if mode & bit == bit:
                perm.append(char)
                break
        else:
            perm.append("-")
    return "".join(perm)

connection = Connection()

def percentage(keyword="PIE"):
    piecount = 0
    total = 0

    for build in analysis.find():
        for f in build["files"]:
            total = total + 1
            mode = f["mode"]
            if f[keyword] not in off:
                piecount = piecount  +1
            else:
                if verbose:
                    print "%s,%s,%s" % (build["package"], f["name"], build["build"])
                    #print "[No %s]" % keyword, build["package"], f["name"], build["build"]

    # print "[-] Out of %d binaries, %d have %s enabled" % (total, piecount, keyword)

def privileged_dangerous(prune=None):
    for build in analysis.find():
        for f in build["files"]:
            dangerous = False
            mode = f["mode"]
            if prune:
                if not prune_list.get(build["package"], False):
                    continue
            if (mode & stat.S_ISUID) or (mode & stat.S_ISGID):
                print "%-27s\t%s\t%-10s\t%-10s\t%s" % (build["package"],
                        filemode(mode), f["user"], f["group"], f["name"])

def privileged_nopie():
    setuid = 0
    pie = 0

    for build in analysis.find():
        #print build["package"]
        for f in build["files"]:
            mode = f["mode"]
            #print mode
            if mode & 04000:
                setuid = setuid + 1
                if f["PIE"] != off:
                    pie = pie  + 1
                else:
                    if verbose:
                        print >> sys.stderr, "[No PIE]", f["name"], build["package"], build["build"]

    # print "[-] Out of %d setuid binaries, %d have PIE enabled" % (setuid, pie)

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

# make prune_list
prune_list = {}

if results.prune_file:
    with open(results.prune_file, "r") as f:
        for line in f.readlines():
            prune_list[line.strip()] = True

privileged_dangerous(results.prune_file)
# percentage()
# percentage("NX")
# percentage("CANARY")
# percentage("RELRO")
# privileged_nopie()
