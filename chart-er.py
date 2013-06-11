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
import stat
from pymongo import Connection

off = "Disabled"
on = "Enabled"
partial = "Partial"

# DB stuff
connection = Connection()
db = connection.test_database
collection = db.test_collection
analysis = db.analysis

# RELRO tracking
no_relro = 0
partial_relro = 0
full_relro = 0

# PIE tracking
no_pie = 0
pie = 0

# NX tracking
no_nx = 0
nx = 0

# Stack Canary tracking
no_canary = 0
canary = 0

# read package list
total_builds = 0
with open(sys.argv[1], "rb") as f:
    for item in f.readlines():
        item = item.strip()
        pkg = analysis.find({"package" : item})
        count = pkg.count()
        total_builds = total_builds + count
        for build in pkg:
            out = {"PIE": off, "NX" : off, "RELRO" : off, "CANARY" : off}
            print "[+]", build["nvr"], build["build"]
            applicable = False
            for f in build["files"]:
                out["package"] = build["package"]
                if f.get("directory", False):
                    continue
                if not f.get("PIE", False):
                    continue
                applicable = True
                if f["PIE"] == on:
                    out["PIE"] = on
                if f["NX"] == on:
                    out["NX"] = on
                if f["CANARY"] == on:
                    out["CANARY"] = on
                if f["RELRO"] == on:
                    out["RELRO"] = on
                elif f["RELRO"] == partial:
                    if out["RELRO"] == off:  # keep the best!
                        out["RELRO"] = partial
            # dirty hack
            if applicable:
                # stats stuff
                if out["PIE"] == on:
                    pie = pie + 1
                else:
                    no_pie = no_pie + 1
                if out["NX"] == on:
                    nx = nx + 1
                else:
                    no_nx = no_nx + 1
                if out["CANARY"] == on:
                    canary = canary + 1
                else:
                    no_canary = no_canary + 1
                if out["RELRO"] == on:
                    full_relro = full_relro + 1
                elif out["RELRO"] == partial:
                    partial_relro = partial_relro + 1
                else:
                    no_relro = no_relro + 1


# plotting stuff starts
import subprocess

with open("my.dat", "wb") as f:
    f.write("Enabled\tDisabled\tPartial\n")
    # PIE status
    f.write("%s\t%s\t-\n" % (canary, no_canary))
    f.write("%s\t%s\t-\n" % (nx, no_nx))
    f.write("%s\t%s\t%s\n" % (full_relro, no_relro, partial_relro))
    f.write("%s\t%s\t-\n" % (pie, no_pie))

p = subprocess.Popen("""gnuplot -e "load 'pie.gnu'"  """, shell=True)

print "\n[+++*] %s total builds processed" % total_builds
