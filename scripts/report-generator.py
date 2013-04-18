#!/usr/bin/env python

"""Output a list of "exposed" programs which are not hardened."""

import sys

try:
    import pkgwat.api
except ImportError:
    print >> sys.stderr, "Please install pkgwat package"
    sys.exit(-1)

try:
    import pymongo
except ImportError:
    print >> sys.stderr, "Please install pymongo package"
    sys.exit(-1)

try:
    import xlwt
except ImportError:
    print >> sys.stderr, "Please install xlwto package"
    sys.exit(-1)

import subprocess
import os
import json
import stat
import csv
from pymongo import Connection

def get_packager(package):
    data = pkgwat.api.search(package)
    print >> sys.stderr, "Fetching info for", package
    fdata = data["rows"][0]
    return fdata.get(u"devel_owner", "?")

connection = Connection()

row = 2

def privileged_dangerous():
    global row
    row += 2
    for build in analysis.find():

        # find if setuid / setgid stuff exists in this package
        analyze_this = False
        for f in build["files"]:
            mode = f["mode"]
            if (mode & stat.S_ISUID) or (mode & stat.S_ISGID):
                if f["PIE"] == off or f["NX"] == off or f["CANARY"] == off or f["RELRO"] == off:
                    analyze_this = True
                    if f["CATEGORY"] == "None":
                        f["CATEGORY"] = "exec"

        daemon = build.get("daemon", False)
        if not daemon and not analyze_this:
            continue

        fetched = False

        for f in build["files"]:
            dangerous = False
            mode = f["mode"]
            if f.get("directory", False):
                continue
            if not f.get("PIE", None):
                continue
            category = f["CATEGORY"]
            if category == "None":
                category = "daemon"
            if f["PIE"] == off or f["NX"] == off or f["CANARY"] == off or f["RELRO"] == off:
                if not fetched:
                    # packager = get_packager(build["package"])
                    packager = "Not Fetched"
                    fetched = True
                output = "%s,%s,%s,%s,%s,%s,%s,%s,%s,%s" % (build["package"], build["build"], f["name"], f["NX"], f["CANARY"], f["RELRO"], f["PIE"], oct(f["mode"]), category, packager)
                for col, data in enumerate(output.split(",")):
                    if "Disabled" in data or "network-ip" in data or "network-local" in data:
                        sheet.write(row, col, data, st)
                    else:
                        sheet.write(row, col, data)
                writer.writerow(output.split(","))
                csvf.flush()
                row += 1

# Create workbook and worksheet
wbk = xlwt.Workbook()
sheet = wbk.add_sheet('F19 unhardened files')
st = xlwt.easyxf('pattern: pattern solid, fore_colour red;')
headerst = xlwt.easyxf('pattern: pattern solid, fore_colour 22;')

# write header
header_fields = ['Package', 'Build', 'File', 'NX', 'CANARY', 'RELRO', 'PIE', 'mode', 'CATEGORY', 'Packager', 'Notes', 'Comments']

for col in range(0, len(header_fields)):
    sheet.write(0, col, header_fields[col], headerst)

# hardcoded widths :(
widths = [25, 35, 30, 10, 10, 8, 8, 8, 25, 25]
for i in range(0, 10):
    sheet.col(i).width = 256 * widths[i]

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

csvf = open("analysis.csv", "w")
writer = csv.writer(csvf)
writer.writerow(header_fields)


privileged_dangerous()

wbk.save('reformatted.data.xls')
