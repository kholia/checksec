#!/usr/bin/env python

from pymongo import Connection

connection = Connection()

def privileged_dangerous():
    for build in analysis.find():
        if build["caps"] == True:
            for item in build["filecaps"]:
                name, caps = item
                caps = caps.strip("= ")
                print "%-30s\t%-30s\t%s" % (build["package"], name, caps)

db = connection.test_database
collection = db.test_collection

analysis = db.analysis

privileged_dangerous()
