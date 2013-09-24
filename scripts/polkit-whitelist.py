#!/usr/bin/env python

from pymongo import Connection

connection = Connection()

def privileged_dangerous():
    for build in analysis.find():
        if build["polkit"] == True:
            for name in build["pols"]:
                name = name.lstrip(".")
                print "%-27s\t%s" % (build["package"],
                    name)

db = connection.test_database
collection = db.test_collection

analysis = db.analysis

privileged_dangerous()
