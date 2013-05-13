from celery import Celery
import majdoor
import scanner
import os
import pymongo
import json
from pymongo import Connection
import subprocess

celery = Celery('tasks', broker='mongodb://localhost/queue')

@celery.task
def add(x, y):
    return x + y

@celery.task
def process(id):
    stuff = majdoor.fetch_koji_build(id)
    if stuff and len(stuff) == 3:
        package, nvr, urls = stuff
    else:
        print "??? majdoor skipped / failed", id
        return "OK"

    if not urls:
        return
    for arch, url in urls:
        basename = url.split('/')[-1]
        path = os.path.join("cache", nvr, basename)

        if path.endswith(".rpm") and not \
                path.endswith(".src.rpm") and \
                not "-debuginfo-" in path:
            output = scanner.analyze(path)
            print output

            connection = Connection()
            db = connection.test_database
            analysis = db.analysis
            analysis.insert(json.loads(output))
            connection.close()

    # do rpmgrill stuff, spawn as we don't know how rpmgrill affets our env.
    basepath = os.path.join(os.path.realpath("cache"), nvr)
    print "Running rpmgrill on", basepath
    p = subprocess.Popen("./invoke_rpmgrill.sh %s" % basepath,
            stderr=subprocess.PIPE, shell=True)
    _, err = p.communicate()

    output = os.path.join(os.path.realpath("cache"), nvr, "rpmgrill.yaml")
    if not os.path.exists(output):
        print "!!! rpmgrill failed for", basepath
        print err
    else:
        with open(output) as f:
            data = f.read()
        # we store the output of rpmgrill.yaml in a database
        connection = Connection()
        db = connection.test_database
        rpmgrill = db.rpmgrill
        entry =  { "nvr" : nvr, "output" : data, "package" : package }
        rpmgrill.insert(entry)
        print "!!!", err

    return "OK"

