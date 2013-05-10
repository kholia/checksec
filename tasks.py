from celery import Celery
import majdoor
import scanner
import os
import pymongo
import json
from pymongo import Connection

celery = Celery('tasks', broker='mongodb://localhost/queue')

@celery.task
def add(x, y):
    return x + y

@celery.task
def process(id):
    nvr, urls = majdoor.fetch_koji_build(id)
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
            collection = db.test_collection
            analysis = db.analysis
            analysis.insert(json.loads(output))

    return "OK"

