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
    urls = majdoor.fetch_koji_build(id)
    if not urls:
        return
    for url in urls:
        basename = url.split('/')[-1]
        path = os.path.join("cache", basename)
        output = scanner.analyze(path)
        print output

        connection = Connection()
        db = connection.test_database
        collection = db.test_collection
        analysis = db.analysis
        analysis.insert(json.loads(output))

    return "OK"

