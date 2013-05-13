#!/usr/bin/env python

from flask import Flask
from flask import Response
from flask import request
from flask import jsonify
import pymongo
from bson.json_util import dumps
import yaml
import json

app = Flask(__name__)
app.config.from_pyfile('settings.py')

# connect to the database
connection = pymongo.Connection(app.config['MONGODB_HOST'],
                app.config['MONGODB_PORT'])

collection = connection[app.config['MONGODB_DB']].analysis
collection_grill = connection[app.config['MONGODB_DB']].rpmgrill

@app.route("/")
def home():
    return ":-)"

@app.route('/packages/')
@app.route('/packages/<package>/')
def packages(package=None):
    callback = request.args.get('callback', False)

    if not package:
        fltr = request.args.get('filter', "index")
        if fltr == "everything":
            ret = collection.find()
        else:
            ret  = collection.distinct("package")
    else:
        spec = {
            "package" : package
        }
        fltr = request.args.get('fuzzy', None)
        if fltr:
            # do fuzzy matching of package names
            fltr = request.args.get('filter', "index")
            if fltr == "everything":
                ret = collection.find({'package': {'$regex': '%s' % package}})
            else:
                ret = []
                output = collection.find({'package': {'$regex': '%s' % package}})
                for item in output:
                    ret.append(item["package"])
        else:
            ret = collection.find(spec)

    if (isinstance(ret, list) and len(ret) != 0) or \
            (not isinstance(ret, list) and ret.count() != 0):
        output = dumps(ret, sort_keys=True, indent=4)
        if callback:
            output = str(callback) + '(' + str(output) + ')'
        return Response(response=output, status=200,
            mimetype="application/json")

    return Response(response=dumps([]), status=404,
            mimetype="application/json")

@app.route('/grill/')
@app.route('/grill/<package>/')
def grill(package=None):
    callback = request.args.get('callback', False)

    if not package:
        fltr = request.args.get('filter', "index")
        if fltr == "everything":
            ret = collection_grill.find()
        else:
            ret  = collection_grill.distinct("package")
    else:
        spec = {
            "package" : package
        }
        fltr = request.args.get('fuzzy', None)
        if fltr:
            # do fuzzy matching of package names
            fltr = request.args.get('filter', "index")
            if fltr == "everything":
                ret = collection_grill.find({'package': {'$regex': '%s' % package}})
            else:
                ret = []
                output = collection_grill.find({'package': {'$regex': '%s' % package}})
                for item in output:
                    ret.append(item["package"])
        else:
            ret = collection_grill.find(spec)

    if (isinstance(ret, list) and len(ret) != 0) or \
            (not isinstance(ret, list) and ret.count() != 0):
        output = []
        for r in ret:
            y = yaml.load(r["output"])
            d = dumps(y, sort_keys=True, indent=4)
            entry = json.loads(d)
            entry["opackage"] = r["package"]
            entry["nvr"] = r["nvr"]
            output.append(entry)
        output = dumps(output, sort_keys=True, indent=4)
        if callback:
            output = str(callback) + '(' + str(output) + ')'
        return Response(response=output, status=200,
            mimetype="application/json")

    return Response(response=dumps([]), status=404,
            mimetype="application/json")


if __name__ == "__main__":
    app.run(host='0.0.0.0', debug=True)
