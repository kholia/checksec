import koji
import urlgrabber
import urlgrabber.progress
import os
import re

topurl = 'http://kojipkgs.fedoraproject.org'
server = 'http://koji.fedoraproject.org/kojihub'
build_target = "f19"

def download_url(url):
    basename = url.split('/')[-1]
    # print url
    # print basename
    path = os.path.join("cache", basename)
    if os.path.exists(path):
        return
    prog_meter = urlgrabber.progress.TextMeter()
    urlgrabber.grabber.urlgrab(url, path, progress_obj=prog_meter)

def fetch_koji_build(bid):
    session = koji.ClientSession(server)
    info = session.getBuild(bid)
    if not info:
        return

    task = session.getTaskInfo(info["task_id"], request=True)
    if not task:
        return
    found = False
    for item in task["request"]:
        if not isinstance(item, str):
            continue
        if re.match(build_target, item):
            found = True
            break
    if not found:
        print "skipping", bid, task["request"]
        return

    urls = []
    rpms = session.listRPMs(buildID=info['id'])
    pathinfo = koji.PathInfo(topdir=topurl)
    for rpm in rpms:
        fname = koji.pathinfo.rpm(rpm)
        url = os.path.join(pathinfo.build(info), fname)
        # print url
        # skip SRPMs and 32-bit RPMs
        if not url.endswith("src.rpm") and not url.endswith("686.rpm"):
            urls.append(url)

    if not urls:
        return
    for url in urls:
        download_url(url)

    print urls
    return urls
