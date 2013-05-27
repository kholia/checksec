import koji
import urlgrabber
import urlgrabber.progress
import os
import re

# these are fixed
topurl = 'http://kojipkgs.fedoraproject.org'
server = 'http://koji.fedoraproject.org/kojihub'
work_url = 'http://kojipkgs.fedoraproject.org/work'
lookup = {'i386' : 'i686'}

# this one is not
build_target = "f19"

def download_url(package, nvr, urls):
    for arch, url in urls:
        arch = lookup.get(arch, arch)
        basename = url.split('/')[-1]

        # log files are special
        if basename.endswith(".log"):
            basepath = os.path.join("cache", nvr, arch)
        else:
            basepath = os.path.join("cache", nvr)
        path = os.path.join(basepath, basename)
        print "[*]", path
        try:
            os.makedirs(basepath)
        except:
            pass

        # fetch stuff
        if os.path.exists(path):
            continue
        prog_meter = urlgrabber.progress.TextMeter()
        urlgrabber.grabber.urlgrab(url, path, progress_obj=prog_meter)

def fetch_koji_build(build):
    """
    build ==> buildID or NVR
    """

    if build.isdigit():
        build = int(build)

    urls = []  # output

    pathinfo = koji.PathInfo(topdir=topurl)
    session = koji.ClientSession(server)
    info = session.getBuild(build)
    # print session.listArchives(build)
    # rpms = session.listRPMs(buildID=info['id'])
    # if not rpms:
    #    print ":-("
    # for rpm in rpms:
    #    fname = pathinfo.rpm(rpm)
    #    url = pathinfo.build(info) + '/' + fname
    #    print url

    if not info:
        return

    task_id = info["task_id"]
    nvr = info.get("nvr", str(task_id))
    package = info.get("name", str(task_id))

    task = session.getTaskInfo(task_id, request=True)
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
        print "skipping", build, task["request"]
        return

    if not task:
        print('Invalid task ID: %i' % task_id)
    elif task['state'] in (koji.TASK_STATES['FREE'], koji.TASK_STATES['OPEN']):
        print('Task %i has not completed' % task['id'])
    elif task['state'] != koji.TASK_STATES['CLOSED']:
        print('Task %i did not complete successfully' % task['id'])

    if task['method'] == 'build':
        print 'Getting rpms from children of task %i: %s' % (task['id'], koji.taskLabel(task))
        tasks = session.listTasks(opts={'parent': task_id, 'method': 'buildArch', 'state': [koji.TASK_STATES['CLOSED']],
                                        'decode': True})
    elif task['method'] == 'buildArch':
        tasks = [task]
    else:
        print('Task %i is not a build or buildArch task' % task['id'])

    for task in tasks:
        print ">>>>", task, task['id']
        arch = task.get('arch', 'unkwown')
        output = session.listTaskOutput(task['id'])
        print ">>>>", arch, output
        # logs = [filename for filename in output if filename.endswith('.log')]
        for item in output:
            base_path = koji.pathinfo.taskrelpath(task['id'])
            file_url = "%s/%s/%s" % (work_url, base_path, item)
            urls.append((arch, file_url))
            # print file_url
            # urls.append(file_url)

    # rpms = session.listRPMs(buildID=info['id'])
    # pathinfo = koji.PathInfo(topdir=topurl)
    # for rpm in rpms:
        # fname = koji.pathinfo.rpm(rpm)
        # url = os.path.join(pathinfo.build(info), fname)
        # print url
        # skip SRPMs and 32-bit RPMs
        # if not url.endswith("src.rpm") and not url.endswith("686.rpm"):
        #    urls.append(url)

    print "Getting", urls

    if not urls:
        return

    download_url(package, nvr, urls)

    return package, nvr, urls
