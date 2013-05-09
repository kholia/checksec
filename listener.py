import json
import pprint
import zmq
from tasks import process

def listen_and_print():
    # You can listen to stg at "tcp://stg.fedoraproject.org:9940"
    endpoint = "tcp://hub.fedoraproject.org:9940"
    topic1 = 'org.fedoraproject.prod.buildsys.build.state.change'
    topic2 = 'org.fedoraproject.prod.bodhi.update.request.stable'
    topic3 = 'org.fedoraproject.prod.git.receive'
    topic4 = 'org.fedoraproject.prod.git.lookaside.new'
    topic5 = 'org.fedoraproject.prod.bodhi.update.request.testing'
    topic6 = 'org.fedoraproject.prod.bodhi.update.request.stable'

    ctx = zmq.Context()
    s = ctx.socket(zmq.SUB)
    s.connect(endpoint)

    # s.setsockopt(zmq.SUBSCRIBE, topic6)
    # s.setsockopt(zmq.SUBSCRIBE, topic5)
    # s.setsockopt(zmq.SUBSCRIBE, topic4)
    s.setsockopt(zmq.SUBSCRIBE, topic3)
    # s.setsockopt(zmq.SUBSCRIBE, topic2)
    s.setsockopt(zmq.SUBSCRIBE, topic1)

    poller = zmq.Poller()
    poller.register(s, zmq.POLLIN)

    while True:
        evts = poller.poll()  # This blocks until a message arrives
        topic, msg = s.recv_multipart()
        print topic
        if topic == topic1:
            data = json.loads(msg)
            if "msg" in data:
                if "build_id" in data["msg"]:
                    state = data["msg"]["new"]
                    bid = data["msg"]["build_id"]
                    name = data["msg"]["name"]
                    if state != 1:
                        print ">>> skipping", bid, "with state", state, "and name", name
                        continue
                    # print data
                    print ">>> adding", bid, "with state", state, "and name", name
                    process.delay(bid)
        elif topic == topic5 or topic == topic6:
            print msg

if __name__ == "__main__":

    listen_and_print()
