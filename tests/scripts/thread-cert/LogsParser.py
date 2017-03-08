import sys
from datetime import datetime
import os
import re


def try_int(str, base=10, def_val=None):
    try:
        return int(str, base)
    except Exception as _:
        # print("try_int fails:", str)
        return def_val


def tokenise(line, delims):
    tokens = re.split("|".join(delims), line)
    return [t for t in tokens if t != '']


class Event:
    class EventType:
        ENTER_FUNC = 0
        EXIT_FUNC = 1
        WORK = 2
        CHUNK = 3
        MLE = 4
        MAC = 5
        ARP = 6

    def __init__(self, line):
        self.str = line
        self.rloc16 = None
        self.next_chunk = None
        self.parse(line)

    type = EventType.WORK

    @staticmethod
    def fits(line):
        raise NotImplementedError()

    def parse(self, line):
        pass

    def add_chunk(self, nxt):
        if nxt.type == Event.EventType.CHUNK:
            if self.next_chunk is None:
                self.next_chunk = nxt
            else:
                self.next_chunk.add_chunk(nxt)

    def get_str(self):
        return self.str

    def to_str(self, tabs=0, incl_chunks=False, chunk_spacing=""):
        res = '\t' * tabs + self.get_str()
        if self.next_chunk is not None:
            if incl_chunks:
                res += '\n ' + chunk_spacing + "\t" + self.next_chunk.to_str(tabs, incl_chunks, chunk_spacing)
            else:
                res += '...'
        return res

    def __str__(self):
        return self.to_str()


class EventFuncEntry(Event):
    type = Event.EventType.ENTER_FUNC

    @staticmethod
    def fits(line):
        return line[:4] == "--->"

    def parse(self, line):
        tokens = tokenise(line, " ,")
        self.func_name = tokens[1]
        if len(tokens) > 2:
            pass


class EventFuncExit(Event):
    type = Event.EventType.EXIT_FUNC

    @staticmethod
    def fits(line):
        return line[:4] == "<---"

    def parse(self, line):
        tokens = tokenise(line, " ")
        self.func_name = tokens[1]
        if len(tokens) > 2:
            pass


class EventMLE(Event):
    type = Event.EventType.MLE

    @staticmethod
    def fits(line):
        return line[:3] == "MLE"

    def parse(self, line):
        tokens = tokenise(line, " :")
        self.rloc16 = try_int(tokens[1], 16)


class EventMAC(Event):
    type = Event.EventType.MAC

    @staticmethod
    def fits(line):
        return line[:3] == "MAC"

    def parse(self, line):
        tokens = tokenise(line, " :")
        self.rloc16 = try_int(tokens[1], 16)


class EventARP(Event):
    type = Event.EventType.ARP

    @staticmethod
    def fits(line):
        return line[:3] == "ARP"

    def parse(self, line):
        tokens = tokenise(line, " ")
        self.rloc16 = try_int(tokens[1], 16)


class EventChunk(Event):
    type = Event.EventType.CHUNK
    reg_exp = re.compile("^[A-Fa-f0-9]{2}( [A-Fa-f0-9]{2})*$")

    @staticmethod
    def fits(line):
        return EventChunk.reg_exp.match(line) is not None


class EventFactory:
    classes = [EventFuncEntry, EventFuncExit, EventMLE, EventMAC, EventARP, EventChunk]

    @staticmethod
    def get_event(line):
        for cl in EventFactory.classes:
            if cl.fits(line):
                return cl(line)
        return Event(line)


class LogInst:
    def __init__(self, line):
        tokens = [x.strip() for x in line.split('\t')]
        self.timestamp = datetime.strptime(tokens[0], '%d/%m/%y %H:%M:%S.%f')
        self.process_id = int(tokens[1], 16)
        self.thread_id = int(tokens[2], 16)
        self.driver = tokens[3][1:-1]
        self.event = EventFactory.get_event(tokens[4])
        self.depth = 0

    def same_log(self, other):
        return self.thread_id == other.thread_id and self.process_id == other.process_id \
               and self.driver == other.driver and (other.timestamp - self.timestamp).total_seconds() <= 1

    def to_str(self, incl_tmst=True, incl_procthr=True, incl_driver=True):
        res = []
        if incl_tmst:
            res.append("{0:%d/%m/%y %H:%M:%S.%f}".format(self.timestamp)[:-3])
        if incl_procthr:
            res.extend([format(self.process_id, '04x'), format(self.thread_id, '04x')])
        if incl_driver:
            res.append('[' + str(self.driver).ljust(6) + ']')
        res.append(self.event.to_str(tabs=self.depth, incl_chunks=False,
                                     chunk_spacing="\t".join([' ' * len(x) for x in res])))
        return "\t".join(res)

    def __str__(self):
        return self.to_str()


class NodeLog:
    def __init__(self):
        self.log_arr = []
        self.process_id = 0
        self.thread_id = 0
        self.rloc16 = None

    def get_id(self):
        return "_".join(["none" if self.rloc16 is None else format(self.rloc16, "04x"),
                         format(self.process_id, '04x'), format(self.thread_id, '04x')])

    def add(self, log):
        self.log_arr.append(log)
        self.thread_id = log.thread_id
        self.process_id = log.process_id
        if log.event.rloc16 is not None:
            self.rloc16 = log.event.rloc16

    def calc_depths(self):
        balance, min_bal = 0, 0
        for log in self.log_arr:
            log.depth = balance
            if log.event.type == Event.EventType.ENTER_FUNC:
                balance += 1
            elif log.event.type == Event.EventType.EXIT_FUNC:
                log.depth = balance = balance - 1
                min_bal = min(min_bal, balance)
        for log in self.log_arr:
            log.depth -= min_bal

    def write_file(self, path):
        self.calc_depths()
        f = open(os.path.join(path, self.get_id() + ".txt"), 'w+')
        for log in self.log_arr:
            f.write(log.to_str(incl_procthr=False) + '\n')
        f.close()


class Parser:
    def __init__(self):
        self.log_arr = []

    def add_line(self, line):
        # print(line)
        log = LogInst(line)
        if log.event.type == Event.EventType.CHUNK:
            for i in range(len(self.log_arr)-1, -1, -1):
                if self.log_arr[i].same_log(log):
                    self.log_arr[i].event.add_chunk(log.event)
                    break
        else:
            self.log_arr.append(log)

    def get_by_procthr(self):
        logs = {}
        for l in self.log_arr:
            if l.thread_id not in logs:
                logs[l.thread_id] = NodeLog()
            logs[l.thread_id].add(l)
        return logs

    def flush_files(self, path):
        path = os.path.join(path, "parsed")
        if not os.path.exists(path):
            os.makedirs(path)
        logs = self.get_by_procthr()
        for key in logs:
            logs[key].write_file(path)


if len(sys.argv) > 1:
    filepath = sys.argv[1]
else:
    filepath = input("Enter filename: ")
path = os.path.dirname(filepath)

sys.stdout = open(os.path.join(path, "stdout.txt"), 'w')
print(filepath)
f = open(filepath, 'r')
parser = Parser()
for line in f:
    parser.add_line(line.strip())
    # print(line, end='')
f.close()
parser.flush_files(path)
