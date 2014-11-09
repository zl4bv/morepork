import collections
import re
import socket
from ryu.lib import hub

from morepork.ids import idsbase

class SecurityOnion(idsbase.IdsBase):
    
    def __init__(self, logger):
        super(SecurityOnion, self).__init__()
        self.logger = logger
        self._alert_regex = re.compile('^<\d{2}>\w{3}\s+\d{1,2}\s\d\d:\d\d:\d\d (?P<server>[\w\-]+) sguil_alert: .*Alert Received: \d \d (?P<category>[\w\-]+) (?P<sensor>[\w\-]+) {(?P<date>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})}.*{(?P<signature>.*?)} (?P<src_ip>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}) (?P<dst_ip>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}) (?P<proto>\d+) (?P<src_port>\d+) (?P<dst_port>\d+) (?P<pid>\d+) (?P<sid>\d+)')
        self._alert_class = collections.namedtuple('IdsAlert',
            ['category', 'src_port', 'signature', 'pid', 'server', 
            'src_ip', 'dst_port', 'sid', 'date', 'dst_ip', 
            'sensor', 'proto'])

    def listen(self, address, port):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind((address, port))
        self.ids_thread = hub.spawn(self._server_loop)

    def parse_event(self, data):
        self.logger.info('IDS Alert: '+data)
        m = self._alert_regex.search(data)
        if not m: return None
        alert = self._alert_class(**m.groupdict())
        return alert

    def _server_loop(self):
        self.logger.info('Listening for alerts from IDS')
        while True:
            data, address = self.sock.recvfrom(4096)
            if not data: continue
            alert = self.parse_event(data)
            if not alert: continue
            self.ids_alert_fire(alert)
