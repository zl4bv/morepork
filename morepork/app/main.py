import datetime
import os.path

from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER, DEAD_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.lib import hub

from morepork.app import layer_firewall

class MoreporkApp(layer_firewall.FirewallLayer):

    flow_stats_file = 'flow-stats-%s.csv'

    def __init__(self, *args, **kwargs):
        super(MoreporkApp, self).__init__(*args, **kwargs)

        t = datetime.datetime.today()
        self.flow_stats_file = self.flow_stats_file % t.strftime('%s')

        # TODO init config here and replace TRIPWIRE_CONF

    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def _flow_stats_reply_handler(self, ev):
        body = ev.msg.body

        if not os.path.isfile(self.flow_stats_file):
            with open(self.flow_stats_file, 'w') as myfile:
                myfile.write("dpid,in_port,out_port,ipv4_src,ipv4_dst,tcp_src,tcp_dst,udp_src,udp_dst,packet_count,byte_count,duration_sec\n")

        with open(self.flow_stats_file, 'a') as myfile:
            dpid = ev.msg.datapath.id
            for stat in body:
                if 'in_port' in stat.match:
                    in_port = stat.match['in_port']
                else:
                    in_port = ''

                try:
                    out_port = stat.instructions[0].actions[0].port
                except:
                    out_port = ''

                if 'ipv4_src' in stat.match:
                    ipv4_src = stat.match['ipv4_src']
                else:
                    ipv4_src = ''

                if 'ipv4_dst' in stat.match:
                    ipv4_dst = stat.match['ipv4_dst']
                else:
                    ipv4_dst = ''

                if 'tcp_src' in stat.match:
                    tcp_src = stat.match['tcp_src']
                else:
                    tcp_src = ''

                if 'tcp_dst' in stat.match:
                    tcp_dst = stat.match['tcp_dst']
                else:
                    tcp_dst = ''

                if 'udp_src' in stat.match:
                    udp_src = stat.match['udp_src']
                else:
                    udp_src = ''

                if 'udp_dst' in stat.match:
                    udp_dst = stat.match['udp_dst']
                else:
                    udp_dst = ''
                packet_count = stat.packet_count
                byte_count = stat.byte_count
                duration_sec = stat.duration_sec
                myfile.write("%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s\n" % (dpid,in_port,out_port,ipv4_src,ipv4_dst,tcp_src,tcp_dst,udp_src,udp_dst,packet_count,byte_count,duration_sec))

        self.logger.info('Wrote flow stats to %s', self.flow_stats_file)
