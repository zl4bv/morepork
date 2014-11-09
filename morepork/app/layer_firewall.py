from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER, DEAD_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.lib import hub
from ryu.ofproto import ether
from ryu.ofproto import inet

from morepork.app import layer_mirror
from morepork.ids import securityonion

class FirewallLayer(layer_mirror.MirrorLayer):

    firewall_table_id = 0
    firewall_drops = {}
    ids_listen_address = '0.0.0.0'
    ids_listen_port = 514

    def __init__(self, *args, **kwargs):
        super(FirewallLayer, self).__init__(*args, **kwargs)
        self.ids = securityonion.SecurityOnion(self.logger)
        self.ids.ids_alert_subscribe(self.ids_alert_handler)
        self.ids.listen(self.ids_listen_address, self.ids_listen_port)

    def get_firewall_drops(self):
        return self.firewall_drops

    def add_firewall_drop(self, dpid, ev):
        '''
        If traffic flow should be dropped then add flow rule
        to match that flow and apply no actions. There is no
        goto table instruction to prevent the normal switch
        functions and thus dropping the packet.
        '''
        datapath = self.datapaths[dpid]
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        src_port = int(ev.src_port)
        dst_port = int(ev.dst_port)
        if ev.proto == '6': # TCP
            match = parser.OFPMatch(ipv4_src=ev.src_ip, ipv4_dst=ev.dst_ip, 
                tcp_src=src_port, tcp_dst=dst_port, eth_type=ether.ETH_TYPE_IP,
                ip_proto=inet.IPPROTO_TCP)
            proto = 'TCP'
        elif ev.proto == '17': # UDP
            match = parser.OFPMatch(ipv4_src=ev.src_ip, ipv4_dst=ev.dst_ip, 
                udp_src=src_port, udp_dst=dst_port, eth_type=ether.ETH_TYPE_IP,
                ip_proto=inet.IPPROTO_UDP)
            proto = 'UDP'
        else:
            return

        actions = []
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
            actions)]
        mod = parser.OFPFlowMod(datapath=datapath, priority=1,
            match=match, instructions=inst, table_id=self.firewall_table_id)
        datapath.send_msg(mod)

        self.logger.warning('Adding entry to drop traffic flow %s %s:%s --> %s:%s on datapath %x',
            proto, ev.src_ip, ev.src_port, ev.dst_ip, ev.dst_port, dpid)

    def remove_firewall_drop(self, dpid, match):
        datapath = self.datapaths[dpid]
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        mod = parser.OFPFlowMod(datapath=datapath, match=match,
            command=ofproto.OFPFC_DELETE, table_id=self.firewall_table_id,
            out_port=ofproto.OFPP_ANY, out_group=ofproto.OFPG_ANY)
        datapath.send_msg(mod)

        self.logger.warning('Removed flow to drop traffic')

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        super(FirewallLayer, self).switch_features_handler(ev)
        
        datapath = ev.msg.datapath
        self.add_default_flow(datapath, self.firewall_table_id, self.mirror_table_id)

    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def _flow_stats_reply_handler(self, ev):
        super(FirewallLayer, self)._flow_stats_reply_handler(ev)

        # Check flow stat threshold for drop flows
        # If stat < threshold
        #    remove_firewall_drop(...)

    def ids_alert_handler(self, ev):
        # Stop the attack on all datapaths
        for dpid in self.datapaths:
            self.add_firewall_drop(dpid, ev)
