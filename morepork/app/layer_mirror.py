from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER, DEAD_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.lib import hub

from morepork.app import layer_tripwire

class MirrorLayer(layer_tripwire.TripwireLayer):

    mirror_table_id = 1
    mirror_port = 3 # TODO make this configurable
    mirror_map = {}

    def __init__(self, *args, **kwargs):
        super(MirrorLayer, self).__init__(*args, **kwargs)

    def get_mirror_ports(self):
        return self.mirror_in_ports

    def add_mirror_port(self, dpid, in_port):
        '''
        Add action to mirror traffic to the mirror port,
        then go to the switch table to forward the traffic
        normally.
        '''
        datapath = self.datapaths[dpid]
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        match = parser.OFPMatch(in_port=in_port)

        actions = [parser.OFPActionOutput(self.mirror_port)]
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
            actions), parser.OFPInstructionGotoTable(self.tripwire_table_id)]
        mod = parser.OFPFlowMod(datapath=datapath, priority=1,
            match=match, instructions=inst, table_id=self.mirror_table_id)
        datapath.send_msg(mod)

        self.logger.warning('Added port mirror %d --> %d on datapath %x', 
            in_port, self.mirror_port, dpid)

    def remove_mirror_port(self, dpid, in_port):
        datapath = self.datapaths[dpid]
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        match = parser.OFPMatch(in_port=in_port)

        mod = parser.OFPFlowMod(datapath=datapath, match=match,
            command=ofproto.OFPFC_DELETE, table_id=self.mirror_table_id,
            out_port=ofproto.OFPP_ANY, out_group=ofproto.OFPG_ANY)
        datapath.send_msg(mod)

        self.logger.warning('Removed port mirror %d --> %d on datapath %x',
            in_port, self.mirror_port, dpid)

    def update_mirror_ports(self, wires):
        new_map = {}
        for wire in wires:
            if wire.dpid not in new_map:
                new_map[wire.dpid] = {}

            if wire.port_no not in new_map[wire.dpid]:
                new_map[wire.dpid][wire.port_no] = wire.tripped

            if (not new_map[wire.dpid][wire.port_no] and
                wire.tripped):
                new[wire.dpid][wire.port_no] = True

        old_map = self.mirror_map
        for dpid, ports in new_map.iteritems():
            for port_no, tripped in ports.iteritems():
                if dpid not in old_map:
                    old_map[dpid] = {}

                if port_no not in old_map[dpid]:
                    old_map[dpid][port_no] = False

                if tripped and not old_map[dpid][port_no]:
                    self.add_mirror_port(dpid, port_no)
                elif not tripped and old_map[dpid][port_no]:
                    self.remove_mirror_port(dpid, port_no)
                # else if new=true and old=true
                # => already port mirroring
                # else if new=false and old=false
                # => never tripped

        self.mirror_map = new_map

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        super(MirrorLayer, self).switch_features_handler(ev)

        datapath = ev.msg.datapath
        self.add_default_flow(datapath, self.mirror_table_id, self.tripwire_table_id)

    @set_ev_cls(ofp_event.EventOFPPortStatsReply, MAIN_DISPATCHER)
    def _port_stats_reply_handler(self, ev):
        super(MirrorLayer, self)._port_stats_reply_handler(ev)

        wires = self.tripwire.process_port_stats()
        self.update_mirror_ports(wires)
