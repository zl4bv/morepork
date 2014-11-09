from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER, DEAD_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.lib import hub

from morepork.app import simple_monitor
from morepork.tripwire import collector
from morepork.tripwire import tripwire

class TripwireLayer(simple_monitor.SimpleMonitor):

    tripwire_table_id = 2
    poll_time = 10

    def __init__(self, *args, **kwargs):
        super(TripwireLayer, self).__init__(*args, **kwargs)
        self.collector = collector.PortStatsCollector()
        self.tripwire = tripwire.Tripwire(self.logger, self.collector)

    def add_flow(self, datapath, priority, match, actions):
        '''
        Override method in simple_switch_13 so we can place
        switch flows in the table number of our choosing.
        '''
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]

        mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                match=match, instructions=inst, table_id=self.tripwire_table_id)
        datapath.send_msg(mod)

    def add_default_flow(self, datapath, table_id, goto_table_id=None):
        '''
        Adds a default flow for a table. Default action is
        to goto the next table (specified by goto_table_id).

        The OFPIT_APPLY_ACTIONS instruction may need to be
        added - at least for the last table in the
        pipeline.

        This may or may not interfere with 
        switch_features_handler in simple_switch_13.py,
        although that method does not specify a table id
        so it is unclear which table that applies to - or
        perhaps that is applies when all tables are
        missed.
        '''
        if not goto_table_id: return

        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        match = parser.OFPMatch()

        inst = [parser.OFPInstructionGotoTable(goto_table_id)]
        mod = parser.OFPFlowMod(datapath=datapath, priority=0,
            match=match, instructions=inst, table_id=table_id)

        datapath.send_msg(mod)

    def print_tripwires(self):
        wires = self.tripwire.process_port_stats()
        self.logger.info('datapath         port     '
                            'metric           value         '
                            'threshold     tripped')
        self.logger.info('---------------- -------- '
                            '---------------- ------------- '
                            '------------- -------')
        for item in wires:
            self.logger.info('%016x %8x %16s %13d %13d %7s',
                item.dpid, item.port_no, item.metric, item.value, 
                item.threshold, item.tripped)

        for item in wires:
            if item.tripped:
                self.logger.warning('Tripped: datapath=%x port=%x metric=%s %d >= %d', 
                    item.dpid, item.port_no, item.metric, item.value, 
                item.threshold)

    def _monitor(self):
        '''
        Override method in simple_monitor so we can change
        how often we request stats.
        '''
        while True:
            for dp in self.datapaths.values():
                self._request_stats(dp)
            hub.sleep(self.poll_time)


    @set_ev_cls(ofp_event.EventOFPPortStatsReply, MAIN_DISPATCHER)
    def _port_stats_reply_handler(self, ev):
        super(TripwireLayer, self)._port_stats_reply_handler(ev)
        dpid = ev.msg.datapath.id
        body = ev.msg.body

        self.collector.push(dpid, body)  
        self.print_tripwires() 
