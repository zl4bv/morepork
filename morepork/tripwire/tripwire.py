##############################################
#
# Stage one - port-based threshold detection
#
# Input: instance of the collector class
# Input: name of the config file
# Process: load config file
# Process: extract collector data based on metrics in config file
# Process: compare collector data to thresholds defined in config file
# Output: list of dpids and port numbers that should are over their thresholds
#
# Stage two - port-based and layer 2/3/4 based threshold detection
#
# Same as above, a new collector class will need to be created to store flow-based data
# Config file will also need extending to handle flow-based thresholds
#

import os

from collections import namedtuple
from ryu.controller import event

from morepork.config import configloader

class Tripwire(object):

    ENV_TRIPWIRE_CONF = 'TRIPWIRE_CONF'

    def __init__(self, logger, collector):
        self.logger = logger
        self.collector = collector

        self._load_environment()
        self.CONF = configloader.ConfigLoader.load(self._tripwire_conf)

        self._wire = namedtuple('Wire', 'dpid, port_no, metric, value, threshold, tripped')

    def _load_environment(self):
        if self.ENV_TRIPWIRE_CONF in os.environ:
            self._tripwire_conf = os.environ[self.ENV_TRIPWIRE_CONF]
        else:
            self.logger.error('Environment variable not found: %s' %
                self.ENV_TRIPWIRE_CONF)
            self._tripwire_conf = None

    def process_flow_stats(self):
        '''
        Run threshold checks on flow stats
        '''
        return [] # TODO

    def process_port_stats(self):
        '''
        Run threshold checks on port stats
        '''
        conf = self.CONF.port
        col = self.collector

        results = []

        for dpid, ports in conf.iteritems():
            if not col.has_dpid(dpid): continue

            for port_no, metrics in ports.iteritems():
                if not col.has_port_no(dpid, port_no): continue

                for metric, settings in metrics.iteritems():
                    if not col.has_metric(dpid, port_no, metric): continue

                    if 'threshold' not in settings:
                        self.logger.warning('Threshold not defined for port-based tripwire metric=%s port_no=%8x dpid=%016x' %
                            (metric, port_no, dpid))
                        continue

                    if 'derivative' in settings:
                        derivative = settings['derivative']
                    else:
                        derivative = 0

                    if settings['derivative'] == 2:
                        val = col.order2(dpid, port_no, metric)
                    elif settings['derivative'] == 1:
                        val = col.order1(dpid, port_no, metric)
                    else:
                        val = col.last_value(dpid, port_no, metric)

                    threshold = settings['threshold']
                    tripped = val >= threshold

                    results.append(self._wire(dpid, port_no, metric, val, threshold, tripped))

        return results
