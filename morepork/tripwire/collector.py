class PortStatsCollector(object):

    store = {}

    def has_dpid(self, dpid):
        '''
        Check if stats for datapath ID exist
        '''
        return dpid in self.store

    def has_port_no(self, dpid, port_no):
        '''
        Check if stats for port exist for a given datapath
        '''
        if not self.has_dpid(dpid):
            return False

        return port_no in self.store[dpid].keys()

    def has_metric(self, dpid, port_no, metric):
        '''
        Check if stats for metric exist for given port and datapath
        '''
        if not self.has_port_no(dpid, port_no):
            return False

        if len(self.store[dpid][port_no]) == 0:
            return False

        return hasattr(self.store[dpid][port_no][0], metric)

    def ports(self, dpid):
        '''
        Gets a list of ports for a given datapath ID
        '''
        if not self.has_dpid(dpid):
            return None

        return self.store[dpid].keys()

    def push(self, dpid, stats):
        '''
        Stores the results from a port stats reply
        '''
        if dpid not in self.store:
            self.store[dpid] = {}

        for set in stats:
            port_no = set.port_no
            if port_no not in self.store[dpid]:
                self.store[dpid][port_no] = []

            self.store[dpid][port_no].append(set)

            # Limit each list size to 2 items
            if len(self.store[dpid][port_no]) > 2:
                del self.store[dpid][port_no][0]

    def last_value(self, dpid, port_no, metric):
        '''
        Gets the last value for a metric
        '''
        if not self.has_metric(dpid, port_no, metric):
            self.logger.warning('Metric not found: %s port_no=%8x dpid=%016x' %
                (metric, port_no, dpid))

        vals = self.__get_datapoints(dpid, port_no, metric)
        if vals is not None:
            return vals[1]

    def order1(self, dpid, port_no, metric):
        '''
        Calculates the 1st-order derivative of a metric
        '''
        if not self.has_metric(dpid, port_no, metric):
            self.logger.warning('Metric not found: %s port_no=%8x dpid=%016x' %
                (metric, port_no, dpid))

        vals = self.__get_datapoints(dpid, port_no, metric)
        if vals is not None:
            return (vals[1] - vals[0]) / vals[2]
        else:
            return 0

    def order2(self, dpid, port_no, metric):
        '''
        Calculates the 2nd-order derivative of a metric
        '''
        if not self.has_metric(dpid, port_no, metric):
            self.logger.warning('Metric not found: %s port_no=%8x dpid=%016x' %
                (metric, port_no, dpid))

        vals = self.__get_datapoints(dpid, port_no, metric)
        if vals is not None:
            return ((vals[1] - vals[0]) / vals[2]) / vals[2]
        else:
            return 0

    def __get_datapoints(self, dpid, port_no, metric):
        '''
        Gets the last two datapoints and time delta
        '''
        if (dpid not in self.store or 
            port_no not in self.store[dpid].keys() ):
            return None

        datasets = self.store[dpid][port_no][-2:]
        if len(datasets) < 2:
            return None

        if (not hasattr(datasets[0], metric) or
            not hasattr(datasets[1], metric)):
            return None

        a = getattr(datasets[0], metric)
        b = getattr(datasets[1], metric)
        dt = datasets[1].duration_sec - datasets[0].duration_sec
        return [a, b, dt]
