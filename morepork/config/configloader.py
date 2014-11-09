import collections
import yaml

class ConfigLoader(object):

    @staticmethod
    def load(filename):
        stream = file(filename, 'r')
        dump = yaml.load(stream)
        Config = collections.namedtuple('Config', dump.keys())
        return Config(**dump)
