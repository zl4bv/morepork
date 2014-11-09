import zope.event

class IdsBase(object):
    '''
    Interactions with specific IDS solutions should
    be implemented in their own classes that
    inherit this class.
    '''
    
    def ids_alert_subscribe(self, func):
        '''
        Functions that want to receive alerts from the IDS
        should use this method to subscribe.
        '''
        zope.event.subscribers.append(func)

    def ids_alert_fire(self, ev):
        '''
        Classes that inherit this class should use this
        method to notify subscribers that an alert has
        occurred.

        ev should be a Dictionary of fields that contain
        useful information about the alert such as the 
        source and destination addresses.
        '''
        zope.event.notify(ev)
