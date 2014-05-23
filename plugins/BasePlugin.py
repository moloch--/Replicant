class BasePlugin(object):

    name = "BasePlugin"
    description = "Plugins should implement this interface"

    def algorithms(self):
        ''' The algorithms this plugin can crack '''
        return []

    def crack(self, algorithm, hashes):
        ''' Cracks a list of hashes for a given algorithm '''
        return {}