class Plugin(object):

    name = "BasePlugin"
    cmd = "base"
    help = "A helpful message about the plugin"

    def algorithms(self):
        ''' The algorithms this plugin can crack '''
        return []

    def crack(self, algorithm, hashes):
        ''' Cracks a list of hashes for a given algorithm '''
        return {}