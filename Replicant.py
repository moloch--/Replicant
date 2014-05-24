#!/usr/bin/env python
'''
@author: Moloch
@copyright: GPLv3
@version: 0.5
--------------------

Replicant is an IRC bot that cracks passwords

'''

import re
import os
import sys
import time
import gevent
import logging


from IRC import IrcBot


### Bot
class Replicant(IrcBot):
    '''
    IRC Bot
    '''

    is_muted = False
    plugins = {}

    def __init__(self, settings):
        '''
        Because twisted is fucking stupid and won't let you use super/init
        '''
        self.logger = settings['logger']
        self.bot_cmds = {
            #"!status": self.status,
            "!plugins": self.plugins,
            #"!history": self.history,
            "!help": self.help,
            #"!stfu": self.mute,
            #"!mute": self.mute,
            "!about": self.about,
        }
        self._load_plugins()
        super(Replicant, self).__init__(settings)

    def _load_plugins(self):
        '''
        Load plugin modules from config, note that we do not instantiate
        the plugin class until it is called by a user.
        '''
        import plugins
        for index, name in enumerate(plugins.__all__):
            module = getattr(plugins, name)
            if not hasattr(module, 'Plugin'):
                self._log_warning("No `Plugin` class found in module '%s'" % module)
            else:
                plugin = module.Plugin()
                self.plugins["!" + plugin.cmd] = plugin
                self._log_info("Successfully loaded plugin #%d '%s'" % (index + 1, plugin.name))

    ##################################################################################
    # Messages
    ##################################################################################
    def privmsg(self, nick, channel, msg):
        ''' This will get called when the bot receives a message '''
        if msg.startswith('!'):
            self._parse_bot_cmd(nick, channel, msg)

    def _parse_bot_cmd(self, nick, channel, msg):
        ''' Parse a bot command '''
        bot_cmd = msg.split(" ")[0]
        msg = ' '.join(msg.split(' ')[1:])
        if bot_cmd in self.bot_cmds:
            self.bot_cmds[bot_cmd](nick, channel, msg)
        elif bot_cmd in self.plugins:
            self.execute_plugin(nick, channel, msg, self.plugins[bot_cmd])
        else:
            self.say(channel, "Not a valid command, see !help")

    def execute_plugin(self, nick, channel, msg, plugin):
        pass

    ##################################################################################
    # Command Implemenations
    ##################################################################################
    def about(self, nick, channel, msg):
        ''' says version information '''
        self.say(channel, "  +---------------------------------------+")
        self.say(channel, "  |  Replicant IRC Bot v0.5 - By Moloch   |")
        self.say(channel, "  +---------------------------------------+")
        self.say(channel, "    https://github.com/moloch--/Replicant  ")

    def help(self, nick, channel, msg):
        ''' says a helpful message '''
        self.say(channel, " > Commands: Replicant IRC Bot ")
        self.say(channel, "--------------------------------------")
        self.say(channel, " !about - Show version information")
        self.say(channel, " !help - Show this helpful message")
        self.say(channel, "----------[Cracking Plugins]----------")
        for plugin in self.plugins.itervalues():
            self.say(channel, "[%s] !%s - %s" % (plugin.name, plugin.cmd, plugin.help))
        self.say(channel, "--------------------------------------")

### Main
if __name__ == '__main__':
    logger = logging.getLogger('irc')
    logger.setLevel(logging.DEBUG)
    ch = logging.StreamHandler()
    ch.setLevel(logging.DEBUG)
    formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    ch.setFormatter(formatter)
    logger.addHandler(ch)
    settings = {
        'server': 'irc.freenode.net',
        'nick': 'replicant_bot',
        'realname': 'Replicant',
        'port': 6667,
        'ssl': False,
        'channels': ['#crackerbot',],
        'logger': logger,
    }
    bot = lambda: Replicant(settings)
    jobs = [gevent.spawn(bot)]
    gevent.joinall(jobs)
