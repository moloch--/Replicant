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
import logging
import sqlite3
import ConfigParser

from datetime import datetime
from Queue import PriorityQueue
from argparse import ArgumentParser
from string import ascii_letters, digits
from twisted.application import internet
from twisted.words.protocols import irc
from twisted.internet import reactor, protocol


### Channel
class ChannelSettings(object):

    is_muted = False

    def __init__(self, name, password=None, ignore=False):
        if name[0] == '&' or ignore:
            self.name = name
        else:
            self.name = "#" + name
        if password is None or password.lower() == '__none__':
            self.password = None
        else:
            self.password = password

    def __eq__(self, other):
        return self.name == str(other)

    def __ne__(self, other):
        return not self == other

    def __str__(self):
        return self.name


### Bot
class Replicant(irc.IRCClient):
    '''
    IRC Bot
    '''

    nickname = "replicant"
    realname = "replicant"
    channels = {}
    is_muted = False
    plugins = {}
    defaults = {
        'level': 'debug',
        'nickname': "replicant",
        'realname': "replicant",
        'debug': 'off',
    }

    def initialize(self):
        '''
        Because twisted is fucking stupid and won't let you use super/init
        '''
        self.commands = {
            "!status": self.status,
            "!plugins": self.plugins,
            "!history": self.history,
            "!help": self.help,
            "!stfu": self.mute,
            "!mute": self.mute,
            "!about": self.about,
        }
        self._load_plugins()

    ##################################################################################
    # Configuration stuffs
    ##################################################################################
    def config(self, filename="replicant.cfg"):
        ''' Load settings from config file '''
        logging.debug('Loading config from: %s' % filename)
        config = ConfigParser.SafeConfigParser(self.defaults)
        with open(filename, 'r') as fp:
            config.readfp(fp)
            self._logging_config(config)
            self._bot_config(config)
            self._channels(config)

    def _logging_config(self, config):
        ''' Configure logging module '''
        logLevel = config.get("Logging", 'level')
        if logLevel.lower() == 'debug':
            logging.getLogger().setLevel(logging.DEBUG)
        elif logLevel.lower().startswith('warn'):
            logging.getLogger().setLevel(logging.WARNING)
        elif logLevel.lower() == 'error':
            logging.getLogger().setLevel(logging.ERROR)
        elif logLevel.lower() == 'critical':
            logging.getLogger().setLevel(logging.CRITICAL)
        else:
            logging.getLogger().setLevel(logging.INFO)

    def _bot_config(self, config):
        ''' Configure system settings '''
        self.nickname = config.get("System", 'nickname')
        logging.debug('Config system bot nickname (%s)' % self.nickname)
        self.realname = config.get("System", 'realname')
        logging.debug('Config system bot realname (%s)' % self.realname)
        self.debug = config.getboolean("System", 'debug')
        logging.debug('Config system debug mode (%s)' % str(self.debug))

    def _load_plugins(self, config):
        '''
        Load plugin modules from config, note that we do not instantiate
        the plugin class until it is called by a user.
        '''
        for item in config.items("Plugins"):
            logging.info("Loading plugin '%s' from '%s'" % (item[0], item[1]))
            if os.path.exists(item[1]):
                self.plugins[item[0]] = __import__(item[1])
            logging.warning("Plugin does not exist at: %s" % item[1])

    def _channels(self, config):
        ''' Read channels to join from config file '''
        self.channel_pairs = config.items("Channels")

    ##################################################################################
    # Messages
    ##################################################################################
    def privmsg(self, nick, channel, msg):
        ''' This will get called when the bot receives a message '''
        if msg.startswith('!'):
            nick = nick.split('!', 1)[0].lower()
            if channel == self.nickname:
                channel = nick
            self.parseCommand(nick, channel, msg)

    def parseCommand(self, user, channel, msg):
        ''' Parse command, call functions '''
        command = msg.split(" ")[0]
        msg = ' '.join(msg.split(' ')[1:])
        if command in self.commands:
            self.commands[command](user, channel, msg)
        elif command in self.plugins:
            plugin = self.plugins[command]()
            self.executePlugin(user, channel, msg, plugin)
        else:
            self.display(user, channel, "Not a command, see !help")

    def executePlugin(self, user, channel, msg, plugin):
        pass

    ##################################################################################
    # Command Implemenations
    ##################################################################################
    def plugins(self, user, channel, msg):
        ''' List currently loaded plugins '''
        for name in self.plugins:
            plugin = self.plugins[name]
            self.display(user, channel, "!%s - %s" % (plugin.name, plugin.description))

    def status(self, user, channel, msg):
        ''' Responds with bot status of plugins '''
        if self.is_busy:
            self.display(user, channel, "I am currently cracking passwords.")
        else:
            self.display(user, channel, "I am currently idle, give me something to crack!")

    def mute(self, user, channel, msg):
        ''' Toggle mute on/off '''
        chan_settings = self.channels.get(channel, None)
        if chan_settings is not None:
            if chan_settings.is_muted:
                chan_settings.is_muted = False
                self.display(user, channel, "Mute: OFF - Responses will be public")
            else:
                self.display(user, channel, "Mute: ON - Responses will be private")
                chan_settings.is_muted = True
        else:
            self.display(user, channel, "Cannot mute this channel.")

    def about(self, user, channel, msg):
        ''' Displays version information '''
        self.display(user, channel, "  +---------------------------------------+")
        self.display(user, channel, "  |  Replicant IRC Bot v0.5 - By Moloch   |")
        self.display(user, channel, "  +---------------------------------------+")
        self.display(user, channel, "    https://github.com/moloch--/Replicant  ")

    def help(self, user, channel, msg):
        ''' Displays a helpful message '''
        self.display(user, channel, " > Commands: Replicant IRC Bot ", whisper=True)
        self.display(user, channel, "-------------------------------------", whisper=True)
        self.display(user, channel, " !login <password>: Authenticate as your current nick; must be pm'd", whisper=True)
        self.display(user, channel, " !plugins: List available cracking plugins", whisper=True)
        self.display(user, channel, " !crack -plugin <plugin> -hashes <hash1,hash2>: Crack a list of hashes", whisper=True)
        self.display(user, channel, " !help [all] - Display this helpful message", whisper=True)
        if msg.lower() == 'all':
            self.display(user, channel, " !mute - Send all responses via pm", whisper=True)
            self.display(user, channel, " !status - Checks if the bot is busy", whisper=True)
            self.display(user, channel, " !jobs - Display the current queue size", whisper=True)
            self.display(user, channel, " !history (count) - Display your history", whisper=True)
            self.display(user, channel, " !create <password> - Create new user, with a password", whisper=True)
            self.display(user, channel, " !about - View version information", whisper=True)


    ##################################################################################
    # Internals
    ##################################################################################
    def connectionMade(self):
        ''' When we make a succesful connection to a server '''
        irc.IRCClient.connectionMade(self)

    def connectionLost(self, reason):
        ''' Auto-reconnect on dropped connections '''
        irc.IRCClient.connectionLost(self, reason)
        self.authenticated_users.clear()
        logging.warn("Disconnected %s" % str(datetime.now()))

    def signedOn(self):
        ''' Called when bot has succesfully signed on to server '''
        if not os.path.exists("replicant.db"):
            self._dbinit()
        if not 0 < len(self.channel_pairs):
            logging.warning("No channels to join.")
        for key_pair in self.channel_pairs:
            channel = ChannelSettings(key_pair[0], key_pair[1])
            self.channels[channel.name] = channel
            if channel.password is None:
                self.join(channel.name)
            else:
                self.join(channel.name, channel.password)

    def joined(self, channel):
        ''' Called when the bot joins the channel '''
        logging.info("Joined channel '%s'" % channel)
        self.display(self.nickname, channel, "My name is %s, I have come to destroy you." % self.nickname)

    def alterCollidedNick(self, nickname):
        ''' Avoids name collisions '''
        logging.info("Nickname collision; chaned to: ^%r" % nickname)
        return nickname + '^'

    def display(self, user, channel, message, whisper=False):
        ''' Intelligently wraps msg, based on mute setting '''
        chan_settings = self.channels.get(channel, None)
        if whisper or (chan_settings is not None and chan_settings.is_muted):
            display_chan = user
        else:
            display_chan = channel
        self.msg(display_chan, message.encode('ascii', 'ignore'))

    def joinChannel(self, user, channel, msg):
        ''' Admin command to get bot to join channel '''
        new_chan = msg.split(" ")
        if len(new_chan) < 2:
            new_chan.append(None)
        channel = ChannelSettings(new_chan[0], new_chan[1])
        self.channels[channel.name] = channel
        if channel.password is None:
            self.join(channel.name)
        else:
            self.join(channel.name, channel.password)
        logging.info("Joined channel %s" % channel.name)

    def leaveChannel(self, user, channel, msg):
        ''' Admin command to leave a channel '''
        logging.info("Leaving channel: %s", msg)
        self.leave(msg, reason="I'll be back...")

### Factory
class ReplicantFactory(protocol.ClientFactory):
    '''
    Twisted IRC bot factory
    '''

    def buildProtocol(self, addr):
        ''' Creates factory '''
        bot = Replicant()
        bot.initialize()
        bot.config(self.configFilename)
        logging.info("Replicant IRC Bot Starting...")
        bot.factory = self
        return bot

    def clientConnectionLost(self, connector, reason):
        ''' If we get disconnected, reconnect to server. '''
        connector.connect()

    def clientConnectionFailed(self, connector, reason):
        ''' When connection fails '''
        logging.warn("Connection failed: " + str(reason))
        reactor.stop()

### Main
if __name__ == '__main__':
    logging.basicConfig(
        format = '\r\033[1m[%(levelname)s]\033[0m %(asctime)s - %(message)s',
        level=logging.INFO)
    factory = ReplicantFactory()
    if 1 < len(sys.argv):
        parser = ArgumentParser(
            description="Password cracking IRC bot.")
        parser.add_argument("server",
            metavar="SERVER",
            help="IRC server to connect to.")
        parser.add_argument("-p", "--port",
            type=int,
            default=6667,
            dest='port',
            help="Port number to connect to.")
        parser.add_argument("-c", "--config",
            metavar="CONFIG",
            default="replicant.cfg",
            dest="configFilename",
            help="Path to config file.")
        args = parser.parse_args()
        factory.configFilename = args.configFilename
        reactor.connectTCP(args.server, args.port, factory)
    elif os.path.exists("replicant.cfg"):
        config = ConfigParser.SafeConfigParser({'port': '6667'})
        config.readfp(open("replicant.cfg", 'r'))
        factory.configFilename = "replicant.cfg"
        server = config.get("Server", 'domain')
        port = config.getint("Server", 'port')
        reactor.connectTCP(server, port, factory)
    else:
        print(value'No config file or args; see --help')
        os._exit(1)
    reactor.run()
