#!/usr/bin/env python
'''
@author: Moloch
@copyright: GPLv3
@version: 0.4
--------------------
Replicant is an IRC bot that implements the RCrackPy interface
to automatically crack passwords using rainbow tables.

Everything is in one file for portability.

'''

import re
import os
import sys
import time
import thread
import logging
import sqlite3
import ConfigParser
import RainbowCrack

from hashlib import sha256
from random import randint
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

    jobQueue = PriorityQueue()
    nickname = "replicant"
    realname = "replicant"
    authenticated_users = set()
    is_busy = False
    channels = {}
    char_whitelist = ascii_letters[:6] + digits + ":"
    is_muted = False
    defaults = {
        'level': 'debug',
        'lm': '.',
        'ntlm': '.',
        'md5': '.',
        'wordlist_path': '.',
        'nickname': "replicant",
        'realname': "replicant",
        'debug': 'off',
        'threads': '2',
    }

    def initialize(self):
        '''
        Because twisted is fucking stupid and won't let you use super/init
        '''
        self.public_commands = {
            "!help": self.help,
            "!mute": self.muteBot,
            "!stfu": self.muteBot,
            "!about": self.about,
            "!status": self.checkStatus,
        }
        self.user_commands = {
            "!md5":
            "!ntlm":
            "!lm":
            "!jobs":
            "!history":
        }

    def _dbinit(self):
        ''' Initializes the SQLite database '''
        logging.info("Initializing SQLite db ...")

    def config(self, filename="replicant.cfg"):
        ''' Load settings from config file '''
        logging.info('Loading config from: %s' % filename)
        config = ConfigParser.SafeConfigParser(self.defaults)
        config.readfp(open(filename, 'r'))
        self._logging_config(config)
        self._tables_config(config)
        self._bot_config(config)
        self._channels(filename)

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

    def _tables_config(self, config):
        ''' Load paths to rainbow tables '''
        self.LM_TABLES = os.path.abspath(config.get("RainbowTables", 'lm'))
        logging.info('Config LM tables (%s)' % self.LM_TABLES)
        self.NTLM_TABLES = os.path.abspath(config.get("RainbowTables", 'ntlm'))
        logging.info('Config NTLM tables (%s)' % self.NTLM_TABLES)
        self.MD5_TABLES = os.path.abspath(config.get("RainbowTables", 'md5'))
        logging.info('Config MD5 tables (%s)' % self.MD5_TABLES)

    def _bot_config(self, config):
        ''' Configure system settings '''
        self.nickname = config.get("System", 'nickname')
        logging.info('Config system bot nickname (%s)' % self.nickname)
        self.realname = config.get("System", 'realname')
        logging.info('Config system bot realname (%s)' % self.realname)
        self.debug = config.getboolean("System", 'debug')
        logging.info('Config system debug mode (%s)' % str(self.debug))
        self.threads = config.getint("System", 'threads')
        logging.info('Config system thread count (%d)' % self.threads)
        self.admin_hash = config.get("System", 'admin_sha256').replace(' ', '')

    def _channels(self, filename):
        ''' Read channels to join from config file '''
        config = ConfigParser.SafeConfigParser()
        config.readfp(open(filename, 'r'))
        self.channel_pairs = config.items("Channels")

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

    def userQuit(self, nick, channel):
        ''' Called when a user quits '''
        user = User.by_nick(nick)
        if user is not None:
            self.logout_user(user, channel, "")

    def userRenamed(self, oldname, newname):
        ''' Called when a user renames themselves '''
        user = User.by_nick(oldname)
        if user is not None:
            self.logout_user(user, channel, "")

    def privmsg(self, nick, channel, msg):
        ''' This will get called when the bot receives a message '''
        nick = nick.split('!', 1)[0].lower()
        if channel == self.nickname:
            channel = nick
        if msg.startswith("!"):
            user = User.by_nick(nick)
            if user is not None and user.uuid in self.authenticated_users:
                self.parseCommand(user, channel, msg)
            elif user is not None and msg.startswith('!login'):
                self.login_user(user, channel, msg)
            elif user is None and msg.startswith('!create'):
                self.create_user(user, channel, msg)
            elif msg[:msg.index(' ')] in self.public_commands:
                self.parsePublicCommand(nick, channel, msg)
            else:
                resp = "You must authenticate to use a command"
                self.display(nick, channel, resp)

    def create_user(self, nick, channel, msg):
        ''' Create a new user in the database '''
        if channel == nick:
            passwd = msg[len('!create '):]
            if 8 <= len(passwd):
                new_user = User(nick=nick, password=)
                dbsession.add(new_user)
                dbsession.flush()
                resp = "New user created succesfully, use !login to authenticate"
                self.display(nick, channel, resp, whisper=True)
            else:
                resp = "Your password is too short, must be 8+ chars"
                self.display(nick, channel, resp, whisper=True)
        else:
            self.display(nick, channel, "Passwords must be sent via private message")

    def login_user(self, user, channel, msg):
        ''' Authenticate a user '''
        if user.validate_password(msg[len('!login '):]):
            self.authenticated_users.add(user.uuid)
        else:
            resp = "Authentication failure, try again"
            self.display(user, channel, resp)

    def logout_user(self, user, channel, msg):
        if user.uuid in self.authenticated_users:
            self.authenticated_users.remove(user.uuid)

    def parseCommand(self, user, channel, msg):
        ''' Parse command, call functions '''
        command = msg.split(" ")[0]
        msg = ' '.join(msg.split(' ')[1:])
        if command in self.public_commands:
            logging.debug("[Command]: <Nick: %s> <Channel: %s> <Msg: %s>" % (
                user, channel, msg))
            self.public_commands[command](user, channel, msg)
        else:
            self.display(user, channel, "Not a command, see !help")

    def md5(self, user, channel, msg):
        ''' Gathers the md5 hashes into a list '''
        hashes = self.splitMsg(msg)
        hashes = filter(lambda hsh: len(hsh) == 32, hashes)
        if 0 < len(hashes):
            self.dispatch(user, channel, msg, hashes, self.MD5_TABLES, 'md5')
        else:
            self.display(user, channel, "%s: Found zero hashes in request" % user)

    def ntlm(self, user, channel, msg):
        ''' Gathers the ntlm hashes into a list '''
        hashes = self.splitMsg(msg)
        if 0 < len(hashes):
            self.dispatch(user, channel, msg, hashes, self.NTLM_TABLES, 'ntlm')
        else:
            self.display(user, channel, "%s: Found zero hashes in request" % user)

    def lm(self, user, channel, msg):
        ''' Gathers the ntlm hashes into a list '''
        hashes = self.splitMsg(msg)
        if 0 < len(hashes):
            self.dispatch(user, channel, msg, hashes, self.LM_TABLES, 'lm')
        else:
            self.display(user, channel, "%s: Found zero hashes in request" % user)

    def splitMsg(self, msg):
        ''' Splits message into a list of hashes, filters non-white list chars '''
        clean_hashes = []
        msg = msg.lower().replace(' ', ',')
        hashes = filter(lambda hsh: 0 < len(hsh), msg.split(","))
        if 0 < len(hashes):
            for hsh in hashes:
                hsh = filter(lambda char: char in self.char_whitelist, hsh)
                clean_hashes.append(hsh)
        return hashes

    def dispatch(self, user, channel, msg, hashes, path, algo, priority=1):
        ''' Starts cracking jobs, or pushes the job onto the queue '''
        if not self.is_busy:
            self.display(user, channel,
                "Starting new job for %s; cracking %d hash(es)" % (user, len(hashes),))
            thread.start_new_thread(self._crack, (user, channel, msg, hashes, path, algo,))
        else:
            self.display(user, channel,
                "Queued job for %s with %d hash(es)" % (user, len(hashes),))
            logging.info("Job in progress, pushing to queue")
            self.jobQueue.put(
                (priority, (user, channel, msg, hashes, path, algo,),)
            )

    def _crack(self, user, channel, msg, hashes, path, algo):
        ''' Cracks a list of hashes '''
        self.isBusy = True
        work = list(hashes)
        logging.info("Cracking %d hashes for %s" % (len(hashes), user))
        results = self._rcrack(user, channel, msg, work, algo)
        logging.info("Job compelted for %s" % user)
        self.display(user, channel, "Job completed for %s; cracked %d of %d hashes." % (
            user, cracked_count, len(hashes),))
        self._next()

    def _rcrack(self, user, channel, msg, work, algo):
        ''' Call RainbowCrack via RCrackPy '''
        self.display(user, channel, "Cracking %d %s hash(es) with rainbow tables" % (
            len(work), algo,))
        results = {}
        try:
            results = RainbowCrack.crack(work, path, debug=self.debug, maxThreads=self.threads)
            self.saveResults(user, channel, results)
        except ValueError:
            logging.exeception("Error while cracking hashes ... ")
        finally:
            return results

    def _next(self):
        ''' Pop the next job off the queue or stop cracking '''
        if 0 < self.jobQueue.qsize():
            job = self.jobQueue.get()
            logging.info("Popping job off queue, %d job(s) remain " % self.jobQueue.qsize())
            thread.start_new_thread(self.__crack__, job[1])
        else:
            self.is_busy = False

    def saveResults(self, user, channel, results):
        ''' Save results in database and send to user '''
        pass

    def checkStatus(self, user, channel, msg):
        ''' Responds with bot status '''
        if self.is_busy:
            self.display(user, channel, "I am currently cracking passwords.")
        else:
            self.display(user, channel, "I am currently idle, give me something to crack!")

    def checkJobs(self, user, channel, msg):
        ''' Displays the current number of queued jobs '''
        current = '.'
        if self.is_busy:
            current = ', and one in progress.'
        self.display(user, channel,
            "There are currently %d queued job(s)%s" % (self.jobQueue.qsize(), current,))

    def muteBot(self, user, channel, msg):
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

    def exampleCommands(self, user, channel, msg):
        pass

    def about(self, user, channel, msg):
        ''' Displays version information '''
        self.display(user, channel, "  +---------------------------------------+")
        self.display(user, channel, "  |  Replicant IRC Bot v0.4 - By Moloch   |")
        self.display(user, channel, "  |     RCrackPy v0.1 // CrackPy v0.1     |")
        self.display(user, channel, "  +---------------------------------------+")
        self.display(user, channel, "    https://github.com/moloch--/Replicant  ")

    def help(self, user, channel, msg):
        ''' Displays a helpful message '''
        self.display(user, channel, " > Commands: Replicant IRC Bot ", whisper=True)
        self.display(user, channel, "-------------------------------------", whisper=True)
        self.display(user, channel, " !login <password> - Authenticate as your current nick; must be pm'd", whisper=True)
        self.display(user, channel, " !md5 <hash1,hash2> - Crack a list of Md5 hashes", whisper=True)
        self.display(user, channel, " !ntlm <hash1,hash2> - Crack a list of NTLM hashes", whisper=True)
        self.display(user, channel, " !lm <hash1,hash2> - Crack a list of LM hashes", whisper=True)
        self.display(user, channel, " !example [md5,ntlm,lm] - View example commands", whisper=True)
        self.display(user, channel, " !help [all] - Display this helpful message", whisper=True)
        if msg.lower() == 'all':
            self.display(user, channel, " !mute - Send all responses via pm", whisper=True)
            self.display(user, channel, " !status - Checks if the bot is busy", whisper=True)
            self.display(user, channel, " !jobs - Display the current queue size", whisper=True)
            self.display(user, channel, " !history (count) - Display your history", whisper=True)
            self.display(user, channel, " !create <password> - Create new user, with a password", whisper=True)
            self.display(user, channel, " !about - View version information", whisper=True)

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
