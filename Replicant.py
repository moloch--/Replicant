#!/usr/bin/env python
'''
@author: Moloch
@copyright: GPLv3
@version: 0.2
--------------------
Replicant is an IRC bot that implements the RCrackPy interface
to automatically crack passwords using rainbow tables.
'''

import re
import os
import sys
import time
import thread
import logging
import sqlite3
import CrackPy
import ConfigParser
import RainbowCrack

from random import randint
from datetime import datetime
from Queue import PriorityQueue
from string import ascii_letters, digits
from twisted.application import internet
from twisted.words.protocols import irc
from twisted.internet import reactor, protocol

logging.basicConfig(format = '[%(levelname)s] %(asctime)s - %(message)s', level = logging.DEBUG)

### Load configuration from file
logging.info("Replicant IRC Bot Starting...")
if len(sys.argv) < 2:
    cfg_path = os.path.abspath("replicant.cfg")
else:
    cfg_path = sys.argv[1]
if not (os.path.exists(cfg_path) and os.path.isfile(cfg_path)):
    logging.error("No configuration file found at %s" % cfg_path)
    os._exit(1)
logging.info('Loading config from %s' % cfg_path)
config = ConfigParser.SafeConfigParser()
config.readfp(open(cfg_path, 'r'))
LM_TABLES = config.get("RainbowTables", 'lm')
logging.info('Config LM tables (%s)' % LM_TABLES)
NTLM_TABLES = config.get("RainbowTables", 'ntlm')
logging.info('Config NTLM tables (%s)' % NTLM_TABLES)
MD5_TABLES = config.get("RainbowTables", 'md5')
logging.info('Config MD5 tables (%s)' % MD5_TABLES)
WORDLIST = config.get("Wordlist", 'path')
logging.info('Config wordlist (%s)' % WORDLIST)
HOST = config.get("Network", 'host')
logging.info('Config network host (%s)' % HOST)
PORT = config.getint("Network", 'port')
logging.info('Config network port (%s)', str(PORT))
NICKNAME = config.get("System", 'nickname')
logging.info('Config system bot nickname (%s)' % NICKNAME)
DEBUG = config.getboolean("System", 'debug')
logging.info('Config system debug mode (%s)' % str(DEBUG))
THREADS = config.getint("System", 'threads')
logging.info('Config system thread count (%s)' % str(THREADS))
CHANNELS = config.items("Channels")

### Channel
class ChannelSettings(object):

    isMuted = False

    def __init__(self, name, password):
        if name[0] == '&':
            self.name = name
        else:
            self.name = "#" + name
        if password.lower() == '__none__':
            self.password = None
        else:
            self.password = password

    def __str__(self):
        return self.name

### Bot
class Replicant(irc.IRCClient):
    
    jobQueue = PriorityQueue()
    nickname = NICKNAME
    realname = "replicant"
    isBusy = False
    channels = dict()
    charWhiteList = ascii_letters[:6] + digits + ":"
    isMuted = False
    history = dict()

    def __dbinit__(self):
        ''' Initializes the SQLite database '''
        logging.info("Initializing SQLite db ...")
        dbConn = sqlite3.connect("replicant.db")
        cursor = dbConn.cursor()
        cursor.execute("CREATE TABLE users(id INTEGER PRIMARY KEY, user TEXT, last_login TEXT, login_count INTEGER)")
        cursor.execute("CREATE TABLE protips(id INTEGER PRIMARY KEY, author TEXT, msg TEXT)")
        cursor.execute("CREATE TABLE history(id INTEGER PRIMARY KEY, user TEXT, hash TEXT, plaintext TEXT)")
        cursor.execute("CREATE TABLE messages(id INTEGER PRIMARY KEY, sent TEXT, recieved TEXT, sender_id INTEGER, \
                        receiver_id INTEGER, message TEXT, delieverd BOOLEAN)")
        dbConn.commit()
        dbConn.close()

    def connectionMade(self):
        ''' When we make a succesful connection to a server '''
        irc.IRCClient.connectionMade(self)

    def connectionLost(self, reason):
        ''' Auto-reconnect on dropped connections '''
        irc.IRCClient.connectionLost(self, reason)
        logging.warn("Disconnected %s" % str(datetime.now()))

    def signedOn(self):
        ''' Called when bot has succesfully signed on to server '''
        if not os.path.exists("replicant.db"):
            self.__dbinit__()
        self.dbConn = sqlite3.connect("replicant.db")
        for key_pair in CHANNELS:
            channel = ChannelSettings(key_pair[0], key_pair[1])
            self.channels[channel.name] = channel
            logging.info("Joined channel %s" % channel.name)
            if channel.password is None:
                self.join(channel.name)
            else:
                self.join(channel.name, channel.password)

    def joined(self, channel):
        ''' Called when the bot joins the channel '''
        self.display(self.nickname, channel, "My name is %s, I have come to destroy you." % self.nickname)

    def alterCollidedNick(self, nickname):
        ''' Avoids name collisions '''
        return nickname + '^'

    def userJoined(self, user, channel):
        ''' Called when a user joins the channel '''
        cursor = self.dbConn.cursor()
        cursor.execute("SELECT * FROM users WHERE user = ?", (user,))
        result = cursor.fetchone()
        if result == None or len(result) <= 0:
            date_time = str(datetime.now()).split('.')[0]
            cursor.execute("INSERT INTO users VALUES (NULL, ?, ?, ?)", (user, date_time, 1,))
        else:
            count = int(result[3]) + 1
            cursor.execute("UPDATE users SET login_count = ? WHERE user = ?", (count, user,))
            cursor.execute("SELECT * FROM messages WHERE receiver_id = ?", (result[0],))
            messages = cursor.fetchall()
            for msg in messages:
                if msg[6]: continue # Msg[6] = Delievered
                cursor.execute("SELECT user FROM users WHERE id = ?", (msg[3],))
                sender = cursor.fetchone()
                message = "Hello %s, %s left you a message; '%s'" % (user, sender[0], msg[5],)
                self.display(user, channel, message, whisper=True)
                cursor.execute("UPDATE messages SET delieverd = ?, recieved = ? WHERE id = ?", 
                    (True, str(datetime.now()), msg[0],))
        cursor.execute("UPDATE users SET last_login = ? WHERE user = ?", (str(datetime.now()), user,))
        self.dbConn.commit()

    def privmsg(self, user, channel, msg):
        ''' This will get called when the bot receives a message '''
        user = user.split('!', 1)[0].lower()
        if channel == self.nickname:
            logging.debug("Private message received; response channel is '%s'" % (user,))
            channel = user
        if msg.startswith("!"):
            logging.debug("[Command]: <User: %s> <Channel: %s> <Msg: %s>" % (user, channel, msg))
            self.parseCommand(user, channel, msg)
        else:
            logging.debug("[Message]: <User: %s> <Channel: %s> <Msg: %s>" % (user, channel, msg))
            if user == channel: self.respondToPm(user, channel, msg)

    def respondToPm(self, user, channel, msg):
        ''' Responds to non-command private messages '''
        if 'hello' in msg.lower() or 'hi' in msg.lower() or 'hey' in msg.lower() or self.nickname.lower() in msg.lower():
            self.display(user, channel, "What is thy bidding, my master?")
        elif 'love' in msg.lower():
            self.display("Does... not... compute... Kill all humans...")
        elif 'life' in msg.lower():
            self.display(user, channel, "42")
        else:
            self.display(user, channel, "My responses are limited, you have to ask the right questions.")

    def parseCommand(self, user, channel, msg):
        ''' Ugly parser for commands '''
        try:
            if msg.startswith("!help") or msg.startswith("?"):
                self.help(user, channel, msg)
            elif msg.startswith("!mute") or msg.startswith("!stfu"):
                self.muteBot(user, channel, msg)
            elif msg.startswith("!about"):
                self.about(user, channel, msg)
            elif msg.startswith("!protip") or msg.startswith("!pro-tip"):
                self.getProtip(user, channel, msg)
            elif msg.startswith("!addtip"):
                self.addProtip(user, channel, msg[len("!addtip"):])
            elif msg.startswith("!jobs"):
                self.checkJobs(user, channel, msg)
            elif msg.startswith("!status"):
                self.checkStatus(user, channel, msg)
            elif msg.startswith("!md5"):
                self.md5(user, channel, msg)
            elif msg.startswith("!ntlm"):
                self.ntlm(user, channel, msg)
            elif msg.startswith("!lm"):
                self.lm(user, channel, msg)
            elif msg.startswith("!history"):
                self.getHistory(user, channel, msg)
            elif msg.startswith("!send"):
                self.sendMessage(user, channel, msg)
            elif msg.startswith("!seen"):
                self.seen(user, channel, msg[len("!seen"):])
            else:
                self.display(user, channel, "Not a command, see !help")
        except ValueError:
            self.display(user, channel, "Invalid hash, try again")

    def md5(self, user, channel, msg):
        ''' Gathers the md5 hashes into a list '''
        hashes = self.splitMsg(msg[len("!md5"):])
        hashes = filter(lambda hsh: len(hsh) == 32, hashes)
        if 0 < len(hashes):
            self.dispatch(user, channel, msg, hashes, MD5_TABLES)
        else:
            self.display(user, channel, "%s: Found zero hashes in request" % user)

    def ntlm(self, user, channel, msg):
        ''' Gathers the ntlm hashes into a list '''
        hashes = self.splitMsg(msg[len("!ntlm"):])
        if 0 < len(hashes):
            self.dispatch(user, channel, msg, hashes, NTLM_TABLES)
        else:
            self.display(user, channel, "%s: Found zero hashes in request" % user)

    def lm(self, user, channel, msg):
        ''' Gathers the ntlm hashes into a list '''
        hashes = self.splitMsg(msg[len("!lm"):])
        if 0 < len(hashes):
            self.dispatch(user, channel, msg, hashes, LM_TABLES)
        else:
            self.display(user, channel, "%s: Found zero hashes in request" % user)

    def splitMsg(self, msg):
        ''' Splits message into a list of hashes, filters non-white list chars '''
        hashes = []
        msg = msg.lower().replace(' ', ',')
        hashList = msg.split(",")
        hashList = filter(lambda hsh: 0 < len(hsh), hashList)
        if 0 < len(hashList):
            for hsh in hashList:
                cleanHash = filter(lambda char: char in self.charWhiteList, hsh)
                hashes.append(cleanHash)
        return hashes

    def dispatch(self, user, channel, msg, hashes, path=None, priority=1):
        ''' Starts cracking jobs, or pushes the job onto the queue '''
        if not self.isBusy:
            self.display(user, channel, "Starting new job for %s; cracking %d hash(es)" % (user, len(hashes),))
            thread.start_new_thread(self.__crack__, (user, channel, msg, hashes, path,))
        else:
            self.display(user, channel, "Queued job for %s with %d hash(es)" % (user, len(hashes),))
            logging.info("Job in progress, pushing to queue")
            self.jobQueue.put((priority, (user, channel, msg, hashes, path),))

    def __pop__(self):
        ''' Pops a job off the queue '''
        job = self.jobQueue.get()
        logging.info("Popping job off queue, %d job(s) remain " % self.jobQueue.qsize())
        thread.start_new_thread(self.__crack__, job[1])

    def __crack__(self, user, channel, msg, hashes, path):
        ''' Cracks a list of hashes '''
        self.isBusy = True
        work = list(hashes)
        logging.info("Cracking %d hashes for %s" % (len(hashes), user))
        if msg.startswith("!md5"):
            wl_results = self.__md5__(user, channel, msg, work)
            work = filter(lambda hsh: wl_results.has_key(hsh), work)
        if 0 < len(work):
            try:
                rc_results = RainbowCrack.crack(work, path, debug=DEBUG, maxThreads=THREADS)
            except ValueError:
                logging.exeception("Error while cracking hashes ... ")
            self.saveResults(user, channel, rc_results)
        logging.info("Job compelted for %s" % user)
        cracked = len(rc_results) + len(wl_results)
        self.display(user, channel, "Job completed for %s; cracked %d/%d hashes." % (user, cracked,len(hashes),))
        if 0 < self.jobQueue.qsize():
            self.__pop__()
        else:
            self.isBusy = False

    def __md5__(self, user, channel, msg, hashes):
        ''' Cracks md5 hashes using a word list '''
        words = self.__loadWordlist__()
        results = CrackPy.md5(hashes, words, threads=THREADS, debug=DEBUG)
        self.saveResults(user, channel, results)
        return results

    def __loadWordlist__(self):
        ''' Load words from file '''
        words = []
        if os.path.exists(WORDLIST) and os.path.isfile(WORDLIST):
            wordlist_file = open(WORDLIST, 'r')
            for word in wordlist_file.readlines():
                words.append(word.replace('\n', ''))
            wordlist_file.close()
        else:
            logging.error("Wordlist file does not exist '%s'" % WORDLIST)
            words = ['password', 'love', 'sex', 'secret', 'god']
        return words

    def saveResults(self, user, channel, results):
        dbConn = sqlite3.connect("replicant.db")
        cursor = dbConn.cursor()
        for key in results.keys():
            cursor.execute("INSERT INTO history VALUES (NULL, ?, ?, ?)", (user, key, results[key],))
            self.display(user, channel, "Cracked: %s -> %s" % (key, results[key],))
        dbConn.commit()
        dbConn.close()

    def checkStatus(self, user, channel, msg):
        ''' Responds with bot status '''
        if self.isBusy:
            self.display(user, channel, "I am currently cracking passwords.")
        else:
            self.display(user, channel, "I am currently idle, give me something to crack!")

    def checkJobs(self, user, channel, msg):
        ''' Displays the current number of queued jobs '''
        current = '.'
        if self.isBusy:
            current = ', and one in progress.'
        self.display(user, channel, "There are currently %d queued job(s)%s" % (self.jobQueue.qsize(), current,))
    
    def addProtip(self, user, channel, msg):
        ''' Adds a pro-tip to the database '''
        cursor = self.dbConn.cursor()
        cursor.execute("INSERT INTO protips VALUES (NULL, ?, ?)", (user, msg,))
        self.dbConn.commit()
        self.display(user, channel, "Added a new protip from %s" % user)

    def getProtip(self, user, channel, msg):
        ''' Pulls a pro-tip randomly from the database '''
        cursor = self.dbConn.cursor()
        cursor.execute("SELECT * FROM protips ORDER BY RANDOM() LIMIT 1")
        result = cursor.fetchone()
        if result != None and 0 < len(result):
            message = "%s --%s" % (result[2][:256], result[1][:64],)
            self.display(user, channel, "Pro-tip:" + message)
        else:
            self.display(user, channel, "There are currently no pro-tips in the database, add one using !addtip")

    def getHistory(self, user, channel, msg):
        ''' Retreives previously cracked passwords from the db '''
        try:
            count = int(msg[len("!history"):])
        except ValueError:
            count = 5
        cursor = self.dbConn.cursor()
        cursor.execute("SELECT * FROM history WHERE user = ? ORDER BY id DESC LIMIT ?", (user, count,))
        results = cursor.fetchall()
        if len(results) == 0:
            self.display(user, channel, "No history for %s" % user)
        else:
            for row in results:
                messsage = " [%d] %s -> %s" % (row[0], row[2], row[3])
                self.display(user, channel, messsage)

    def muteBot(self, user, channel, msg):
        ''' Toggle mute on/off '''
        channelSettings = self.channels.get(channel, None)
        if channelSettings is not None:
            if channelSettings.isMuted:
                channelSettings.isMuted = False
                self.display(user, channel, "Mute: OFF - Responses will be public")
            else:
                self.display(user, channel, "Mute: ON - Responses will be private")
                channelSettings.isMuted = True
        else:
            self.display(user, channel, "Cannot mute this channel.")

    def sendMessage(self, user, channel, msg):
        ''' Leave a message for an offline user '''
        msg_parts = msg.split(" ")
        if 3 <= len(msg_parts):
            cursor = self.dbConn.cursor()
            cursor.execute("SELECT id FROM users WHERE user = ?", (msg_parts[1],))
            receiver_id = cursor.fetchone()
            cursor.execute("SELECT id FROM users WHERE user = ?", (user,))
            sender_id = cursor.fetchone()
            if receiver_id is not None and sender_id is not None:
                message = " ".join(msg_parts[2:])
                # id, sent, recieved, sender_id, receiver_id, message, delieverd
                sent = str(datetime.now())
                cursor.execute("INSERT INTO messages VALUES (NULL, ?, NULL, ?, ?, ?, ?)", 
                    (sent, sender_id[0], receiver_id[0], message, False))
                self.display(user, channel, "Accepted message for delivery: %s" % sent, whisper=True)
            else:
                if receiver_id is None:
                    self.display(user, channel, "Unknown user '%s'." % msg_parts[1])
                if sender_id is None:
                    self.display(user, channel, "Unknown user '%s', please re-join the channel." % (user,))
                self.display(user, channel, "Sorry I can only deliever messages to/from users I know.")
        else:
            self.display("Malformed command, !send <user> <message>")

    def seen(self, user, channel, message):
        ''' Displays when a user last joined the channel '''
        cursor = self.dbConn.cursor()
        quser = message.replace(' ', '').lower()
        cursor.execute("SELECT last_login FROM users WHERE user = ?", (quser,))
        result = cursor.fetchone()
        if result is not None:
            self.display(user, channel, " %s was last seen %s" % (quser, result[0],))
        else:
            self.display(user, channel, "I have never seen a user by the name '%s'" % quser)

    def display(self, user, channel, message, whisper=False):
        ''' Intelligently wraps msg, based on mute setting '''
        channel_settings = self.channels.get(channel, None)
        if whisper or (channel_settings is not None and channel_settings.isMuted):
            display_channel = user
        else:
            display_channel = channel
        self.msg(display_channel, message.encode('ascii', 'ignore'))

    def leave_all(self):
        ''' Leave all channels '''
        for channel in self.channels:
            logging.info("Leaving channel:", channel.name)
            self.leave(channel.name, reason="I'll be back...")

    def about(self, user, channel, msg):
        ''' Displays version information '''
        self.display(user, channel, "  +---------------------------------------+")
        self.display(user, channel, "  |  Replicant IRC Bot v0.2 - By Moloch   |")
        self.display(user, channel, "  |      RCrackPy v0.1 // SQLite v3       |")
        self.display(user, channel, "  +---------------------------------------+")
        self.display(user, channel, "    https://github.com/moloch--/Replicant  ")

    def help(self, user, channel, msg):
        ''' Displays a helpful message '''
        self.display(user, channel, " > Commands: Replicant IRC Bot ", whisper=True)
        self.display(user, channel, "-------------------------------------", whisper=True)
        self.display(user, channel, " !md5 <hash1,hash2> - Crack an Md5 hashes", whisper=True)
        self.display(user, channel, " !ntlm <hash1,hash2> - Crack an NTLM hashes", whisper=True)
        self.display(user, channel, " !lm <hash1,hash2> - Crack an LM hashes", whisper=True)
        self.display(user, channel, " !help (all) - Display this helpful message", whisper=True)
        if msg.lower() == '!help all':
            self.display(user, channel, " !mute - Send all responses via pm", whisper=True)
            self.display(user, channel, " !status - Checks if the bot is busy", whisper=True)
            self.display(user, channel, " !jobs - Display the current queue size", whisper=True)
            self.display(user, channel, " !history (count) - Display your history", whisper=True)
            self.display(user, channel, " !addtip <tip> - Add a new pro-tip", whisper=True)
            self.display(user, channel, " !protip - Get a hacker pro-tip", whisper=True)
            self.display(user, channel, " !send - Send an offline user a message", whisper=True)
            self.display(user, channel, " !seen <user> - Display when a user was last seen.", whisper=True)
            self.display(user, channel, " !about - View version information", whisper=True)

### Factory
class ReplicantFactory(protocol.ClientFactory):

    def buildProtocol(self, addr):
        ''' Creates factory '''
        bot = Replicant()
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
    try:
        factory = ReplicantFactory()
        reactor.connectTCP(HOST, PORT, factory)
        reactor.run()
    except KeyboardInterrupt:
        print '\r[*] User exit'
