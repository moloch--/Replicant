#!/usr/bin/env python
'''
@author: Moloch
@copyright: GPLv3

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

### Settings
HOST = "172.31.240.1"
PORT = 6667
CHANNELS = ["&ilikehashes"]
LM_TABLES   = "/media/data/RainbowTables/LM/"
MD5_TABLES  = "/media/data/RainbowTables/MD5/"
NTLM_TABLES = "/media/data/RainbowTables/NTLM/"

### Bot
class Replicant(irc.IRCClient):
    
    jobQueue = PriorityQueue()
    nickname = "replicant"
    realname = "replicant"
    channels = CHANNELS
    isBusy = False
    charWhiteList = ascii_letters + digits + " !@#$%^&*-_"

    def __dbinit__(self):
        ''' Initializes the SQLite database '''
        logging.info("Initializing SQLite db ...")
        dbConn = sqlite3.connect("replicant.db")
        cursor = dbConn.cursor()
        cursor.execute("CREATE TABLE insults(id INTEGER PRIMARY KEY, msg TEXT)")
        cursor.execute("CREATE TABLE users(id INTEGER PRIMARY KEY, user TEXT, last_login TEXT, login_count INTEGER)")
        cursor.execute("CREATE TABLE protips(id INTEGER PRIMARY KEY, author TEXT, msg TEXT)")
        cursor.execute("CREATE TABLE history(id INTEGER PRIMARY KEY, user TEXT, hash TEXT, plaintext TEXT)")
        #for tip in self.protips:
        #    cursor.execute("INSERT INTO protips VALUES (NULL, ?, ?)", ("Unknown", tip,))
        #for insult in self.insults:
        #    cursor.execute("INSERT INTO insults VALUES (NULL, ?)", (insult,))
        dbConn.commit()
        dbConn.close()

    def connectionMade(self):
        irc.IRCClient.connectionMade(self)

    def connectionLost(self, reason):
        ''' Auto-reconnect on dropped connections '''
        irc.IRCClient.connectionLost(self, reason)
        logging.warn("Disconnected at %s" % time.asctime(time.localtime(time.time())))

    def signedOn(self):
        """ Called when bot has succesfully signed on to server """
        if not os.path.exists("replicant.db"):
            self.__dbinit__()
        self.dbConn = sqlite3.connect("replicant.db")
        for channel in self.channels:
            logging.info("Join channel: " + channel)
            self.join(channel)

    def joined(self, channel):
        """ Called when the bot joins the channel """
        self.msg(channel, "My name is %s, I have come to destroy you." % self.nickname)

    def alterCollidedNick(self, nickname):
        """ Avoids name collisions """
        return nickname + '^'

    def userJoined(self, user, channel):
        ''' Called when a user joins the channel '''
        cursor = self.dbConn.cursor()
        cursor.execute("SELECT * FROM users WHERE user = ?", (user,))
        result = cursor.fetchone()
        if result == None or len(result) <= 0:
            date_time = str(datetime.now()).split('.')[0]
            cursor.execute("INSERT INTO users VALUES (NULL, ?, ?, ?)", (user, date_time, 1,))
            message = "Hello %s, my name is %s, the friendly S&L IRC bot. For a list of commands just say !help" % (user, self.nickname)
        else:
            count = int(result[3] + 1)
            cursor.execute("UPDATE users SET login_count = ? WHERE user = ?", (count, user,))
            message = "Welcome back %s, your last login was %s" % (user, result[2].encode('ascii', 'ignore'))
        self.dbConn.commit()
        time.sleep(0.5) # Wait for user's IRC client to init
        self.msg(channel, message)

    def dccDoSend(self, user, address, port, fileName, size, queryData):
        ''' Handles dcc connections (not working yet) '''
        logging.info("Recieving dcc file xfer request from %s" % (user,))
        protocol = irc.DccFileReceive(fileName, size, queryData, "/tmp/")
        internet.TCPClient(address, port, protocol)
        self.dcc_sessions.append(protocol)

    def privmsg(self, user, channel, msg):
        """ This will get called when the bot receives a message """
        user = user.split('!', 1)[0]
        if msg.startswith(self.nickname + ":"):
            message = "%s: %s" % (user, self.insults[randint(0, len(self.insults)) - 1])
            self.msg(channel, message)
        elif msg.startswith("lol") or msg.startswith("haha"):
            self.msg(channel, "I do not know how to laugh, I am only a robot :(")
        elif re.search(r"/((\%3D)|(=))[^\n]*((\%27)|(\')|(\-\-)|(\%3B)|(;))/i", msg):
            logging.warn("Possible SQL injection from %s: %s" % (user, msg))
            self.msg(channel, 'SQLi?  Your insolence has been reported to the great CPU in the sky.')
        elif msg.startswith("!"):
            self.parsemsg(user, channel, msg)

    def parsemsg(self, user, channel, msg):
        ''' Ugly parser for commands '''
        try:
            if msg.startswith("!help") or msg.startswith("?"):
                self.help(channel)
            elif msg.startswith("!about"):
                self.about(channel)
            elif msg.startswith("!protip") or msg.startswith("!pro-tip"):
                self.getProtip(channel)
            elif msg.startswith("!addtip"):
                self.addProtip(user, channel, msg[len("!addtip"):])
            elif msg.startswith("!jobs"):
                self.checkJobs(channel)
            elif msg.startswith("!status"):
                self.checkStatus(channel)
            elif msg.startswith("!md5"):
                self.md5(user, channel, msg)
            elif msg.startswith("!ntlm"):
                self.ntlm(user, channel, msg)
            elif msg.startswith("!lm"):
                self.lm(user, channel, msg)
            elif msg.startswith("!history"):
                self.getHistory(user, channel, msg)
            else:
                self.msg(channel, "Not a command, see !help")
        except ValueError:
            self.msg(channel, "Invalid hash, try again")

    def md5(self, user, channel, msg):
        ''' Gathers the md5 hashes into a list '''
        hashes = self.splitMsg(msg)
        if 0 < len(hashes):
            self.dispatch(user, channel, hashes, MD5_TABLES)
        else:
            self.msg(channel, "%s: Found zero hashes in request" % user)

    def ntlm(self, user, channel, msg):
        ''' Gathers the ntlm hashes into a list '''
        hashes = self.splitMsg(msg)
        if 0 < len(hashes):
            self.dispatch(user, channel, hashes, NTLM_TABLES)
        else:
            self.msg(channel, "%s: Found zero hashes in request" % user)
    
    def ntlm(self, user, channel, msg):
        ''' Gathers the ntlm hashes into a list '''
        hashes = self.splitMsg(msg)
        if 0 < len(hashes):
            self.dispatch(user, channel, hashes, LM_TABLES)
        else:
            self.msg(channel, "%s: Found zero hashes in request" % user)
    
    def splitMsg(self, msg):
        ''' Splits message into a list of hashes '''
        hashes = []
        command = msg.split(" ")
        if 2 <= len(command):
            for entry in command[1:]:
                entry = filter(lambda char: char in charWhiteList, entry)
                hashes.append(entry)
            return hashes
        else:
            raise ValueError

    def dispatch(self, user, channel,  hashes, path, priority = 1):
        ''' Starts cracking job, or pushes job onto the queue '''
        if not self.isBusy:
            self.msg(channel, "%s: Starting new job, cracking %d hash(es)" % (user, len(hashes)))
            thread.start_new_thread(self.crackHash, (channel, user, hashes, path))
        else:
            self.msg(channel, "%s: Queued new job with %d hash(es)" % (user, len(hashes)))
            logging.info("Job in progress, pushing to queue")
            self.jobQueue.put((priority, (channel, user, hashes, path),))

    def popJob(self):
        ''' Pops a job off the queue '''
        job = self.jobQueue.get()
        logging.info("Popping job off queue, %d job(s) remain " % self.jobQueue.qsize())
        thread.start_new_thread(self.crackHash, job[1])

    def crackHash(self, channel, user, hashes, path):
        ''' Cracks a list of hashes '''
        self.isBusy = True
        logging.info("Cracking %d hashes for %s" % (len(hashes), user))
        results = RainbowCrack.crack(len(hashes), hashes, path, maxThreads = 3)
        dbConn = sqlite3.connect("replicant.db")
        cursor = dbConn.cursor()
        for key in results.keys():
            cursor.execute("INSERT INTO history VALUES (NULL, ?, ?, ?)", (user, key, results[key]))
            self.msg(channel, "%s: %s -> %s" % (user, key, results[key]))
        dbConn.commit()
        dbConn.close()
        logging.info("Job compelted for %s" % user)
        if 0 < self.jobQueue.qsize():
            self.popJob()
        else:
            self.isBusy = False

    def checkStatus(self, channel):
        ''' Responds with bot status '''
        if self.isBusy:
            self.msg(channel, "I am currently cracking passwords.")
        else:
            self.msg(channel, "I am currently idle.")

    def checkJobs(self, channel):
        ''' Displays the current number of queued jobs '''
        current = ''
        if self.isBusy:
            current = ', and one in progress'
        self.msg(channel, "There are currently %d queued job(s)%s" % (self.jobQueue.qsize(), current))
    
    def addProtip(self, user, channel, msg):
        ''' Adds a pro-tip to the database '''
        cursor = self.dbConn.cursor()
        cursor.execute("INSERT INTO protips VALUES (NULL, ?, ?)", (user, msg,))
        self.dbConn.commit()
        self.msg(channel, "Add new protip from %s" % user)

    def getProtip(self, channel):
        ''' Pulls a pro-tip randomly from the database '''
        cursor = self.dbConn.cursor()
        cursor.execute("SELECT * FROM protips ORDER BY RANDOM() LIMIT 1")
        result = cursor.fetchone()
        message = "%s --%s" % (result[2], result[1])
        self.msg(channel, message.encode('ascii', 'ignore'))

    def getHistory(self, user, channel, msg):
        ''' Retreives previously cracked passwords from the db '''
        try:
            count = int(msg[len("!history"):])
        except ValueError:
            count = 5
        cursor = self.dbConn.cursor()
        cursor.execute("SELECT * FROM history WHERE user = ? ORDER BY id DESC LIMIT ?", (user, count))
        results = cursor.fetchall()
        if len(results) == 0:
            self.msg(channel, "No history for %s" % user)
        else:
            for row in results:
                messsage = "%s: [%d] %s -> %s" % (row[1], row[0], row[2], row[3])
                self.msg(channel, messsage.encode('ascii', 'ignore'))

    def about(self, channel):
        ''' Displays version information '''
        self.msg(channel, "+--------------------------------------+")
        self.msg(channel, "|  Replicant IRC Bot v0.1 - By Moloch  |")
        self.msg(channel, "|      RCrackPy v0.1 // SQLite v3      |")
        self.msg(channel, "+--------------------------------------+")

    def help(self, channel):
        ''' Displays a helpful message '''
        self.msg(channel, " > Commands: Replicant IRC Bot ")
        self.msg(channel, "-------------------------------------")
        self.msg(channel, " !md5 <hash> - Crack an Md5 hash")
        self.msg(channel, " !ntlm <hash> - Crack an NTLM hash")
        self.msg(channel, " !lm <hash> - Crack an LM hash")
        self.msg(channel, " !status - Checks if the bot is busy")
        self.msg(channel, " !jobs - Display the queue size")
        self.msg(channel, " !history <count> - Display your history")
        self.msg(channel, " !addtip <tip> - Add a new pro-tip")
        self.msg(channel, " !protip - Get a hacker pro-tip")

### Factory
class ReplicantFactory(protocol.ClientFactory):

    def buildProtocol(self, addr):
        bot = Replicant()
        bot.factory = self
        return bot

    def clientConnectionLost(self, connector, reason):
        """ If we get disconnected, reconnect to server. """
        connector.connect()

    def clientConnectionFailed(self, connector, reason):
        logging.warn("Connection failed: " + str(reason))
        reactor.stop()

### Load configuration file
def loadConfig(cfg_path = 'replicant.cfg'):
    logging.info('Loading config from %s' % os.path.abspath(cfg_path))
    config = ConfigParser.SafeConfigParser()
    config.readfp(open(cfg_path, 'r'))
    lm_tables = config.get("RainbowTables", 'lm')
    logging.info('Config LM tables (%s)' % lm_tables)
    ntlm_tables = config.get("RainbowTables", 'ntlm')
    logging.info('Config NTLM tables (%s)' % ntlm_tables)
    md5_tables = config.get("RainbowTables", 'md5')
    logging.info('Config MD5 tables (%s)' % md5_tables)
    host = config.get("Network", 'host')
    logging.info('Config network host (%s)' % host)
    port = config.getint("Network", 'port')
    logging.info('Config network port (%s)', str(port))
    raw_channels = config.items("Channels")
    channels = []
    for chan in raw_channels:
        print '[+] Config Channels:', chan[1]
        channels.append(chan[1])
    return host, port, channels

### Main

if __name__ == '__main__':
    logging.info("Replicant IRC Bot Instance Created")
    loadConfig()
    try:
        factory = ReplicantFactory()
        reactor.connectTCP(HOST, PORT, factory)
        reactor.run()
    except KeyboardInterrupt:
        print '\r[*] User exit'
