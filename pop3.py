#!/usr/bin/env python
# -*- coding: utf-8 -*-

# Copyright (c) 2014 Alexander Bredo
# All rights reserved.
# 
# Redistribution and use in source and binary forms, with or 
# without modification, are permitted provided that the 
# following conditions are met:
# 
# 1. Redistributions of source code must retain the above 
# copyright notice, this list of conditions and the following 
# disclaimer.
# 
# 2. Redistributions in binary form must reproduce the above 
# copyright notice, this list of conditions and the following 
# disclaimer in the documentation and/or other materials 
# provided with the distribution.
# 
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND 
# CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, 
# INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF 
# MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE 
# DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR 
# CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, 
# INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES 
# (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE 
# GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR 
# BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF 
# LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT 
# (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT 
# OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE 
# POSSIBILITY OF SUCH DAMAGE.


import time, uuid
import os, os.path
from datetime import datetime
from twisted.internet import protocol, reactor, ssl
from twisted.protocols.basic import LineReceiver
from twisted.conch.telnet import TelnetProtocol

from base.applog import *
from base.appconfig import Configuration
from handler.manager import HandlerManager

class Pop3Config(Configuration):
	def setup(self, *args, **kwargs): # Defaults: 
		self.__version = '0.1.0'
		self.__appname = 'honeypot_pop3'
		self.port=110
		self.hostname='mx2.example.com'
		self.domain='example.com'
		self.maildir='static/'
		self.sslport=995
		self.sslcertprivate='keys/smtp.private.key'
		self.sslcertpublic='keys/smtp.public.key'
		self.enabled_handlers = {
			'elasticsearch': True, 
			'screen': True,
			'file': True
		}
		self.elasticsearch = {
			'host': '127.0.0.1', 
			'port': 9200, 
			'index': 'honeypot'
		}
		self.filename = 'honeypot_output.txt'
		
config = Pop3Config()
handler = HandlerManager(config)

class SimplePop3Session(LineReceiver, TelnetProtocol):
	def __init__(self):
		self.delimiter = '\n'
		self.__mailcount()
		self.session = str(uuid.uuid1()) # Dirty. todo. 
		self.myownhost = None

	def connectionMade(self):
		self.__logInfo('connected', '', True)
		self.transport.write('+OK QPOP (version 2.2) at 127.0.0.1 starting.\r\n')
		self.state = 'AUTHUSER'

	def connectionLost(self, reason):
		self.__logInfo('disconnected', '', True)

	def lineReceived(self, line):
		line = line.replace(b"\r", b"") # Remove unneccessary chars
		command = line.strip().lower()
		if (command in ['quit', 'exit']):
			self.transport.write('+OK Pop server at %s signing off.\r\n' % config.hostname)
			self.transport.loseConnection()
		elif (command.startswith('capa')):
			self.__logInfo('CAPABILITIES', command, True)
			self.transport.write('+OK Capability list follows\r\n')
			self.transport.write('TOP\r\n')
			self.transport.write('APOP\r\n')
			self.transport.write('USER\r\n')
			self.transport.write('PASS\r\n')
			self.transport.write('STAT\r\n')
			self.transport.write('LIST\r\n')
			self.transport.write('RETR\r\n')
			self.transport.write('DELE\r\n')
			self.transport.write('RSET\r\n')
			self.transport.write('.\r\n')
		else:
			getattr(self, 'pop3_' + self.state)(command)

	def pop3_AUTHUSER(self, command):
		if (command.startswith('user')):
			self.__logInfo('AUTHUSER', command, True)
			self.transport.write('+OK Password required for %s.\r\n' % command[4:].strip())
			self.state = 'AUTHPASS'
		elif (command.startswith('apop') and len(command) > 15):
			self.__logInfo('AUTHUSER', command, True)
			self.transport.write('+OK')
			self.state = 'META'
		else:
			self.__logInfo('ERR', command, False)
			self.transport.write('-ERR Authentication required.\r\n')
			
	def pop3_AUTHPASS(self, command):
		if (command.startswith('pass')):
			self.__logInfo('AUTHPASS', command, True)
			mailcount = self.__mailcount() 
			self.transport.write('+OK User has %s messages (%s octets).\r\n' % (str(mailcount), mailcount*1123))
			self.state = 'META'
		else:
			self.__logInfo('ERR', command, False)
			self.transport.write('-ERR Password required.\r\n') 
			
	def pop3_META(self, command):
		if (command.startswith('retr') or command.startswith('top')):
			self.__logInfo('RETR', command, True)
			file = config.maildir + command[4:].strip() + '.mail'
			if (self.__existsmail(file)):
				self.transport.write('+OK %s octets\r\n' % self.__mailsize(file))
				fo = open(file)
				for line in fo.readlines():
					self.transport.write(line.strip() + '\r\n')
				fo.close()
				self.transport.write('.\r\n')
			else:
				self.transport.write('-ERR Requested mail does not exist.\r\n')
		elif (command.startswith('stat')):
			if (len(command) == 4):
				self.transport.write('+OK %s 1532\r\n' % self.__mailcount())
			else:
				self.__logInfo('STAT', command, True)
				file = config.maildir + command[4:].strip() + '.mail'
				if (self.__existsmail(file)):
					self.transport.write('+OK %s octets\r\n' % self.__mailsize(file))
				else:
					self.transport.write('-ERR Requested mail does not exist.\r\n')
		elif (command.startswith('list')):
			self.__logInfo('LIST', command, True)
			self.transport.write('+OK %s messages:\r\n' % str(self.__mailcount()))
			for name in os.listdir(config.maildir):
				if os.path.isfile(config.maildir + name):
					self.transport.write('%s %s\r\n' % (name.split('.')[0], str(self.__mailsize(config.maildir + name))))
			self.transport.write('.\r\n')
		elif (command.startswith('dele')):
			self.__logInfo('DELETE', command, False)
			self.transport.write('+OK Message deleted\r\n')
		elif (command.startswith('rset')):
			self.__logInfo('RESET', command, True)
			self.transport.write('+OK Reset state\r\n')
			self.state = 'AUTHPASS'
		else:
			self.__logInfo('ERR', command, False)
			self.transport.write('-ERR Invalid command specified.\r\n') 

	def __mailcount(self):
		return len([name for name in os.listdir(config.maildir) if os.path.isfile(config.maildir + name)])
		
	def __mailsize(self, file):
		try:
			return os.path.getsize(file)
		except:
			return 371
			
	def __existsmail(self, file):
		return os.path.exists(file)
		
	def __logInfo(self, type, command, successful):
		try: # Hack: On Connection-Close socket unavailable. remember old ip.
			self.myownhost = self.transport.getHost()
		except AttributeError:
			pass # nothing

		data = {
			'module': 'POP3', 
			'@timestamp': int(time.time() * 1000), # in milliseconds
			'sourceIPv4Address': str(self.transport.getPeer().host), 
			'sourceTransportPort': self.transport.getPeer().port,
			'type': type,
			'command': command, 
			'success': successful, 
			'session': self.session
		}
		if self.myownhost:
			data['destinationIPv4Address'] = str(self.myownhost.host)
			data['destinationTransportPort'] = self.myownhost.port

		handler.handle(data)

class Pop3Factory(protocol.Factory):
	def buildProtocol(self, addr):
		return SimplePop3Session()

try:
	reactor.listenTCP(
		config.port, 
		Pop3Factory()
	)
	reactor.listenSSL(
		config.sslport, 
		Pop3Factory(), 
		ssl.DefaultOpenSSLContextFactory(
			config.sslcertprivate, 
			config.sslcertpublic
	))
	log.info('Server listening on Port %s (Plain) and on %s (SSL).' % (config.port, config.sslport))
	reactor.run()
except Exception, e:
	log.error(str(e));
	exit(-1)
log.info('Server shutdown.')