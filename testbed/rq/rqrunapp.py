#!/usr/bin/python3
# rq job runner

import os
from sys import exit
from rq import Queue
from redis import Redis
from argparse import ArgumentParser
import logging
import time
import pathlib
from rqrunapi import *

scriptpath = '/root/secure_IOT'
logFileName = 'rqrunapp.log'


funclookup = {'suricata':runSuricata, 'zeek':runZeek, 'pentest':runPentest, 'describe':runDescribe}	

if __name__ == "__main__":
	parser = ArgumentParser(description='Rq based container runner')
	parser.add_argument('-a', '--api',nargs="*", required=True, help='API entry - one or more of snort, zeek, suricata, pentest, pcapdescribe')
	parser.add_argument('-o', '--outdir', help='Output directory name to appear in /reports',required=True)
	parser.add_argument('-p', '--pcappath', default=None, help='PCAP capture file to process',required=True)
	parser.add_argument('-i', '--ipattack', default=None, help='IP to attack with pentest script',required=True)
	args = parser.parse_args()	
	if args.outdir:
		if not (os.path.exists(args.outdir)):
			pathlib.Path(args.outdir).mkdir(parents=True, exist_ok=True)
	logging.basicConfig(filename=os.path.join(args.outdir,logFileName),level=logging.DEBUG,filemode='w')
	if "REDIS_URL" in os.environ:
		rurl = os.environ['REDIS_URL']
		rurls = rurl.split(':') # meh
		rport = rurls[-1]
		rhost = rurls[-2].split('//')[1]
		print('rurl',rurl,rurls,'rport',rport,'rhost',rhost)
	else:
		logging.debug('No REDIS_URL found in environment. Cannot find remote redis')
		exit(1)
	
	# Tell RQ what Redis connection to use
	redis_conn = Redis(rhost,rport)
		
	
	for apicall in args.api:
		qname = '%sq' % apicall
		funcname = funclookup.get(apicall,None)
		if funcname:
			logging.debug('Sending %s to %s @ %s:%s' % (apicall,qname,rhost,rport))
			q = Queue(qname,connection=redis_conn,)  # no args implies the default queue
			if apicall == 'pentest':
				job = q.enqueue(funcname, args.ip,args.outdir)
			else:
				job = q.enqueue(funcname, args.pcappath,args.outdir)
		else:
			logging.debug('Got apicall %s - not recognised as a function' % (apicall))

