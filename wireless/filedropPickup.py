#!/usr/bin/python3
# processor for moving newly completed rotating pcap files
# from filedrop to long term store

import os
import sys
from datetime import datetime
import tempfile
import shutil
from subprocess import check_output,Popen, PIPE
import logging
from rq import Queue, Connection
from redis import Redis

SNORTREDISPORT = 5555
ZEEKREDISPORT = 5556
REDISPORT = 6379

LOCKFILE = "/pcap/filedrop/filedrop.lock"
AWHILE = 60 # seconds to sleep if no completed pcaps available from tcpdump
from pathlib import Path

def fileInUse(filename):
	try: # if grep finds filename, the (pcap) file is in use by another process - tcpdump with any luck
	   lsout=Popen(['lsof',filename],stdout=PIPE, shell=False)
	   check_output(["grep",filename], stdin=lsout.stdout, shell=False)
	   return True
	except:
		return False
	   
def runZEEKjob(pcap,outdir):
		Path(outdir).mkdir(parents=True, exist_ok=True)
		os.chdir(outdir)
		z = Popen(['zeek','-r',pcap])
	    return z
	    
# Check to see if already running
pdir=/pcap/filedrop
permdir = "/pcap/%s-%s-%s' % (year,month,day)"
os.makedirs(permdir, exist_ok=True)
dt = datetime.now()
year = dt.year
month = dt.month
minute = dt.minute
if os.path.exists(LOCKFILE):
	sys.exit('%s exists - am I aleady running? Delete it if not please' % LOCKFILE)
	


with Connection(Redis('localhost', REDISPORT)):
    snortq = Queue('snortrunme')
    zeekq = Queue('zeekrunme')
    
foo = open(LOCKFILE,'w')
while true:
	drops = os.listdir(pdir)
	for pf in drops:
		if os.path.isfile(pf):
			pfp = os.path.join(pdir,pf)
			if fileInUse(pfp):
				continue
			logging.info('New file %s in %s - processing and compressing to permanent store %s' % (pf,pdir,permdir))
			tdir = tempfile.TemporaryDirectory()
			shutil.move(pfp,tdir)
			pfp = os.path.join(tdir,pf)
			newpfp = os.path.join(permdir,'%s.gz')
			gzok = Popen('gzip','-c',pfp,' > %s' % newpfp)
			if not gzok:
				s = 'Emergency$$$$ Problem with gzip for %s > %s' % (pfp,newpfp)
				logging.warning(s)
				print(s)
			outdir = '/usr/local/zeek/logs/%s' % pf.split('.pcap')[0]
			job = zeekq.enqueue(runZeekJob,pfp,outdir)
			print(job.result)   # => None

			sniff = Popen('snort','-c','/etc/snort/snort.conf','--pcap-dir',tdir,'-pcap-filter','"*.pcap"')
		else:
			sleep(AWHILE)
os.remove(LOCKFILE)
