# extract all packets within a time window as a pcap file from a folder of rotated pcap logs 
# ross lazarus



# Expanding upon flabdablet’s answer (changing -G 1800 to -G 300 – rotation every five minutes – just for testing purposes),

# tcpdump -i en0 -w /var/tmp/trace-%m-%d-%H-%M-%S-%s -W 3 -G 300

# will give you %m=month, %d=day of month, %H=hour of day, %M=minute of day, %S=second of day, %s=millisecond of day, resulting in

# /var/temp/trace-03-02-08-30-56-1520002568
# /var/temp/trace-03-02-08-35-56-1520002568
# /var/temp/trace-03-02-08-40-56-1520002568


import os
from datetime import datetime
import dateutil
from scapy.all import *
import bisect
import pathlib
import logging

FSDTFORMAT = '%Y-%m-%d-%H:%M:%S'

class pcapStore():
	""" find all subdirs and read within a time window
		# - use  (eg) tcpdump -i en0 -w "testbed_%Y-%m-%d-%H:%M:%S.pcap" -G 3600 
		The underscore allows easy trimming of the file name prefix part
	"""
	
	def __init__(self,pcapsFolder):
		self.pcapsFolder = pcapsFolder
		self.pcapfnames = []
		self.pcaptds = []
		
		
	def readFolder(self)
		""" 
		index complex folders of pcaps on start date
		using fugly metadata in filename so a time window 
		of packets can be extracted
		"""
		pcapfnames = []
		pcaptds = [] # date time started
		for dirName, subdirList, fileList in os.walk(self.pcapsFolder):
			for pfn in fileList:
				fs = pfn.split('_') # assume name works this way...
				if len(fs) == 2:
					fn = fs[1] 
					ppath = os.path.join(dirName, fn)
					fstartdate = os.path.basename(fn) # date
					try:
						fsdt = datetime.strptime(fstartdate,FSDTFORMAT)
						fsdtt = time.mktime(fsdt.timetuple())
						pcapdts.append(int(fsdtt)) # easier for bisect to work on - assume never > 1/sec FFS!
						pcapfnames.append(ppath)
					except:
						logging.debug('Found pcap file name %s in path %s - expected something else...ignoring' % (pfn,self.pcapsFolder))
		self.pcapfnames = pcapfnames
		self.pcaptds = pcaptds
		
		
	def writePeriod(sdt,edt,pcapdest):
		"""write packets in a datetime window into pcapdest as pcap
		"""
		self.readFolder() # in case any new ones since we started running
		respcap = []
		edtt = time.mktime(edt.timetuple()) # as seconds since epoch
		sdtt = time.mktime(sdt.timetuple())
		try:
			enddt = edt.strftime('%Y-%m-%d-%H:%M:%S')
			startdt = sdt.strftime('%Y-%m-%d-%H:%M:%S')
		except:
			logging.debug('##Problem with start and end datetimes in writePeriod - %s and %s - expected datetimes' % (sdt,edt))
			return False
		firstfi = bisect.bisect(self.pcapdts,sdtt)
		lastfi = bisect.bisect_right(self.pcapdts,edtt)
		acted = False
		for fnum in firsfi to lastfi:
			rdfname = pcapfnames[fnum]
			pin = rdpcap(rdfname)
			pin = [x for x in pin if x.time <= edtt and x.time >= sdtt] # gotta love scapy 
			if len(pin) > 0:
				wrpcap(pcapdest, pin, append=True) #appends packets to output file
				acted = True
			else:
				logging.debug('writePeriod got zero packets filtering by start %d end %d on pcal %s' % (sdtt,edtt,rdfname))
		if acted:
			logging.info('writePeriod filtered from %d packet files using window %s - %s to %s' % (lastfi-firstfi+1,startdt,enddt,pcapdest))
		return acted
