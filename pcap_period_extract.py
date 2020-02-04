# extract all packets within a time window as a pcap file from a folder of rotated pcap logs 
# ross lazarus
# FSDTFORMAT should correspond to the suffix of the filename made by tcpdump
# tcpdump -i en0 -w "testbed_%Y-%m-%d-%H:%M:%S.pcap" -G 3600 
# for example. Use whatever you want before the underscore 
# and anything you like as the extension
# mismatched timezone settings between capture and analysis 
# images will cause the obvious consequences. 

import os
from datetime import datetime
from time import localtime,time
import dateutil
from scapy.all import *
import bisect
import pathlib
import logging

logFileName = 'pcap_period_extract.log'
logging.basicConfig(filename=logFileName,filemode='w')
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
		
		
	def readFolder(self):
		""" 
		index complex folders of pcaps on start date
		using fugly metadata in filename so a time window 
		of packets can be extracted
		"""
		pcapfnames = []
		pcaptds = [] # date time started
		pcapinfo = []
		for dirName, subdirList, fileList in os.walk(self.pcapsFolder):	
			for pfn in fileList:
				fs = pfn.split('_') # assume name works this way...
				if len(fs) == 2:
					fn = fs[1] 
					ppath = os.path.join(dirName, pfn)
					fstartdate = fn.split('.')[0] # date
					try:
						fsdt = datetime.strptime(fstartdate,FSDTFORMAT)
						fsdtt = int(time.mktime(fsdt.timetuple()))
						pcapinfo.append([fsdtt,ppath])
					except:
						logging.warning('Found pcap file name %s in path %s - expected %s preceded by an underscore - ignoring' % (pfn,self.pcapsFolder,FSDTFORMAT))
		pcapinfo.sort() # files might turn up in any old order in complex archives
		self.pcapfnames = [x[1] for x in pcapinfo]
		self.pcaptds = [x[0] for x in pcapinfo]
		
		
	def writePeriod(self,sdt,edt,pcapdest):
		"""write packets in a datetime window into pcapdest as pcap
		"""
		self.readFolder() # in case any new ones since object instantiated
		respcap = []
		edtt = time.mktime(edt.timetuple()) # as seconds since epoch
		sdtt = time.mktime(sdt.timetuple())
		try:
			enddt = edt.strftime('%Y-%m-%d-%H:%M:%S')
			startdt = sdt.strftime('%Y-%m-%d-%H:%M:%S')
		except:
			logging.warning('##Problem with start and end datetimes in writePeriod - %s and %s - expected datetimes' % (sdt,edt))
			return False
		firstfi = bisect.bisect_left(self.pcaptds,int(sdtt))
		lastfi = min(bisect.bisect_right(self.pcaptds,int(edtt)) + 1, len(self.pcaptds)-1)
		acted = False
		npkt = 0
		for fnum in range(firstfi, lastfi):
			rdfname = self.pcapfnames[fnum]
			pin = rdpcap(rdfname)
			mint = min([x.time for x in pin])
			maxt = max([x.time for x in pin])
			print('file',rdfname,'has min',mint,'max',maxt)
			pin = [x for x in pin if int(x.time) >= sdtt and int(x.time) <= edtt] # gotta love scapy 
			if len(pin) > 0:
				npkt += len(pin)
				wrpcap(pcapdest, pin, append=True) #appends packets to output file
				acted = True
				logging.info('wrote %d packets to %s' % (len(pin),pcapdest))
			else:
				logging.debug(('writePeriod got zero packets filtering by start %s end %s on pcap %s ' % (sdtt,edtt,rdfname))
		logging.info('writePeriod filtered %d packets from %d packet files using window %s - %s to %s' % (npkt,lastfi-firstfi+1,startdt,enddt,pcapdest))
		return acted
		
if __name__ == "__main__": # testing testbed_2020-02-03-18:42:00.pcap
	ps = pcapStore(pcapsFolder = '/testbed/pcaps/filedrop')
	dest = '/tmp/test3hour.pcap'
	sdt = datetime.strptime('2020-02-03-18:30:00', FSDTFORMAT)
	edt = datetime.strptime('2020-02-03-19:00:00', FSDTFORMAT)
	ok = ps.writePeriod(sdt,edt,dest)
