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


class pcapStore():
	""" find all subdirs and read within a time window
	# - use tcpdump -i en0 -w "testbed_%Y-%m-%d-%H:%M:%S.pcap" -G 3600 -z gzip
	"""
	
	def __init__(self,pcapsFolder):
		self.pcapsFolder = pcapsFolder
		plist = os.listdir(pcapsFolder)
		pcapfnames = []
		pcaptds = [] # date time started
		for pfn in plist:
			ppath = os.path.join(pcapsFolder, pfn)
			if os.path.isdir(ppath):
				flist =  os.listdir(pfn)
				tds = []
				for fname in flist: 
					fs = fname.split('_')
					if len(fs) == 2:
						fstartdate = fs[1]
						fsdt = datetime.strptime(fstartdate,'%Y-%m-%d-%H:%M:%S')
						pcapdts.append(fsdt)
						pcapfnames.append(fname)
					else:
						logging.debug('Got pcap file name %s - expected something else...ignoring' % fname)
		self.pcapfnames = pcapfnames
		self.pcaptds = pcaptds
		
		
	def getPeriod(sdt,edt,pcapdest):
		"""put all packets found between the two dates into the pcapdest filename
		"""
		respcap = []
		enddt = edt.strftime('%Y-%m-%d-%H:%M:%S')
		startdt = sdt.strftime('%Y-%m-%d-%H:%M:%S')
		firstfi = bisect.bisectl(self.pcapdts,startdt)
		lastfi = bisect.bisect(self.pcapdts,enddt)
		for fnum in firsfi to lastfi:
			rdfname = os.path.join(self.pcapsFolder,pcapfnames[fnum])
			pin = rdpcap(rdfname)
			respcap += pin
		return respcap  # removes dupes
