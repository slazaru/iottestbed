#!/usr/bin/python3
# rq job runner api

from os import system


def runSuricata(pcappath,outpath):
	system('suricata -r %s -o %s' % (pcappath,outpath))

def runZeek(pcappath,outpath):
	system('mkdir -p /reports/%s && mkdir -p /reports/%s/zeek cd /reports/%s/zeek && zeek -r %s' % (outpath,outpath,outpath,pcappath))
	
def runPentest(ip,outpath):
	system('python3 %s/attack.py -i %s -o %s' % (ip,outpath))

def runDescribe(pcappath,outpath):
	system('python3  %s/pcapreporter.py -r %s -o %s' % (scriptpath,pcappath,outpath))

