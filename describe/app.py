from flask import Flask
from flask import request
from flask import jsonify
import os
import logging
logging.basicConfig(filename='flask.log',level=logging.INFO)

app = Flask(__name__)

attack_exe = 'python3 describe.py'
describe_exe = 'python3 describe.py'

"""
to send:

import requests
res = requests.post('http://localhost:5000/api/attack/1234', json={"executeme":"ls",'-la':''})
if res.ok:
	print res.json()
"""

@app.route('/api/attack/<int:jobid>/', methods=['GET', 'POST'])
def run_attack(jobid):
	config = request.get_json()
	cll = [attack_exe,]
	for k in config.keys():
		cll.append('%s=%s' % (k,config[k]))
	cl = ' '.join(cll)
	c = os.popen(cl).read()
	logging.debug('attack from config %s, got %s' % (cl,c))
	return jsonify({"jobid":jobid,"command":cl,"output":c}), 201

@app.route('/api/describe/<int:jobid>/', methods=['GET', 'POST'])
def run_describe(jobid):
	config = request.get_json()
	cll = [describe_exe,]
	for k in config.keys():
		cll.append('%s=%s' % (k,config[k]))
	cl = ' '.join(cll)
	c = os.popen(cl).read()
	logging.debug('describe from config %s, got %s' % (cl,c))
	return jsonify({"jobid":jobid,"command":cl,"output":c}), 201
