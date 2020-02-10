from fastapi import FastAPI
from starlette.requests import Request
from starlette.staticfiles import StaticFiles
from starlette.templating import Jinja2Templates
import os
import logging

# logging.basicConfig(filename='app.log',level=logging.INFO)



attack_exe = 'python3 /reports/flaskapp/describe.py'
describe_exe = 'python3 /reports/flaskapp/describe.py'


app = FastAPI()

app.mount("/static", StaticFiles(directory="static"), name="static")


templates = Jinja2Templates(directory="templates")



@app.route("/")
async def homepage(request):
    return templates.TemplateResponse('index.html', {'request': request})


@app.get("/items/{id}")
async def read_item(request: Request, id: str):
    return templates.TemplateResponse("item.html", {"request": request, "id": id})


"""
to send:

import requests
res = requests.post('http://localhost:5000/api/attack/1234', json={"executeme":"ls",'-la':''})
if res.ok:
	print res.json()
"""

@app.route('/app/attack/<int:jobid>/', methods=['GET', 'POST'])
def run_attack(jobid):
	config = request.get_json()
	cll = [attack_exe,]
	for k in config.keys():
		cll.append('%s=%s' % (k,config[k]))
	cl = ' '.join(cll)
	c = os.popen(cl).read()
	logging.debug('attack from config %s, got %s' % (cl,c))
	return jsonify({"jobid":jobid,"command":cl,"output":c}), 201

@app.route('/app/describe/<int:jobid>/', methods=['GET', 'POST'])
def run_describe(jobid):
	config = request.get_json()
	cll = [describe_exe,]
	for k in config.keys():
		cll.append('%s=%s' % (k,config[k]))
	cl = ' '.join(cll)
	c = os.popen(cl).read()
	logging.debug('describe from config %s, got %s' % (cl,c))
	return jsonify({"jobid":jobid,"command":cl,"output":c}), 201

@app.route('/app/snort', methods=['GET', 'POST'])
def run_snort(request):
	return templates.TemplateResponse('snortrun.html', {'request': request})
@app.route('/app/zeek', methods=['GET', 'POST'])
def run_zeek(request):
	return templates.TemplateResponse('zeekrun.html', {'request': request})
