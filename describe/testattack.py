
import requests

j1 = dict(zip(['a','b','c'],[99,100,101]))


res = requests.post('http://localhost:3000/api/attack/1/', json=j1)
if res.ok:
    print('attack ok,json=',res.json())
else:
	print('attack not ok,res=',res)

res = requests.post('http://localhost:3000/api/describe/2/', json=j1)
if res.ok:
    print('describe ok,json=',res.json())
else:
	print('describe not ok,res=',res)
