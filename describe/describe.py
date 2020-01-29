# describe command line parameters
import sys
cl = []
for x in sys.argv:
	cl.append(x)
print('Passed parameters = ',' '.join(cl))
