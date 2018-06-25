import os
import time
import urllib2
from apple_signed_server import *

def Login():
	try:
		result = plistlib.readPlist(HTTPSignedManageHandler.Requested("devloper.conf"))
		for index in result['devs']:
			try:
				print index
				url = "http://127.0.0.1:8000/"
				url += "DeveloperLogin?developer="
				url += index["developer"]
				url += "&password="
				url += index["password"]
				for i in range(10):
					try:
						print url
						op = urllib2.urlopen(url)
						if op.getcode()!=200:
							continue
						resp = json.loads(op.read())
						if resp['status']=='ok':
							print resp
							break
						time.sleep(90)
					except Exception as e:
						print e
						pass
			except Exception as e:
				print e
				pass
	except:
		pass
def CallRepeatedly(interval, func, *args):
    stopped = Event()
    def loop():
        while not stopped.wait(interval): # the first call is in `interval` secs
            func(*args)
    Thread(target=loop).start()    
    return stopped.set
if __name__ == '__main__':
	while True:
		Login()
		time.sleep(60*60*3)