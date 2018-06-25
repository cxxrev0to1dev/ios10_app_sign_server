import os,time,urllib,urllib2,json,multiprocessing

def GetTaskVector():
	result = {}
	try:
		result['request_url'] = "http://sign.25fz.com/SignatureAPP?developer=502247331@qq.com&deviceId=8487364d605600d568e9153f7b05f077cd645d12&AppVerId=1000010000"
		result['response_url'] = "http://tg.fengzigame.com/Gonghui/anzhuang/wancheng?tagid=1000010000&udid=8487364d605600d568e9153f7b05f077cd645d12&url="
		op = urllib2.urlopen("http://tg.fengzigame.com/Gonghui/anzhuang/renwu")
		if op.getcode()!=200:
			return result
		resp = json.loads(op.read())
		url = "http://sign.25fz.com/" + "SignatureAPP?developer=" + resp["appleid"] + "&deviceId=" + resp["udid"] + "&AppVerId=" + resp["tagid"]
		result['request_url'] = url
		result['response_url'] = "http://tg.fengzigame.com/Gonghui/anzhuang/wancheng?tagid=" + resp["tagid"] + "&udid=" + resp["udid"] + "&url="
		return result
	except:
		return result
def TaskVectorMachine(process_msg):
	try:
		task_vecor = GetTaskVector()
		print task_vecor
		op = urllib2.urlopen(task_vecor['request_url'])
		if op.getcode()!=200:
			task_vecor['response_url'] += 'null'
			return task_vecor['response_url']
		resp = json.loads(op.read())
		if resp['status']=='ok':
			if "except" in resp['msg']['APP']:
				task_vecor['response_url'] += 'null'
			else:
				task_vecor['response_url'] += resp['msg']['APP']
		else:
			task_vecor['response_url'] += 'null'
	except Exception, e:
		task_vecor['response_url'] += 'null'
		print e
	return task_vecor['response_url']
def RunTaskVector():
	try:
		pool = multiprocessing.Pool(processes = 15)
		result = []
		for index in xrange(10):
			msg = ("hello %d" % (index))
			result.append(pool.apply_async(TaskVectorMachine, (index, )))
		pool.close()
		pool.join()
		for index_vector in result:
			try:
				status_url = index_vector.get()
				if status_url!='null':
					print status_url
					print urllib2.urlopen(status_url).read()
			except Exception, e:
				print e
	except:
		pass
if __name__ == '__main__':
	while True:
		RunTaskVector()
		time.sleep(5)