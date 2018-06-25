#!/usr/bin/env python
#-*- coding:utf-8 -*-
#reference:https://github.com/lludo/RunThisApp/blob/master/core/apple-services.php
#locations:./google_drive/workspace/RunThisApp.zip
#reference:https://github.com/fastlane/fastlane/blob/master/spaceship/spec/portal/portal_stubbing.rb
#locations:./google_drive/workspace/fastlane.zip
import os,sys,logging,urllib,urllib2,zlib,re,time,base64,datetime,random,string,socket
import urllib,httplib,json,Queue,gzip,plistlib,logging,subprocess,tempfile,shutil,zipfile,glob
from random import randint
from StringIO import StringIO
from os import listdir
from os.path import isfile, join
from BaseHTTPServer   import BaseHTTPRequestHandler, HTTPServer , test as _test
from SimpleHTTPServer import SimpleHTTPRequestHandler
from SocketServer import ThreadingMixIn
from urlparse import urlparse
import tempfile
import shutil, errno
import OpenSSL
import multiprocessing
import threading
import hashlib
import io
import zlib
from threading import Event, Thread
import random
from random import choice
from string import ascii_uppercase
from random import randint
############################################################################
#pip install pyopenssl
############################################################################
cookie = ""
############################################################################
def SetCookieFromHeaders(headers):
	global cookie
	items = str(headers).split('\r\n')
	for index in items:
		if "Set-Cookie" in index:
			set_cookie = index[index.find(':') + 1:]
			if set_cookie[0]==' ':
				set_cookie = set_cookie[1:]
				set_cookie = set_cookie[0:set_cookie.find(';')]
			if cookie!=None and set_cookie in cookie:
				continue
			if cookie!="":
				cookie += "; "
			cookie += set_cookie
	#print 'cookie:',cookie
class Signer:
	@staticmethod
	def GetRootFromApp(payload):
		for dir_, _, files in os.walk(payload):
			filename, file_extension = os.path.splitext(dir_)
			if file_extension == ".app":
				return dir_
		return None
	@staticmethod
	def MobileProvisionToEntltiementsPlist(mobileprovision,entltiements_plist):
		if os.path.exists(mobileprovision)==False:
			 raise Exception("embedded.mobileprovision")
		if os.path.exists(entltiements_plist)==True:
			os.remove(entltiements_plist)
		bytes = open(mobileprovision, "rb").read()
		plists = plistlib.readPlist(StringIO(bytes[bytes.find('<plist'):bytes.find('plist>') + len('plist>')]))
		plists['get-task-allow'] = True
		plistlib.writePlist(plists['Entitlements'],entltiements_plist)
	@staticmethod
	def ResetEmbeddedMobileProvision(payload_app):
		re_mobileprovision = os.path.join(payload_app, "embedded.mobileprovision")
		re_codeSignature = os.path.join(payload_app, "_CodeSignature")
		if os.path.exists(re_mobileprovision)==True:
			os.remove(re_mobileprovision)
		if os.path.exists(re_codeSignature)==True:
			shutil.rmtree(re_codeSignature)
		return re_mobileprovision
	@staticmethod
	def CFBundleExecutable(payload_app,device_id = None):
		result = None
		cf_bundle_executable = None
		try:
			subprocess.call(('plutil', "-convert", "xml1", os.path.join(payload_app,"Info.plist")))
			result = plistlib.readPlist(os.path.join(payload_app,"Info.plist"))
			if device_id!=None:
				result['device_id'] = device_id
				plistlib.writePlist(result,os.path.join(payload_app,"Info.plist"))
			cf_bundle_executable = result['CFBundleExecutable']
		except:
			pass
		return cf_bundle_executable
	@staticmethod
	def CreateTemporaryCopy(path):
		out = os.path.join(HTTPSignedManageHandler.RootDirectory(), "signing")
		if not os.path.exists(out):
			os.makedirs(out)
		tmp = str(''.join(random.choice('abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890') for _ in range(10)))
		temp_path = os.path.join(out, str(tmp + ".app"))
		Signer.CopyAnything(path, temp_path)
		return temp_path
	@staticmethod
	def CreateSubDirsCacheSigned():
		out = os.path.join(HTTPSignedManageHandler.RootDirectory(), "signing")
		if not os.path.exists(out):
			os.makedirs(out)
		tmp = str(''.join(random.choice('abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890') for _ in range(10)))
		temp_path = os.path.join(out, str(tmp + ".app"))
		return temp_path
	@staticmethod
	def GetFileList(target):
		file_list = []
		for dir_, _, files in os.walk(target):
			for file in files:
				relDir = os.path.relpath(dir_, target)
				relFile = os.path.join(relDir, file)
				if relDir=='.':
					relFile = file
				file_list.append(relFile)
		return file_list
	@staticmethod
	def SignatureProcess(work_directory,device_id,mobileprovision,cert_name,target_app,out_app,is_return_app):
		payload_app = Signer.CreateTemporaryCopy(target_app)
		Signer.ResetEmbeddedMobileProvision(payload_app)
		shutil.copyfile(mobileprovision, os.path.join(payload_app, "embedded.mobileprovision"))
		entltiements_plist = os.path.join(work_directory, "entltiements.plist")
		Signer.MobileProvisionToEntltiementsPlist(mobileprovision,entltiements_plist)
		cf_bundle_executable = Signer.CFBundleExecutable(payload_app,device_id)
		shutil.copyfile(entltiements_plist,os.path.join(payload_app, "entltiements.plist"))
		signable_format = [".dylib",".so",".0",".vis",".pvr",".framework",".appex"]
		sub_dirs_cache = Signer.CreateSubDirsCacheSigned()
		modify_files = []
		for format in signable_format:
			for root, dirs, files in os.walk(payload_app):
				for file in files:
					try:
						filename, file_extension = os.path.splitext(root)
						relative_path = root.replace(payload_app,'')
						if file.endswith(format):
							subprocess.call(['/usr/bin/codesign',"-vvv", "-fs",cert_name,"--no-strict", "--entitlements=" + entltiements_plist, os.path.join(root, file)])
							if len(relative_path)>=1 or is_return_app==False:
								Signer.CopyAnything(root, os.path.join(sub_dirs_cache, relative_path[1:]))
						elif file_extension == format:
							subprocess.call(['/usr/bin/codesign',"-vvv", "-fs",cert_name,"--no-strict", "--entitlements=" + entltiements_plist, root])
							if len(relative_path)>=1 or is_return_app==False:
								Signer.CopyAnything(root, os.path.join(sub_dirs_cache, relative_path[1:]))
					except:
						pass
		subprocess.call(['/usr/bin/codesign',"-vvv", "-fs",cert_name,"--no-strict", "--entitlements=" + entltiements_plist, payload_app])
		os.chdir(work_directory)
		if is_return_app==False:
			try:
				if not os.path.exists(sub_dirs_cache):
					os.makedirs(sub_dirs_cache)
			except:
				pass
			os.chdir(sub_dirs_cache)
			src_mobileprovision = os.path.join(payload_app, "embedded.mobileprovision")
			dst_mobileprovision = os.path.join(sub_dirs_cache, "embedded.mobileprovision")
			shutil.copyfile(src_mobileprovision,dst_mobileprovision)
			src_code_signature = os.path.join(payload_app, "_CodeSignature")
			dst_code_signature = os.path.join(sub_dirs_cache, "_CodeSignature")
			Signer.CopyAnything(src_code_signature,dst_code_signature)
			shutil.copyfile(os.path.join(payload_app, cf_bundle_executable),os.path.join(sub_dirs_cache, cf_bundle_executable))
			shutil.copyfile(os.path.join(payload_app,"Info.plist"),os.path.join(sub_dirs_cache, "Info.plist"))
			shutil.copyfile(entltiements_plist,os.path.join(sub_dirs_cache, "entltiements.plist"))
			modify_files.extend(Signer.GetFileList(sub_dirs_cache))
			filename, file_extension = os.path.splitext(target_app)
			theplist = {}
			theplist['root'] = str("Payload" + "/" + str(cf_bundle_executable + ".app"))
			theplist['patchs'] = modify_files
			plistlib.writePlist(theplist,os.path.join(sub_dirs_cache, "fengzizhushou.plist"))
			subprocess.call(['/usr/bin/zip',"-qrm", out_app, ".", "Info.plist", "embedded.mobileprovision", "_CodeSignature/", cf_bundle_executable])
		else:
			work_app = os.path.join(work_directory, 'Payload')
			if not os.path.exists(work_app):
				os.makedirs(work_app)
			work_app = os.path.join(work_app, str(cf_bundle_executable + ".app"))
			Signer.CopyAnything(payload_app,work_app)
			shutil.copyfile(os.path.join(payload_app,"Info.plist"),os.path.join(work_app, "Info.plist"))
			shutil.copyfile(entltiements_plist,os.path.join(work_app, "entltiements.plist"))
			subprocess.call(['/usr/bin/zip',"-qrm", out_app, "Payload/", "WatchKitSupport/", "iTunesArtwork"])
		try:
			shutil.rmtree(payload_app)
		except:
			pass
		os.chdir(HTTPSignedManageHandler.RootDirectory())
	@staticmethod
	def SignatureImpl(device_id,mobileprovision,cert_name,target_app,is_return_app):
		work_directory = tempfile.mkdtemp()
		filename, file_extension = os.path.splitext(target_app)
		filename += str(''.join(choice(ascii_uppercase) for i in range(12)))
		filename += ".ipa"
		try:
			os.remove(filename)
		except:
			pass
		Signer.SignatureProcess(work_directory,device_id,mobileprovision,cert_name,target_app,filename,is_return_app)
		return filename
	@staticmethod
	def GetDownloadURL(AppVerId,filename):
		url = "http://sign.25fz.com"
		url += "/"
		url += os.path.basename(Signer.APPDirectory())
		url += "/"
		url += str(AppVerId)
		url += "/"
		url += os.path.basename(filename)
		return url
	@staticmethod
	def md5_for_file(f, block_size=2**20):
		md5 = hashlib.md5()
		while True:
			data = f.read(block_size)
			if not data:
				break
			md5.update(data)
		f.close()
		return md5.hexdigest()
	@staticmethod
	def IPAExtractor(ipa_file):
		out_directory = tempfile.mkdtemp()
		payload_app = None
		os.chdir(out_directory)
		app_name = None
		app_directory = None
		subprocess.call(['/usr/bin/unzip',ipa_file])
		for root, dirs, files in os.walk(out_directory):
			if len(dirs)==1 and '.app' in dirs[0]:
				payload_app = os.path.join(root, dirs[0])
				app_name = str(Signer.md5_for_file(open(os.path.join(payload_app, "Info.plist"),"rb")))
				app_name += ".app"
				app_directory = os.path.join(Signer.APPDirectory(), app_name)
				break
		try:
			Signer.CopyAnything(payload_app,app_directory)
			shutil.rmtree(out_directory)
		except:
			pass
		os.chdir(HTTPSignedManageHandler.RootDirectory())
		return app_name
	@staticmethod
	def DecompressIPA():
		for root, dirs, files in os.walk(HTTPSignedManageHandler.RootDirectory()):
			for file in files:
				if file.endswith(".ipa"):
					try:
						ipa_file = hashlib.md5(file.encode('utf-8')).hexdigest()
						ipa_file += ".ipa"
						ipa_file = os.path.join(root, ipa_file)
						shutil.move(os.path.join(root, file),ipa_file)
						Signer.IPAExtractor(ipa_file)
						os.remove(ipa_file)
						print(os.path.join(root, file))
					except:
						pass
	@staticmethod
	def APPDirectory():
		out = os.path.join(HTTPSignedManageHandler.RootDirectory(), "app")
		if not os.path.exists(out):
			os.makedirs(out)
		return out
	@staticmethod
	def GetOutPath(directory,file):
		out = os.path.join(directory, "out")
		if not os.path.exists(out):
			os.makedirs(out)
		return os.path.join(out, file)
	@staticmethod
	def CopyAnything(src, dst):
		try:
			shutil.copytree(src, dst)
		except OSError as exc: # python >2.5
			if exc.errno == errno.ENOTDIR:
				shutil.copy(src, dst)
			else: raise
class IDMSWebAuth:
	def __init__(self):
		self.firstName = None
		self.lastName = None
		self.myacinfo = None
		self.creationTimeStamp = None
		self.responseID = None
		self.userLocale = None
		self.resultCode = None
		self.resultString = None
		self.personId = None
		self.protocolVersion = None
		self.is_login_ok = False
		self.login_json = None
	def Login(self,appleid,password):
		global cookie
		cookie = ""
		self.login_json = None
		self.is_login_ok = False
		headers = {
			"Connection": "close",
			"User-Agent": "Xcode",
			"Content-Type": "application/x-www-form-urlencoded",
			"Accept": "text/x-xml-plist",
			"Accept-Encoding": "gzip, deflate",
			"Accept-Language": "zh-cn"
		}
		payload_data = {
			"appIdKey":"ba2ec180e6ca6e6c6a542255453b24d6e6e5b2be0cc48bc1b0d8ad64cfe0228f",
			"userLocale":"en_US",
			"protocolVersion":"A1234",
			"appleId":appleid,
			"password":password,
			"format":"plist",
		}
		self.is_login_ok = False
		request_https = urllib2.Request('https://idmsa.apple.com/IDMSWebAuth/clientDAW.cgi', urllib.urlencode(payload_data), headers)
		response = urllib2.urlopen(request_https)
		items = str(response.headers).split('\r\n')
		SetCookieFromHeaders(response.headers)
		if response.info().get('Content-Encoding') == 'gzip':
			buf = StringIO( response.read())
			f = gzip.GzipFile(fileobj=buf)
			data = f.read()
			return self.LoginResponse(data)
		else:
			return self.LoginResponse(response.read())
	def LoginResponse(self,json_data):
		try:
			tmp = None
			try:
				self.login_json = None
				tmp = StringIO(json_data)
				tmp = plistlib.readPlist(tmp)
			except:
				pass
			self.firstName = tmp['firstName']
			self.lastName = tmp['lastName']
			self.myacinfo = tmp['myacinfo']
			self.creationTimeStamp = tmp['creationTimeStamp']
			self.responseID = tmp['responseID']
			self.userLocale = tmp['userLocale']
			self.resultCode = tmp['resultCode']
			self.resultString = tmp['resultString']
			self.personId = tmp['personId']
			self.protocolVersion = tmp['protocolVersion']
			self.is_login_ok = True
			self.login_json = json_data
			return True
		except:
			return False
	def SetLoginOK(self,status):
		self.is_login_ok = status
	def IsLoginOK(self):
		return self.is_login_ok
	def LoginJson(self):
		return self.login_json
	def Print(self):
		print self.firstName
		print self.lastName
		print self.myacinfo
		print self.creationTimeStamp
		print self.responseID
		print self.userLocale
		print self.resultCode
		print self.resultString
		print self.personId
		print self.protocolVersion
class XCodeDeveloper(IDMSWebAuth):
	def __init__(self,appleid,password):
		global cookie
		logging.basicConfig(filename='apple_signed_server.log',level=logging.DEBUG)
		self.idms = IDMSWebAuth()
		self.developer_cookie = None
		if appleid!=None and password!=None and (len(appleid)>0 and len(password)>0):
			self.idms.Login(appleid,password)
			self.developer_cookie = str(cookie + "; myacinfo=" + self.idms.myacinfo)
		self.provisioningProfileId = None
		self.teamId = []
		self.name = []
		self.appIdId = None
		self.certificateId = []
		self.serialNumber = None
		self.deviceId = []
		self.list_teams = None
		self.list_devices = None
		self.list_appids = None
		self.list_certs = None
		self.list_profiles = None
		self.create_profile = None
	def listTeams(self,session_guid):
		try:
			self.list_teams = None
			if self.idms.IsLoginOK()==False:
				return
			payload_data = {
				"clientId":"XABBG36SBA",
				"myacinfo":self.idms.myacinfo,
				"protocolVersion":"QH65B2",
				"requestId":session_guid,
				"userLocale":"en_US",
			}
			payload_data = plistlib.writePlistToString(payload_data)
			response = None
			for index in range(3):
				try:
					request_https = urllib2.Request('https://developerservices2.apple.com/services/QH65B2/listTeams.action?clientId=XABBG36SBA', payload_data, self.Headers())
					response = urllib2.urlopen(request_https)
					break
				except:
					pass
			data = ""
			if response.info().get('Content-Encoding') == 'gzip':
				buf = StringIO( response.read())
				f = gzip.GzipFile(fileobj=buf)
				data = f.read()
			else:
				data = response.read()
			self.list_teams = data
			data = self.PListXmlToJSON(data)
			for index in data['teams']:
				self.teamId.append(index['teamId'])
				self.name.append(index['name'])
		except:
			pass
	def GetDeviceId(self,session_guid,ios_uuid):
		try:
			device_list = self.listDevices(session_guid)
			return device_list[ios_uuid]
		except:
			return None
	def listDevices(self,session_guid):
		try:
			self.list_devices = None
			if self.idms.IsLoginOK()==False:
				return
			payload_data = {
				"clientId":"XABBG36SBA",
				"myacinfo":self.idms.myacinfo,
				"protocolVersion":"QH65B2",
				"requestId":session_guid,
				"teamId":self.teamId[0],#from listTeams
				"userLocale":"en_US"
			}
			payload_data = plistlib.writePlistToString(payload_data)
			response = None
			for index in range(3):
				try:
					request_https = urllib2.Request('https://developerservices2.apple.com/services/QH65B2/ios/listDevices.action?clientId=XABBG36SBA', payload_data, self.Headers())
					response = urllib2.urlopen(request_https)
					break
				except:
					pass
			data = ''
			if response.info().get('Content-Encoding') == 'gzip':
				buf = StringIO( response.read())
				f = gzip.GzipFile(fileobj=buf)
				data = f.read()
			else:
				data = response.read()
			self.list_devices = data
			data = plistlib.readPlistFromString(data)
			devices = data['devices']
			device_list = {}
			for index in devices:
				device_list[index['deviceNumber']] = index['deviceId']
			return device_list
		except:
			pass
	def listAppIds(self,session_guid):
		try:
			self.list_appids = None
			if self.idms.IsLoginOK()==False:
				return
			payload_data = {
				"clientId":"XABBG36SBA",
				"myacinfo":self.idms.myacinfo,
				"protocolVersion":"QH65B2",
				"requestId":session_guid,
				"teamId":self.teamId[0],#from listTeams
				"userLocale":"en_US",
			}
			headers = self.Headers()
			headers['Origin'] = 'https://developer.apple.com'
			headers['Referer'] = 'https://developer.apple.com/account/ios/identifier/bundle'
			payload_data = plistlib.writePlistToString(payload_data)
			request_https = urllib2.Request('https://developerservices2.apple.com/services/QH65B2/ios/listAppIds.action?clientId=XABBG36SBA', payload_data, headers)
			response = urllib2.urlopen(request_https)
			if response.info().get('Content-Encoding') == 'gzip':
				buf = StringIO( response.read())
				f = gzip.GzipFile(fileobj=buf)
				data = f.read()
			else:
				data = response.read()
			self.list_appids = data
			return True
		except:
			pass
	def addDevice(self,session_guid,iPhone_udid,iPhone_name,is_get):
		try:
			self.deviceId = []
			if self.idms.IsLoginOK()==False:
				return
			payload_data = {
				"clientId":"XABBG36SBA",
				"myacinfo":self.idms.myacinfo,
				"protocolVersion":"QH65B2",
				"requestId":session_guid,
				"deviceNumber":iPhone_udid,#"0e83ff56a12a9cf0c7290cbb08ab6752181fb54b",#reference:https://bjango.com/help/iphoneudid/
				"name":iPhone_name,#from listTeams
				"teamId":self.teamId[0],#from listTeams
				"userLocale":"en_US"
			}
			payload_data = plistlib.writePlistToString(payload_data)
			response = None
			for index in range(3):
				try:
					request_https = urllib2.Request('https://developerservices2.apple.com/services/QH65B2/ios/addDevice.action?clientId=XABBG36SBA', payload_data, self.Headers())
					response = urllib2.urlopen(request_https)
					break
				except:
					pass
			data = ""
			if response!=None and response.info().get('Content-Encoding') == 'gzip':
				buf = StringIO( response.read())
				f = gzip.GzipFile(fileobj=buf)
				data = f.read()
			else:
				data = response.read()
			try:
				root = plistlib.readPlistFromString(data)
				my_device_id = root['device']['deviceId']
				logging.info('udid:'+iPhone_udid+'-deviceId:'+self.deviceId)
				self.deviceId.append(my_device_id)
			except:
				if is_get:
					my_device_id = self.GetDeviceId(session_guid,iPhone_udid)
					if my_device_id!=None:
						self.deviceId.append(my_device_id)
			return False
		except:
			pass
	def addAppId(self,identifier,appIdName,session_guid):
		try:
			self.appIdId = None
			if self.idms.IsLoginOK()==False:
				return
			entitlements = []
			payload_data = {
				"clientId":"XABBG36SBA",
				"myacinfo":self.idms.myacinfo,
				"protocolVersion":"QH65B2",
				"requestId":session_guid,
				"identifier":identifier,
				"entitlements":entitlements,
				"appIdName":appIdName,
				"name":appIdName,###?????????
				"teamId":self.teamId[0],#from listTeams
				"userLocale":"en_US"
			}
			payload_data = plistlib.writePlistToString(payload_data)
			response = None
			for index in range(3):
				try:
					request_https = urllib2.Request('https://developerservices2.apple.com/services/QH65B2/ios/addAppId.action?clientId=XABBG36SBA', payload_data, self.Headers())
					response = urllib2.urlopen(request_https)
					break
				except:
					pass
			data = ""
			if response.info().get('Content-Encoding') == 'gzip':
				buf = StringIO( response.read())
				f = gzip.GzipFile(fileobj=buf)
				data = self.PListXmlToJSON(f.read())
			else:
				data = self.PListXmlToJSON(response.read())
			try:
				self.appIdId = data['appId']['appIdId']
			except Exception as e:
				print e
			return False
		except:
			pass
	def submitDevelopmentCSR(self,csr_file,session_guid):
		if self.idms.IsLoginOK()==False:
			return
		fileContent = None
		with open(csr_file, mode='rb') as file: # b is important -> binary
			fileContent = file.read()
		payload_data = {
			"clientId":"XABBG36SBA",
			"myacinfo":self.idms.myacinfo,
			"protocolVersion":"QH65B2",
			"requestId":session_guid,
			"csrContent":fileContent,#reference:http://support.visiolink.com/hc/en-us/articles/200003861-How-to-Create-a-certificate-and-provisioning-for-signing-apps-iOS-
			"teamId":self.teamId[0],#from listTeams
			"userLocale":"en_US"
		}
		payload_data = plistlib.writePlistToString(payload_data)
		response = None
		for index in range(3):
			try:		
				request_https = urllib2.Request('https://developerservices2.apple.com/services/QH65B2/ios/submitDevelopmentCSR.action?clientId=XABBG36SBA', payload_data, self.Headers())
				response = urllib2.urlopen(request_https)
				break
			except:
				pass
		data = ""
		if response.info().get('Content-Encoding') == 'gzip':
			buf = StringIO( response.read())
			f = gzip.GzipFile(fileobj=buf)
			data = self.PListXmlToJSON(f.read())
		else:
			data = self.PListXmlToJSON(response.read())
		return False
	def downloadDevelopmentCert(self,session_guid,save_path):
		if self.idms.IsLoginOK()==False:
			return
		payload_data = {
			"clientId":"XABBG36SBA",
			"myacinfo":self.idms.myacinfo,
			"protocolVersion":"QH65B2",
			"requestId":session_guid,
			"teamId":self.teamId[0],#from listTeams
			"userLocale":"en_US"
		}
		payload_data = plistlib.writePlistToString(payload_data)
		response = None
		for index in range(3):
			try:		
				request_https = urllib2.Request('https://developerservices2.apple.com/services/QH65B2/ios/downloadDevelopmentCert.action?clientId=XABBG36SBA', payload_data, self.Headers())
				response = urllib2.urlopen(request_https)
				break
			except:
				pass
		data = ""
		if response.info().get('Content-Encoding') == 'gzip':
			buf = StringIO( response.read())
			f = gzip.GzipFile(fileobj=buf)
			data = self.PListXmlToJSON(f.read())
		else:
			data = self.PListXmlToJSON(response.read())
		self.certificateId.append(data['certificate']['certificateId'])
		self.serialNumber = data['certificate']['serialNumber']
		with open(save_path, 'wb') as f:
			f.write(data['certificate']['certContent'].data)
		return False
	def listAllDevelopmentCerts(self,session_guid):
		try:
			self.list_certs = None
			if self.idms.IsLoginOK()==False:
				return
			payload_data = {
				"clientId":"XABBG36SBA",
				"myacinfo":self.idms.myacinfo,
				"protocolVersion":"QH65B2",
				"requestId":session_guid,
				"teamId":self.teamId[0],#from listTeams
				"userLocale":"en_US"
			}
			payload_data = plistlib.writePlistToString(payload_data)
			response = None
			for index in range(3):
				try:
					request_https = urllib2.Request('https://developerservices2.apple.com/services/QH65B2/ios/listAllDevelopmentCerts.action?clientId=XABBG36SBA', payload_data, self.Headers())
					response = urllib2.urlopen(request_https)
					break
				except:
					pass
			data = ""
			if response.info().get('Content-Encoding') == 'gzip':
				buf = StringIO( response.read())
				f = gzip.GzipFile(fileobj=buf)
				data = f.read()
			else:
				data = response.read()
			self.list_certs = data
			data = self.PListXmlToJSON(data)
			certificates = data['certificates']
			for index in certificates:
				self.certificateId.append(index['certificateId'])
			return False
		except:
			pass
	def listProvisioningProfiles(self,session_guid):
		try:
			self.list_profiles = None
			if self.idms.IsLoginOK()==False:
				return
			payload_data = {
				"clientId":"XABBG36SBA",
				"myacinfo":self.idms.myacinfo,
				"protocolVersion":"QH65B2",
				"requestId":session_guid,
				"teamId":self.teamId[0],#from listTeams
				"userLocale":"en_US",
				"includeInactiveProfiles":True
			}
			payload_data = plistlib.writePlistToString(payload_data)
			response = None
			for index in range(3):
				try:
					request_https = urllib2.Request('https://developerservices2.apple.com/services/QH65B2/ios/listProvisioningProfiles.action?clientId=XABBG36SBA', payload_data, self.Headers())
					response = urllib2.urlopen(request_https)
					break
				except:
					pass
			data = ""
			if response.info().get('Content-Encoding') == 'gzip':
				buf = StringIO( response.read())
				f = gzip.GzipFile(fileobj=buf)
				data = f.read()
			else:
				data = response.read()
			self.list_profiles = data
			return False
		except:
			pass
	def revokeDevelopmentCert(self,session_guid):
		if self.idms.IsLoginOK()==False:
			return
		payload_data = {
			"clientId":"XABBG36SBA",
			"myacinfo":self.idms.myacinfo,
			"protocolVersion":"QH65B2",
			"requestId":session_guid,
			"serialNumber":self.serialNumber,
			"teamId":self.teamId[0],#from listTeams
			"userLocale":"en_US"
		}
		payload_data = plistlib.writePlistToString(payload_data)
		request_https = urllib2.Request('https://developerservices2.apple.com/services/QH65B2/ios/revokeDevelopmentCert.action?clientId=XABBG36SBA', payload_data, self.Headers())
		response = urllib2.urlopen(request_https)
		is_parse_ok = False
		if response.info().get('Content-Encoding') == 'gzip':
			buf = StringIO( response.read())
			f = gzip.GzipFile(fileobj=buf)
			data = f.read()
			#print data
			is_parse_ok = True
		else:
			data = response.read()
		#logging.info(str(sys._getframe().f_code.co_name))
		return is_parse_ok
	def genProvisioningProfile(self,session_guid,profile_name,is_regen):
		try:
			self.create_profile = None
			if self.idms.IsLoginOK()==False:
				return
			#iOS Development="distributionType":"limited"
			#"iOS Distribution"="distributionType": "store"
			payload_data = {
				"clientId":"XABBG36SBA",
				"myacinfo":self.idms.myacinfo,
				"protocolVersion":"QH65B2",
				"requestId":session_guid,
				"appIdId":self.appIdId,
				"deviceIds":self.deviceId,
				"certificateIds":self.certificateId,
				"distributionType":"limited",
				"provisioningProfileName":profile_name,
				"teamId":self.teamId[0],#from listTeams
				"userLocale":"en_US"
			}
			#print str(sys._getframe().f_code.co_name),':',payload_data
			payload_data = plistlib.writePlistToString(payload_data)
			response = None
			for index in range(3):
				try:
					request_https = None
					if is_regen==True:
						request_https = urllib2.Request('https://developerservices2.apple.com/services/QH65B2/ios/regenProvisioningProfile.action?clientId=XABBG36SBA', payload_data, self.Headers())
					else:
						request_https = urllib2.Request('https://developerservices2.apple.com/services/QH65B2/ios/createProvisioningProfile.action?clientId=XABBG36SBA', payload_data, self.Headers())
					response = urllib2.urlopen(request_https)
					break
				except:
					pass
			if response.info().get('Content-Encoding') == 'gzip':
				buf = StringIO( response.read())
				f = gzip.GzipFile(fileobj=buf)
				data = self.PListXmlToJSON(f.read())
			else:
				data = self.PListXmlToJSON(response.read())
			self.create_profile = data
		except:
			pass
	def downloadProfile(self,session_guid,save_path):
		try:
			if self.idms.IsLoginOK()==False:
				return
			payload_data = {
				"clientId":"XABBG36SBA",
				"myacinfo":self.idms.myacinfo,
				"protocolVersion":"QH65B2",
				"requestId":session_guid,
				"appIdId":self.appIdId,
				"teamId":self.teamId[0],#from listTeams
				"userLocale":"en_US"
			}
			payload_data = plistlib.writePlistToString(payload_data)
			response = None
			for index in range(3):
				try:
					request_https = urllib2.Request('https://developerservices2.apple.com/services/QH65B2/ios/downloadTeamProvisioningProfile.action?clientId=XABBG36SBA', payload_data, self.Headers())
					response = urllib2.urlopen(request_https)
					break
				except:
					pass
			data = ""
			if response!=None and response.info().get('Content-Encoding') == 'gzip':
				buf = StringIO( response.read())
				f = gzip.GzipFile(fileobj=buf)
				data = self.PListXmlToJSON(f.read())
			else:
				data = self.PListXmlToJSON(response.read())
			try:
				self.provisioningProfileId = data['provisioningProfile']['provisioningProfileId']
				with open(save_path, 'wb') as f:
					f.write(data['provisioningProfile']['encodedProfile'].data)
			except Exception as e:
				print e
			return False
		except:
			pass
	def deleteProvisioningProfile(self,session_guid):
		if self.idms.IsLoginOK()==False:
			return
		payload_data = {
			"clientId":"XABBG36SBA",
			"myacinfo":self.idms.myacinfo,
			"protocolVersion":"QH65B2",
			"requestId":session_guid,
			"provisioningProfileId":self.provisioningProfileId,
			"teamId":self.teamId[0],#from listTeams
			"userLocale":"en_US"
		}
		payload_data = plistlib.writePlistToString(payload_data)
		request_https = urllib2.Request('https://developerservices2.apple.com/services/QH65B2/ios/deleteProvisioningProfile.action?clientId=XABBG36SBA', payload_data, self.Headers())
		response = urllib2.urlopen(request_https)
		is_parse_ok = False
		if response.info().get('Content-Encoding') == 'gzip':
			buf = StringIO( response.read())
			f = gzip.GzipFile(fileobj=buf)
			data = f.read()
			is_parse_ok = True
			#print data
		else:
			data = response.read()
		#logging.info(str(sys._getframe().f_code.co_name))
		return is_parse_ok
	def Headers(self):
		headers = {
			"Connection": "close",
			"User-Agent": "Xcode",
			"Content-Type": "text/x-xml-plist",
			"X-Xcode-Version": "9.1",
			"Accept": "text/x-xml-plist",
			"Accept-Encoding": "gzip, deflate",
			"Accept-Language": "zh-cn",
			"Cookie":self.developer_cookie
		}
		return headers
	def PListXmlToJSON(self,data):
		try:
			json_data = StringIO(data)
			json_data = plistlib.readPlist(json_data)
			return json_data
		except:
			return data
class MultiArchSet:
	@staticmethod
	def MultiArchSet_init():
		multi_arch_set = MultiArchSet()
		return multi_arch_set
	@classmethod
	def __init__(self):
		self.__xcode_developer = XCodeDeveloper(None,None)
		self.__issued_to_signer = None
	@classmethod
	def MultiArchSet_LoginOK(self):
		self.__xcode_developer.idms.SetLoginOK(True)
	@classmethod
	def MultiArchSet_developer_cookie(self,str):
		self.__xcode_developer.developer_cookie = None
		self.__xcode_developer.developer_cookie = str
	@classmethod
	def MultiArchSet_idms_myacinfo(self,str):
		self.__xcode_developer.idms.myacinfo = None
		self.__xcode_developer.idms.myacinfo = str
	@classmethod
	def MultiArchSet_idms_responseID(self,str):
		self.__xcode_developer.idms.responseID = None
		self.__xcode_developer.idms.responseID = str
	@classmethod
	def MultiArchSet_teamId(self,str):
		self.__xcode_developer.teamId = []
		self.__xcode_developer.teamId.append(str)
	@classmethod
	def MultiArchSet_appIdId(self,str):
		self.__xcode_developer.appIdId = None
		self.__xcode_developer.appIdId = str
	@classmethod
	def MultiArchSet_deviceId(self,str):
		self.__xcode_developer.deviceId = []
		self.__xcode_developer.deviceId.append(str)
	@classmethod
	def MultiArchSet_deviceIds(self,str):
		self.__xcode_developer.deviceId = []
		self.__xcode_developer.deviceId = str
	@classmethod
	def MultiArchSet_certificateId(self,str):
		self.__xcode_developer.certificateId = str
	@classmethod
	def MultiArchSetInternal_downloadProfile(self,out_provision_path):
		self.__xcode_developer.downloadProfile(self.__xcode_developer.idms.responseID,out_provision_path)
	@classmethod
	def MultiArchSetInternal_RequestedWriter(self,developer):
		try:
			result = {}
			result['cookie'] = self.__xcode_developer.developer_cookie
			result['myacinfo'] = self.__xcode_developer.idms.myacinfo
			result['responseID'] = self.__xcode_developer.idms.responseID
			result['teamId'] = self.__xcode_developer.teamId[0]
			result['certificateId'] = self.__xcode_developer.certificateId
			result['certificateName'] = self.__issued_to_signer
			plistlib.writePlist(result,HTTPSignedManageHandler.Requested(developer))
		except:
			pass
	@classmethod
	def MultiArchSetInternal_RequestedReader(self,developer):
		try:
			result = plistlib.readPlist(HTTPSignedManageHandler.Requested(developer))
			self.MultiArchSet_developer_cookie(result['cookie'])
			self.MultiArchSet_idms_myacinfo(result['myacinfo'])
			self.MultiArchSet_idms_responseID(result['responseID'])
			self.MultiArchSet_teamId(result['teamId'])
			self.MultiArchSet_certificateId(result['certificateId'])
			self.__issued_to_signer = result['certificateName']
			self.MultiArchSet_LoginOK()
		except:
			pass
	@classmethod
	def MultiArchSetWebAPI_login(self,appleid,password):
		global cookie
		result = {}
		self.__issued_to_signer = None
		self.__xcode_developer.idms = IDMSWebAuth()
		self.__xcode_developer.idms.Login(appleid,password)
		if self.__xcode_developer.idms.IsLoginOK():
			self.MultiArchSet_developer_cookie(str(cookie + "; myacinfo=" + self.__xcode_developer.idms.myacinfo))
			self.__xcode_developer.listTeams(self.__xcode_developer.idms.responseID)
			self.__xcode_developer.listDevices(self.__xcode_developer.idms.responseID)
			self.__xcode_developer.listAppIds(self.__xcode_developer.idms.responseID)
			self.__xcode_developer.listAllDevelopmentCerts(self.__xcode_developer.idms.responseID)
			self.__xcode_developer.listProvisioningProfiles(self.__xcode_developer.idms.responseID)
			certificate = HTTPSignedManageHandler.DeveloperCER(appleid)
			self.__xcode_developer.downloadDevelopmentCert(self.__xcode_developer.idms.responseID,certificate)
			x509 = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_ASN1,open(certificate, "rb").read())
			self.__issued_to_signer = x509.get_subject().CN
		if self.__xcode_developer.idms.IsLoginOK():
			result['login_status'] = self.__xcode_developer.idms.IsLoginOK()
			result['login_json'] = self.__xcode_developer.idms.LoginJson()
			result['login_cookies'] = self.__xcode_developer.developer_cookie
			result['list_teams'] = self.__xcode_developer.list_teams
			result['list_devices'] = self.__xcode_developer.list_devices
			result['list_appids'] = self.__xcode_developer.list_appids
			result['list_certs'] = self.__xcode_developer.list_certs
			result['list_profiles'] = self.__xcode_developer.list_profiles
			self.MultiArchSetInternal_RequestedWriter(appleid)
		return result
	
	@classmethod
	def MultiArchSetWebAPI_addDevice(self,device_udid,device_name):
		try:
			self.__xcode_developer.addDevice(self.__xcode_developer.idms.responseID,device_udid,device_name,True)
			return self.__xcode_developer.deviceId
		except:
			return []
	@classmethod
	def MultiArchSetWebAPI_addAppId(self,appId,appIdName):
		try:
			self.__xcode_developer.addAppId(appId,appIdName,self.__xcode_developer.idms.responseID)
			return self.__xcode_developer.appIdId
		except:
			return None
	@classmethod
	def MultiArchSetWebAPI_genProvisioningProfile(self,appid):
		profile_name = HTTPSignedManageHandler.ProfileName(appid)
		self.__xcode_developer.genProvisioningProfile(self.__xcode_developer.idms.responseID,profile_name,False)
		return self.__xcode_developer.create_profile
	@classmethod
	def MultiArchSetWebAPI_regenProvisioningProfile(self,appid):
		profile_name = HTTPSignedManageHandler.ProfileName(appid)
		self.__xcode_developer.genProvisioningProfile(self.__xcode_developer.idms.responseID,profile_name,True)
		return self.__xcode_developer.create_profile
	@classmethod
	def MultiArchSetWebAPI_SignatureAPP(self,developer,device_id,appid,app_dir,is_return_app):
		try:
			self.MultiArchSetWebAPI_regenProvisioningProfile(appid)
			profile_in = HTTPSignedManageHandler.ProfilePath(developer)
			self.MultiArchSetInternal_downloadProfile(profile_in)
			out_app = Signer.SignatureImpl(device_id,profile_in,self.__issued_to_signer,app_dir,is_return_app)
			return out_app
		except:
			return "except."
class PairDeveloper:
	def StoringFiles(self,developer,is_available_app):
		os.chdir(HTTPSignedManageHandler.RootDirectory())
		out = os.path.join(HTTPSignedManageHandler.RootDirectory(), "developer")
		if not os.path.exists(out):
			os.makedirs(out)
		out = os.path.join(out, developer)
		if not os.path.exists(out):
			os.makedirs(out)
		if is_available_app:
			return os.path.join(out, developer + ".ables_app")
		else:
			return os.path.join(out, developer + ".parts_app")
	def PairDeviceIdToDeveloper(self,developer,device_id,is_available_app):
		storing_data = []
		try:
			result = plistlib.readPlist(self.StoringFiles(developer,is_available_app))
			storing_data = result['DeviceIds']
			if device_id in storing_data:
				return True
		except:
			pass
		return False
	def PairSigntureAPP(self,developer,app_ver_id,is_available_app):
		os.chdir(HTTPSignedManageHandler.RootDirectory())
		out = os.path.join(HTTPSignedManageHandler.RootDirectory(), "developer")
		out = os.path.join(out, developer)
		if is_available_app:
			out = os.path.join(out, "ables_app")
		else:
			out = os.path.join(out, "parts_app")
		if not os.path.exists(out):
			os.makedirs(out)
		out = os.path.join(out, app_ver_id + ".ipa")
		return out
	def GetDeviceIdAPP(self,target_ipa, out_ipa_file):
		os.chdir(HTTPSignedManageHandler.RootDirectory())
		out = os.path.join(Signer.APPDirectory(), "tmp")
		if not os.path.exists(out):
			os.makedirs(out)
		out = os.path.join(out, out_ipa_file)
		Signer.CopyAnything(target_ipa, out)
		return "tmp"
	def GetDeviceIdId(self,developer,device_id,is_available_app):
		storing_data = []
		try:
			result = plistlib.readPlist(self.StoringFiles(developer,is_available_app))
			deviceIdId = result.get(device_id, None)
			return deviceIdId
		except:
			pass
		return None
	def AddDeviceIdToDeveloper(self,developer,device_id,device_ids,is_available_app):
		result = {}
		deviceIdId = None
		try:
			result = plistlib.readPlist(self.StoringFiles(developer,is_available_app))
			deviceIdId = result.get(device_id, None)
			if deviceIdId != None:
				return
		except:
			pass
		result[device_id] = device_ids
		plistlib.writePlist(result,self.StoringFiles(developer,is_available_app))
	def AddIPAToDeveloperDirs(self,developer,app_src,app_ver_id,is_available_app):
		Signer.CopyAnything(app_src, self.PairSigntureAPP(developer,app_ver_id,is_available_app))
##############################################################################################
class HTTPSignedServer(ThreadingMixIn, HTTPServer):
	pass
class HTTPSignedRequestHandler(BaseHTTPRequestHandler):
	def do_GET(self):
		query = urlparse(self.path).query
		os.chdir(HTTPSignedManageHandler.RootDirectory())
		if cmp(self.path[0:len('/DeveloperLogin')],'/DeveloperLogin')==0:
			try:
				developer = None
				password = None
				try:
					query_components = dict(qc.split("=") for qc in query.split("&"))
					developer = urllib.unquote(query_components["developer"])
					password = urllib.unquote(query_components["password"])
				except Exception , e:
					print e
				if password==None or developer==None or len(password)==0 or len(developer)==0:
					self.StatusFailed()
					return
				start_time = time.time()
				multi_arch_set = MultiArchSet.MultiArchSet_init()
				data = multi_arch_set.MultiArchSetWebAPI_login(developer,password)
				json.dump(data,open(HTTPSignedManageHandler.Developer(developer),"wb"))
				if data['login_status']==True:
					HTTPSignedManageHandler.DeviceloperConfWriter(developer,password)
					msg = {}
					msg['login'] = 'OK'
					self.StatusOK(msg)
				else:
					self.StatusFailed()
				print("--- %s seconds ---" % (time.time() - start_time))
			except Exception , e:
				print e
				self.StatusExcept()
		elif cmp(self.path[0:len('/PairDevice')],'/PairDevice')==0:
			try:
				developer = None
				device_udid = None 
				device_name = None
				try:
					query_components = dict(qc.split("=") for qc in query.split("&"))
					developer = urllib.unquote(query_components["developer"])
					device_udid = urllib.unquote(query_components["udid"])
					device_name = urllib.unquote(query_components["name"])
				except Exception , e:
					print e
				if developer==None or device_udid==None or device_name==None:
					self.StatusFailed()
					return
				start_time = time.time()
				multi_arch_set = MultiArchSet.MultiArchSet_init()
				multi_arch_set.MultiArchSetInternal_RequestedReader(developer)
				device_ids = multi_arch_set.MultiArchSetWebAPI_addDevice(device_udid,device_name)
				if len(device_ids)==1:
					msg = {}
					msg['DeviceId'] = device_ids[0]
					self.StatusOK(msg)
				else:
					self.StatusFailed()
				print("--- %s seconds ---" % (time.time() - start_time))
			except Exception , e:
				print e
				self.StatusExcept()
		elif cmp(self.path[0:len('/PairAPPId')],'/PairAPPId')==0:
			try:
				developer = None
				appId = None
				appIdName = None
				deviceId = None
				try:
					query_components = dict(qc.split("=") for qc in query.split("&"))
					developer = urllib.unquote(query_components["developer"])
					appId = urllib.unquote(query_components["appId"])
					appIdName = urllib.unquote(query_components["appIdName"])
					deviceId = urllib.unquote(query_components["deviceId"])
				except Exception , e:
					print e
				if developer==None or appId==None or appIdName==None or deviceId==None:
					self.StatusFailed()
					return
				start_time = time.time()
				multi_arch_set = MultiArchSet.MultiArchSet_init()
				multi_arch_set.MultiArchSetInternal_RequestedReader(developer)
				appIdId = multi_arch_set.MultiArchSetWebAPI_addAppId(appId,appIdName)
				if appIdId!=None:
					multi_arch_set.MultiArchSet_deviceId(deviceId)
					multi_arch_set.MultiArchSetWebAPI_genProvisioningProfile(appId)
					msg = {}
					msg['appIdId'] = appIdId
					self.StatusOK(msg)
				else:
					self.StatusFailed()
				print("--- %s seconds ---" % (time.time() - start_time))
			except Exception , e:
				print e
				self.StatusExcept()
		elif cmp(self.path[0:len('/SignatureAPP')],'/SignatureAPP')==0:
			try:
				developer = None
				appIdId = None
				deviceId = None
				appId = None
				AppVerId = None
				ReturnAPP = ""
				try:
					query_components = dict(qc.split("=") for qc in query.split("&"))
					developer = urllib.unquote(query_components["developer"])
					deviceId = urllib.unquote(query_components["deviceId"])
					AppVerId = urllib.unquote(query_components["AppVerId"])
					ReturnAPP = urllib.unquote(query_components["ReturnAPP"])
				except Exception , e:
					print e
				if developer==None or deviceId==None or AppVerId==None:
					self.StatusFailed()
					return
				pair_developer = PairDeveloper()
				start_time = time.time()
				#if pair_developer.PairDeviceIdToDeveloper(developer,deviceId,(ReturnAPP=="all")):
					#target_ipa = pair_developer.PairSigntureAPP(developer, AppVerId, (ReturnAPP=="all"))
					#if os.path.exists(target_ipa):
						#out_ipa_file = AppVerId
						#out_ipa_file += ".ipa"
						#msg = {}
						#msg['APP'] = Signer.GetDownloadURL(pair_developer.GetDeviceIdAPP(target_ipa, out_ipa_file),out_ipa_file)
						#self.StatusOK(msg)
						#return
				multi_arch_set = MultiArchSet.MultiArchSet_init()
				multi_arch_set.MultiArchSetInternal_RequestedReader(developer)
				is_skip_web = True
				device_ids = pair_developer.GetDeviceIdId(developer,deviceId,(ReturnAPP=="all"))
				if device_ids == None:
					is_skip_web = False
					device_ids = multi_arch_set.MultiArchSetWebAPI_addDevice(deviceId,deviceId)
					if len(device_ids)>=1:
						pair_developer.AddDeviceIdToDeveloper(developer,deviceId,device_ids,(ReturnAPP=="all"))
				if len(device_ids)>=1:
					multi_arch_set.MultiArchSet_deviceIds(device_ids)
					appId = HTTPSignedManageHandler.AppId(developer)
					appIdId = HTTPSignedManageHandler.GetDeviceloperAppIdId(developer)
					if appIdId==None:
						appIdName = "Xcode iOS App ID "
						appIdName += appId
						appIdName = appIdName.replace(".*","")
						appIdName = appIdName.replace("."," ")
						appIdId = multi_arch_set.MultiArchSetWebAPI_addAppId(appId,appIdName)
						if is_skip_web==False:
							multi_arch_set.MultiArchSetWebAPI_genProvisioningProfile(appId)
						HTTPSignedManageHandler.SetDeviceloperAppIdId(developer,appId,appIdId)
					multi_arch_set.MultiArchSet_appIdId(appIdId)
					in_app = Signer.GetRootFromApp(os.path.join(Signer.APPDirectory(), AppVerId))
					msg = {}
					relative_file = multi_arch_set.MultiArchSetWebAPI_SignatureAPP(developer,deviceId,appId,in_app,(ReturnAPP=="all"))
					msg['APP'] = Signer.GetDownloadURL(AppVerId,relative_file)
					self.StatusOK(msg)
					print("--- %s seconds ---" % (time.time() - start_time))
				else:
					self.StatusFailed()
			except Exception , e:
				print e
				self.StatusExcept()
		elif cmp(self.path[0:len('/DecompressIPA')],'/DecompressIPA')==0:
			Signer.DecompressIPA()
			self.ResponseTEXT(200,"status:ok")
		elif cmp(self.path[0:len('/app/')],'/app/')==0:
			siged_app = HTTPSignedManageHandler.RootDirectory()
			siged_app += self.path
			if not os.path.exists(siged_app):
				self.StatusFailed()
				return
			with open(siged_app, 'rb') as content:
				self.send_response(200)
				self.send_header("Content-Type", 'application/octet-stream')
				self.end_headers()
				shutil.copyfileobj(content, self.wfile)
		else:
			self.StatusExcept()
	def ResponseTEXT(self,code,str):
		try:
			self.send_response(code)
			self.send_header("Content-type", "text/html")
			self.end_headers()
			self.wfile.write(str)
			self.wfile.close()
		except Exception , e:
			print e
	def StatusFailed(self):
		status = {}
		status["status"] = "failed"
		self.ResponseTEXT(200,str(json.dumps(status)))
	def StatusExcept(self):
		status = {}
		status["status"] = "except"
		self.ResponseTEXT(200,str(json.dumps(status)))
	def StatusOK(self,msg):
		status = {}
		status["status"] = "ok"
		status["msg"] = msg
		self.ResponseTEXT(200,str(json.dumps(status)))
class HTTPSignedManageHandler:
	root_directory = None
	server_port = None
	@staticmethod
	def RootDirectory():
		if HTTPSignedManageHandler.root_directory==None:
			HTTPSignedManageHandler.root_directory = os.path.dirname(os.path.realpath(__file__))
		return HTTPSignedManageHandler.root_directory
	@staticmethod
	def RunSignedServer(HandlerClass=HTTPSignedRequestHandler,ServerClass=HTTPSignedServer):
		server_address = ('', HTTPSignedManageHandler.server_port)
		HandlerClass.protocol_version = "HTTP/1.0"
		httpd = ServerClass(server_address, HandlerClass)
		sa = httpd.socket.getsockname()
		print "Serving HTTP on", sa[0], "port", sa[1], "..."
		httpd.serve_forever()
	@staticmethod
	def Developer(account):
		os.chdir(HTTPSignedManageHandler.RootDirectory())
		out = os.path.join(HTTPSignedManageHandler.RootDirectory(), "developer")
		if not os.path.exists(out):
			os.makedirs(out)
		out = os.path.join(out, account)
		if not os.path.exists(out):
			os.makedirs(out)
		return os.path.join(out, account + ".json")
	@staticmethod
	def DeveloperCER(account):
		os.chdir(HTTPSignedManageHandler.RootDirectory())
		out = os.path.join(HTTPSignedManageHandler.RootDirectory(), "developer")
		if not os.path.exists(out):
			os.makedirs(out)
		out = os.path.join(out, account)
		if not os.path.exists(out):
			os.makedirs(out)
		return os.path.join(out, account + ".cer")
	@staticmethod
	def Requested(account):
		os.chdir(HTTPSignedManageHandler.RootDirectory())
		out = os.path.join(HTTPSignedManageHandler.RootDirectory(), "developer")
		if not os.path.exists(out):
			os.makedirs(out)
		out = os.path.join(out, account)
		if not os.path.exists(out):
			os.makedirs(out)
		return os.path.join(out, account + ".plist")
	@staticmethod
	def AppId(developer):
		appId = "com.signed.server."
		appId += str(zlib.crc32(developer) & 0xffffffff)
		appId += ".*"
		return appId
	@staticmethod
	def ProfileName(appid):
		return str(appid + " limited")
	@staticmethod
	def ProfilePath(developer):
		os.chdir(HTTPSignedManageHandler.RootDirectory())
		out = os.path.join(HTTPSignedManageHandler.RootDirectory(), "developer")
		if not os.path.exists(out):
			os.makedirs(out)
		out = os.path.join(out, developer)
		if not os.path.exists(out):
			os.makedirs(out)
		return os.path.join(out, developer + ".mobileprovision")
	@staticmethod
	def SetDeviceloperAppIdId(developer,appId,appIdId):
		try:
			out = os.path.join(HTTPSignedManageHandler.RootDirectory(), "developer")
			if not os.path.exists(out):
				os.makedirs(out)
			out = os.path.join(out, developer)
			if not os.path.exists(out):
				os.makedirs(out)
			result = {}
			result["appId"] = appId
			result["appIdId"] = appIdId
			plistlib.writePlist(result,os.path.join(out, developer + ".appid"))
		except:
			pass
	@staticmethod
	def GetDeviceloperAppIdId(developer):
		try:
			out = os.path.join(HTTPSignedManageHandler.RootDirectory(), "developer")
			if not os.path.exists(out):
				os.makedirs(out)
			out = os.path.join(out, developer)
			if not os.path.exists(out):
				os.makedirs(out)
			result = plistlib.readPlist(os.path.join(out, developer + ".appid"))
			return result["appIdId"]
		except:
			return None
	@staticmethod
	def DeviceloperConfWriter(developer,password):
		try:
			result = {}
			conf = {}
			conf_array = HTTPSignedManageHandler.DeviceloperConfReader()
			is_exist = True
			for index in conf_array:
				if developer == index["developer"] and password==index["password"]:
					is_exist = False
			if is_exist:
				conf['developer'] = developer
				conf['password'] = password
				conf_array.append(conf)
				result['devs'] = conf_array
				plistlib.writePlist(result,HTTPSignedManageHandler.Requested("devloper.conf"))
		except:
			pass
	@staticmethod
	def DeviceloperConfReader():
		try:
			result = plistlib.readPlist(HTTPSignedManageHandler.Requested("devloper.conf"))
			return result['devs']
		except:
			return []
	@staticmethod
	def DeviceloperValidCheck():
		try:
			result = plistlib.readPlist(HTTPSignedManageHandler.Requested("devloper.conf"))
			for index in result['devs']:
				try:
					url = "http://127.0.0.1" + ":" + str(HTTPSignedManageHandler.server_port) + "/"
					url += "DeveloperLogin?developer="
					url += index["developer"]
					url += "&password="
					url += index["password"]
					print urllib2.urlopen(url).read()
				except:
					pass
		except:
			pass
def ProcessInternalThread(n,base_port):
	HTTPSignedManageHandler.server_port = n + base_port
	threads = threading.Thread(target=HTTPSignedManageHandler.RunSignedServer, args=[])
	threads.start()
	threads.join()
def CallRepeatedly(interval, func, *args):
    stopped = Event()
    def loop():
        while not stopped.wait(interval): # the first call is in `interval` secs
            func(*args)
    Thread(target=loop).start()    
    return stopped.set
def Test():
	process_array = []
	for index in range(30):
		base_port = 8000
		if HTTPSignedManageHandler.server_port==None:
			HTTPSignedManageHandler.server_port = index + base_port
			CallRepeatedly(60*60*3, HTTPSignedManageHandler.DeviceloperValidCheck)
		process = multiprocessing.Process(target=ProcessInternalThread, args=(index,base_port))
		process.start()
		process_array.append(process)
		time.sleep(1)
	for process in process_array:
		process.join()
if __name__ == '__main__':
	#urllib2.install_opener(urllib2.build_opener(urllib2.ProxyHandler({"http" : '10.9.36.100:8888'})))
	process_array = []
	os.chdir(HTTPSignedManageHandler.RootDirectory())
	if HTTPSignedManageHandler.server_port==None:
		HTTPSignedManageHandler.server_port = 8001
		CallRepeatedly(60*60*3, HTTPSignedManageHandler.DeviceloperValidCheck)
		process = multiprocessing.Process(target=ProcessInternalThread, args=(0,8001))
		process.start()
		process_array.append(process)
	process = multiprocessing.Process(target=ProcessInternalThread, args=(0,8000))
	process.start()
	process_array.append(process)
	for process in process_array:
		process.join()