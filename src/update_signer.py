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
import apple_signed_server
############################################################################
#pip install pyopenssl
############################################################################
class Update:
	def __init__(self):
		self.key_developer = 'developer'
		self.key_app_ver_id = 'app_ver_id'
		self.key_update_ok = 'update_ok'
		self.key_down_url = 'down_url'
		self.key_filename = 'update_signer.plist'
	def AddToFile(self,developer,device_id,app_ver_id):
		result = {}
		try:
			result = plistlib.readPlist(self.GetFile())
			if result.get(device_id, None) != None:
				return
		except:
			pass
		data = {}
		data[self.key_developer] = developer
		data[self.key_app_ver_id] = app_ver_id
		data[self.key_update_ok] = False
		data[self.key_down_url] = 'https://www.baidu.com'
		result[device_id] = data
		plistlib.writePlist(result,self.GetFile())
	def IsUpdateOK(self,developer,device_id,app_ver_id):
		result = {}
		try:
			result = plistlib.readPlist(self.GetFile())
			if result.get(device_id, None) == None:
				return False
			return (result[device_id][self.key_update_ok]==True)
		except:
			pass
		return False
	def GetDownloadURL(self,developer,device_id,app_ver_id):
		result = {}
		try:
			result = plistlib.readPlist(self.GetFile())
			if result.get(device_id, None) == None:
				return ""
			return result[device_id][self.key_down_url]
		except:
			pass
		return ""
	def SetDownloadURL(self,developer,device_id,url):
		result = {}
		try:
			result = plistlib.readPlist(self.GetFile())
			if result.get(device_id, None) == None:
				return
			result[device_id][self.key_down_url] = url
		except:
			pass
		print result
		plistlib.writePlist(result,self.GetFile())
	def SetUpdateStatusBool(self,developer,device_id,status):
		result = {}
		try:
			result = plistlib.readPlist(self.GetFile())
			if result.get(device_id, None) == None:
				return
			result[device_id][self.key_update_ok] = status
		except:
			pass
		plistlib.writePlist(result,self.GetFile())
	def ResignImpl(self,update_plist):
		result = {}
		result = plistlib.readPlist(update_plist)
		for key, value in result.iteritems():
			try:
				device_id = key
				if value[self.key_update_ok]==False:
					print value[self.key_developer]
					print device_id
					print value[self.key_app_ver_id]
					url = apple_signed_server_v1_02.Sign(value[self.key_developer],device_id,value[self.key_app_ver_id])
					if url!=None and len(url)>0:
						self.SetDownloadURL(value[self.key_developer],device_id,url)
						self.SetUpdateStatusBool(value[self.key_developer],device_id,True)
			except:
				pass
	def GetUpdatePList(self):
		root = os.path.dirname(os.path.realpath(__file__))
		out = os.path.join(root, "developer")
		result = []
		for root, dirs, files in os.walk(out):
			if self.key_filename in files:
				pppp = os.path.join(root, self.key_filename)
				if pppp in result:
					continue
				result.append(pppp)
		list1 = result
		list2 = []
		[list2.append(i) for i in list1 if not i in list2]
		return list2
	def Resign(self):
		self.ResignImpl(self.GetFile())
	def GetFile(self):
		root = os.path.dirname(os.path.realpath(__file__))
		out = os.path.join(root, "developer")
		if not os.path.exists(out):
			os.makedirs(out)
		out = os.path.join(out,self.key_filename)
		return out
def CallRepeatedly(interval, func, *args):
    stopped = Event()
    def loop():
        while not stopped.wait(interval): # the first call is in `interval` secs
            func(*args)
    Thread(target=loop).start()    
    return stopped.set
if __name__ == '__main__':
	ss = Update()
	while True:
		ss.Resign()
		time.sleep(60*3)

#ss.AddToFile("502247331@qq.com","051457825f8885d3665fcc23123c2ce6","1035192537")
#print ss.IsUpdateOK("502247331@qq.com","051457825f8885d3665fcc23123c2ce6","1035192537")
#print ss.GetDownloadURL("502247331@qq.com","051457825f8885d3665fcc23123c2ce6","1035192537")