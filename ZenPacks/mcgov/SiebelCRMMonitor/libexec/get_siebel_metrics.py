#!/usr/bin/env python
import sys
import httplib, base64

username = "zenuser"
password = "password"
remote_server="mcgov_crm_gwy"
remote_port=7890

deviceName = sys.argv[1]
if deviceName == None:
   deviceName = 'siebsrvr.mcgov.gov'

remote_server = sys.argv[2]
remote_port = int(sys.argv[3])
username = sys.argv[4]
password = sys.argv[5]

auth = base64.encodestring("%s:%s" % (username, password))

headers = {"Authorization" : "Basic %s" % auth, "Accept": "text/plain"}

hconn = httplib.HTTPConnection(remote_server, remote_port)
try:
  hconn.request('GET','/getStats?server=' + deviceName + '&isFullMetrics=false', headers=headers)
  r1 = hconn.getresponse()
  if r1.status == 200:
    data1 = r1.read()
  else:
    data1 = ("ERROR from server: %s -- %s" % (r1.status,r1.reason))
  print data1
  hconn.close()
except Exception, ex:
   print "SIEBEL_STAT ERROR| General Error accessing Siebel server: %s" % str(ex)
