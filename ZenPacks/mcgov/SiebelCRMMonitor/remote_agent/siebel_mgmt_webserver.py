#!/usr/bin/env python
import sys
import getopt
import re
import winpexpect
import time
import BaseHTTPServer, cgi
from base64 import b64decode
from winservice import Service, instart, setOption, getOption
import socket
import logging
import logging.config

class SiebelHTTPServer(BaseHTTPServer.HTTPServer):
    def __init__(self, addr, handler):
       self.stop = False
       BaseHTTPServer.HTTPServer.__init__(self, addr, handler)


    def run_forever(self):
        """Handle one request at a time until doomsday."""
        while not self.stop:
            try:
                self.handle_request()
            except (IOError, socket.error), ex:
                if 'Bad file descriptor' in str(ex):
                    logger.exception("Skipping bad file error: %s" % (str(ex)))
                    pass
                else:
                    logger.exception("Raising caught error: %s" % (str(ex)))
                    raise

    def handle_error(self, request, client_address):
        """Handle an error gracefully.  Overridden from SocketServer."""

        logger.exception("handle_error caught error")

class WebRequestHandler(BaseHTTPServer.BaseHTTPRequestHandler):
    config_props = dict()
    parent = None

    def do_GET(self):
        authorization = self.headers.get('authorization')
	if (authorization == None):
	    self.send_response(401)
	    self.send_header('WWW-Authenticate', 'Basic realm="Siebel Srvrmgr"')
	    self.end_headers()
	    logger.error( "Missing auth header" )
	    self.wfile.write('Authentication failure')
	    return
	else:
	    (kind, data) = authorization.split(' ')
	    if (kind == 'Basic'):
	       (username, _, password) = b64decode(data).partition(':')
               if (username != config_props["web.username"] or password != config_props["web.password"]):
	          self.send_response(403)
	          self.send_header('WWW-Authenticate', 'Basic realm="Siebel Srvrmgr"')
	          self.end_headers()
	          logger.error( "Invalid auth header: %s -- %s" % (username,password) )
	          self.wfile.write('Authentication failure - Wrong user/password')
	          return

        if self.path.find('?') != -1:
            self.urlPath, self.query_string = self.path.split('?', 1)
        else:
            self.urlPath = self.path
            self.query_string = 'server=' + config_props.get("svc.mgmt.default.host", "UNKNOWN")
        
        logger.debug ("For path: %s the url is: %s and query is: %s" % (self.path,self.urlPath,self.query_string))
        
        
        if self.urlPath == config_props["web.path"]:
            qsl = dict(cgi.parse_qsl(self.query_string))
            logger.debug(qsl)
            
            servers = dict(cgi.parse_qsl(config_props["siebel.mgmt.server.map"]))
            #logger.debug(servers)
            
            hostServer = qsl.get("server", "UNKNOWN").upper()
            isFullMetrics = qsl.get("isFullMetrics", "FALSE").upper() == "TRUE"
            siebel_server = servers.get(hostServer, "UNKNOWN")
            if siebel_server == "UNKNOWN":
                self.send_error(500, "Missing valid server parameter: " + hostServer)
            else:
                self.send_response(200)
                self.send_header("Content-type", "text/plain")
                self.end_headers()
                logger.info("About to collect statistics for host: %s of siebel server: %s" % (hostServer,siebel_server))
                stats = getStatistics(siebel_server,hostServer, isFullMetrics)
                self.wfile.write(stats)
        else:
            self.send_error(404, "Requested resource not found")

    def log_message(self, format, *args):
        """Overridden from BaseHTTPRequestHandler because this method occasionally throws error when send_response(200) is called."""
        
        if logger.isEnabledFor(logging.DEBUG):
           logger.debug(args[0])

class SiebelMgmtSvc(Service):
    def start(self):
        logger.warn( "Starting the service" )
        startServer()
    def stop(self):
        logger.warn( "Stopping the service" )

def buildStatDict(stats, prefix='', keyIdx=0,valIdx=3, inc=0):
   statLines=stats.splitlines()
   logger.debug( statLines )
   statLines=statLines[2:-2]
   logger.debug( statLines )
   allStats = dict()
   keyInc = 0
   for aLine in statLines:
      logger.debug( aLine )
      if aLine.startswith("------"):
         logger.debug( "Skipping a line: %s" % (aLine) )
         continue
      lineEntries = aLine.split()
      logger.debug( lineEntries )
      if len(lineEntries) < valIdx+1:
         logger.debug( "Skipping a line: %s" % (aLine) )
         continue
      
      keyKey = prefix+lineEntries[keyIdx]
      if inc > 0:
          keyInc = keyInc + 1
          keyKey = keyKey + str(keyInc)
      allStats[keyKey] = lineEntries[valIdx]
   return allStats

def getStatistics(siebel_server, hostServer, isFullMetrics=False):
    child = None
    isError = False
    try:
        try:
            result = dict()
            errorPrefix = 'SIEBEL_STAT ERROR| '
            successPrefix = 'SIEBEL_STAT OK| '
    
            compNameMap = dict(cgi.parse_qsl(config_props["siebel.mgmt.components.map"]))
            metrics_scale = dict(cgi.parse_qsl(config_props["siebel.mgmt.metrics.scale.map"]))
            if metrics_scale == None:
               metrics_scale = dict()
               
            logger.debug( "Getting stat for enterprise: %s" % (config_props["siebel.enterprise"]) )
            svrmgr_call = 'srvrmgr.exe /g ' + config_props["siebel.gateway"] + ' /e ' + config_props["siebel.enterprise"] + ' /s ' + siebel_server + ' /u ' + config_props["siebel.user"] + ' /p ' + config_props["siebel.password"]
            svrmgr_prompt = 'srvrmgr:' + siebel_server + '>'
            child = winpexpect.winspawn(svrmgr_call)
            #time.sleep(15)
    
            logger.debug( "Checking for the prompt: %s" % (svrmgr_prompt) )
            child.expect (svrmgr_prompt, timeout=120)
            headerMsg = child.before 
        
        
            #Get Server status
            logger.info( "Getting the server status" )
            child.sendline ('list servers show SBLSRVR_NAME,HOST_NAME,SBLSRVR_STATE,START_TIME,END_TIME')
            child.expect (svrmgr_prompt, timeout=120)
            stats = child.before
            logger.debug( stats )
            serverPrefix = "Server_"
            oneStats = buildStatDict(stats, serverPrefix,0,2)
            logger.debug( oneStats )
            if oneStats.get(serverPrefix+siebel_server, None) == None:
                return buildNagioOut(errorPrefix + serverPrefix + 'STATE=3 ', result, isError=True)
        
            serverStatus = oneStats[serverPrefix+siebel_server].upper()
            del oneStats[serverPrefix+siebel_server]
            if serverStatus != 'RUNNING':
                return buildNagioOut(errorPrefix + serverPrefix + 'STATE=2 ', result, isError=True)
        
            result.update(oneStats)
            result[serverPrefix + 'STATE'] = '0'  #serverStatus
        
            components = config_props['siebel.mgmt.components.' + hostServer].split(',')
            taskComponents = config_props['siebel.mgmt.interactive.components.' + hostServer].split(',')
    
            #Get Components status
            logger.info( "Getting the component status" )
            child.sendline ('list component show CC_ALIAS,CG_ALIAS,CP_DISP_RUN_STATE,CP_START_TIME,CP_END_TIME')
            child.expect (svrmgr_prompt, timeout=120)
            stats = child.before
            compPrefix = 'comp_'
            oneStats = buildStatDict(stats, compPrefix,0,2)
            logger.debug( oneStats )
        
            for aSibelComp in components:
                aComp = compNameMap.get(aSibelComp, aSibelComp)
                if oneStats.get(compPrefix+aSibelComp, None) == None:
                    return buildNagioOut(errorPrefix + compPrefix+aComp + '_STATE=3 ', result, isError=True)
            
                compStatus = oneStats[compPrefix+aSibelComp].upper()
                #del oneStats[compPrefix+aSibelComp]
                if compStatus != 'RUNNING' and compStatus != 'ONLINE':
                    return buildNagioOut(errorPrefix + compPrefix+aComp + '_STATE=2 ', result, isError=True)
            
                logger.debug( oneStats )
                #result.update(oneStats)
                result[compPrefix+aComp + '_STATE'] = '0'  #compStatus
        
        
            #Get Running Tasks status for each Component
            logger.info( "Getting the component tasks status" )
            goodpctStr = config_props["siebel.mgmt.interactive.components.goodPct"]
            goodpct = -1
            if goodpctStr != None:
                goodpct = int(goodpctStr)
                
            for aSibelComp in taskComponents:
                aComp = compNameMap.get(aSibelComp, aSibelComp)
                taskPrefix = 'task_'+ aComp + '_'
    
                child.sendline ('list tasks for component ' + aSibelComp + ' show SV_NAME, CC_ALIAS, TK_PID, TK_DISP_RUNSTATE')
                child.expect (svrmgr_prompt, timeout=120)
                stats = child.before
                oneStats = buildStatDict(stats, taskPrefix,0,3, inc=1)
                logger.debug( oneStats )
                if len(oneStats) <= 0:
                    isError = True
                    logger.warn( "No active tasks found")
                    result[taskPrefix + 'STATE'] = '1'
                    #return buildNagioOut(errorPrefix + taskPrefix + 'STATE=1 ', result, isError=True)
        
                else:
                    errorTasks = 0
                    for aTask in oneStats.keys():
                        taskStatus = oneStats[aTask].upper()
                        if taskStatus != 'RUNNING' and taskStatus != 'COMPLETED'  and taskStatus != 'ONLINE':
                            errorTasks = errorTasks + 1
                            #result[taskPrefix + 'STATE'] = taskStatus
                           #return buildNagioOut(errorPrefix + taskPrefix + 'STATE=' + taskStatus + ' ', result, isError=True)
        
                    if errorTasks <= 0:
                        #result.update(oneStats)
                        result[taskPrefix + 'STATE'] = '0'  #taskStatus
                    else:
                        if goodpct < 0 or (((len(oneStats)-errorTasks)/len(oneStats))*100) > goodpct:
                           logger.warn( "More than allowed number of tasks are down: %s out of %s for task: %s" % (errorTasks,len(oneStats),taskPrefix))
                           result[taskPrefix + 'STATE'] = '2'
                           isError = True
                           
                    result[taskPrefix + 'TOTAL_TASKS'] = str(len(oneStats)-errorTasks)
        
            #Get statistics for each Component
            compErrors = 0
            logger.info( "Getting the component statistic list" )
            for aSibelComp in components:
                aComp = compNameMap.get(aSibelComp, aSibelComp)
                compPrefix = 'comp_'+ aComp + '_'
                logger.debug( "Getting stat for component: %s" % (aSibelComp) )
                child.sendline ('list statistics for component ' + aSibelComp + ' show STAT_ALIAS,SD_DATATYPE,SD_SUBSYSTEM,CURR_VAL,STAT_NAME')
                child.expect (svrmgr_prompt, timeout=120)
                stats = child.before
                oneStats = buildStatDict(stats, compPrefix,0,3)
                logger.debug( oneStats )
                if len(oneStats) <= 0:
                    isError = True
                    compErrors = compErrors + 1
                    result[compPrefix + '_STATE'] = '1'
                    #return buildNagioOut(errorPrefix + compPrefix + '_STATE=1 ', result, isError=True)
        
                else:
                    for aMetric in metrics_scale:
                        metricVal = oneStats.get(aMetric, None)
                        if metricVal != None:
                            metricVal = str(int(float(metricVal)*float(metrics_scale[aMetric])))
                            oneStats[aMetric] = metricVal
                    result.update(oneStats)
        
            logger.info( "All done; exiting!" )
            child.sendline ('exit')
            #time.sleep(1)
        except Exception:
            logger.exception("Failed to get statistics")
            return buildNagioOut(errorPrefix + 'General_Error ', result, isError=True)
    finally:
        try:
            child.close()
        except Exception:
            pass
            
    
    if isError:
        return buildNagioOut(errorPrefix, result, isError=True, isFullMetrics=isFullMetrics)
    else:
        return buildNagioOut(successPrefix, result, isError=False, isFullMetrics=isFullMetrics)

def buildNagioOut(statPrefix,result, isError=False, isFullMetrics=False):

    collectMetrics = config_props.get("siebel.mgmt.collect.metrics", None)
    if collectMetrics == None:
        comp_metrics = None
    else:
        comp_metrics = config_props["siebel.mgmt.collect.metrics"].split(',')

    nagioFullOut = ''
    nagioOut = ''
    for aKey in result.keys():
        nagioFullOut = nagioFullOut + aKey + '=' + result[aKey] + ' '
        if isFullMetrics or comp_metrics == None or aKey in comp_metrics:
            nagioOut = nagioOut + aKey + '=' + result[aKey] + ' '

    if config_props.get("svc.log.all.metrics", "FALSE").upper() == "TRUE":
        resultStr = statPrefix + nagioFullOut
        logger.warn( resultStr )

    resultStr = statPrefix + nagioOut
    if isError:
        logger.error( resultStr )
    
    return resultStr
    
def readProperties(prop_filename):
    propFile= file( prop_filename, "r" )
    
    propDict= dict()
    for propLine in propFile:
        propDef= propLine.strip()
        if len(propDef) == 0:
            continue
        if propDef[0] in ( '!', '#' ):
            continue
        punctuation= [ propDef.find(c) for c in ':= ' ] + [ len(propDef) ]
        found= min( [ pos for pos in punctuation if pos != -1 ] )
        name= propDef[:found].rstrip()
        value= propDef[found:].lstrip(":= ").rstrip()
        propDict[name]= value
    propFile.close()
    return propDict

def startServer():
    req_handler = WebRequestHandler
    req_handler.config_props = config_props
    server = SiebelHTTPServer((http_address,http_port), req_handler)
    server.run_forever()

def usage():
   print ("%s\n\t-h|--help\t\tTo print this help\n\t-s|--standalone\t\tTo run monitor service in command-line\n\t-c|--config_file\tProperties file to configure the webservice\n\t-l|--log_config_file\tFile containing logging configuration" % (sys.argv[0]))

#
# Main Program
#
svc_name = 'SiebelMonitor'
svc_display_name = 'Siebel Performance Monitor'

prop_filename=None
log_filename=None
nosvc = False
argrest=sys.argv[1:]
opts, args = getopt.getopt(argrest, "hsc:l:", ["help", "standalone", "config_file=", "log_config_file="])
for opt, arg in opts:
   if opt in ("-h", "--help"):
      usage()
      sys.exit()
   elif opt in ("-s", "--standalone"):
      nosvc = True
      print "Running the monitor one-time"
   elif opt in ("-c", "--config_file"):
      prop_filename = arg
      print "Using config_file: %s" % prop_filename
   elif opt in ("-l", "--log_config_file"):
      log_filename = arg
      print "Using log_config_file: %s" % log_filename

if prop_filename is None:
   prop_filename = getOption(svc_name, 'prop_filename', None)
   
if log_filename is None:
   log_filename = getOption(svc_name, 'log_filename', None)

if prop_filename is None:
   print "Missing properties file name...quitting..."
   import servicemanager
   servicemanager.LogInfoMsg(str('Missing properties file name for service %s' % svc_name))
   sys.exit()
   
logging.config.fileConfig(log_filename)

logger = logging.getLogger('main_logger')

config_props=readProperties(prop_filename)
logger.debug( config_props )

http_address = ''
http_port = int(config_props["web.port"])

if nosvc:
   print ("Launching program at commandline")
   startServer()
else:
   instart(SiebelMgmtSvc, svc_name, svc_display_name)
   setOption(svc_name, 'prop_filename', prop_filename)
   setOption(svc_name, 'log_filename', log_filename)
   prop_filename = getOption(svc_name, 'prop_filename', None)
   log_filename = getOption(svc_name, 'log_filename', None)
   print ("Registered properties file name: %s" % (prop_filename))
   print ("Registered log file name: %s" % (log_filename))
