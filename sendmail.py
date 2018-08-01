# -*- coding: utf-8 -*-
#!/usr/bin/env python
"""
	Scalp! Apache log based attack analyzer
	by Romain Gaucher <r@rgaucher.info> - http://rgaucher.info
	                                      http://code.google.com/p/apache-scalp


	Copyright (c) 2008 Romain Gaucher <r@rgaucher.info>

	Licensed under the Apache License, Version 2.0 (the "License");
	you may not use this file except in compliance with the License.
	You may obtain a copy of the License at

		http://www.apache.org/licenses/LICENSE-2.0

	Unless required by applicable law or agreed to in writing, software
	distributed under the License is distributed on an "AS IS" BASIS,
	WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
	See the License for the specific language governing permissions and
	limitations under the License.
"""
import time
import os,sys,re,random
import subprocess
from datetime import datetime
from datetime import timedelta
import smtplib
import copy
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import traceback

reload(sys)
sys.setdefaultencoding('utf8')

FILTER_NUM = 50 #一小时被限制50次给其它人报警
html_header = """<html><head><style>
html, body {background-color:#ccc;color:#222;font-family:'Lucida Grande',Verdana,Arial,Sans-Serif;font-size:0.8em;line-height:1.6em;margin:0;padding:0;}
body {background-color:#fff;padding:0; margin: 15px; border: 1px solid #444;}
h1 {	display: block;	border-bottom: 2px solid #333;	padding: 5px;}
h2 { display: block; font-size: 1.5em; font-weight: 700; background-color: #efefef;margin:10px;padding-left: 15px;}
.match { display: block; margin: 10px; border: 1px solid; padding: 5px;}
.impact { float: right; background-color: #fff; border: 1px solid #ccc; padding: 5px; font-size: 1.8em;}
.impact-1,.impact-2,.impact-3 { background-color: #f2ffe0; border-color: #DEF0C3;}
.impact-4,.impact-5 { background-color: #ffe6bf; border-color: #ffd38f;}
.impact-6,.impact-7,.impact-8,.impact-9,.impact-10,.impact-11 /*...*/ { background-color: #FFEDEF; border-color: #FFC2CA;}
.block {display:block; margin:5px;}
.highlight {margin: 5px;}
.reason {font-weight: 700; color: #444;}
.line, .regexp {border-bottom: 1px solid #ccc; border-right: 1px solid #ccc; background-color: #fff; padding: 2px; margin: 10px;}
#footer {text-align: center;}
</style></head><body>"""

html_footer = "<div id='footer'>access log analysis by sec@*; - </div></body></html>"


def send_email(content, mailto, get_sub, attach_files=[]):
    mail_host = 'mail.*-inc.cn'
    mail_host = '10.132.26.13'
    mail_user = '*@*.cn'
    mail_pwd = '***'
    msg = MIMEMultipart()
    msg['From'] = mail_user
    msg['Subject'] = get_sub
    msg['To'] = ",".join(mailto)

    msg.attach(MIMEText(content, 'html', 'utf-8'))

    for attach_file in attach_files:
        if os.path.isfile(attach_file):
            attach = MIMEText(open(attach_file, 'rb').read(), 'base64', 'gb2312')
            attach['Content-Type'] = 'application/octet-stream'
            attach['Content-Disposition'] = 'attachment; filename="%s"' % attach_file.split('/')[-1]
            msg.attach(attach)


    try:
        s = smtplib.SMTP_SSL(mail_host, 465)
        s.login(mail_user, mail_pwd)
        s.sendmail(mail_user, mailto, msg.as_string())
        s.close()
    except Exception as e:
        traceback.print_exc(file=sys.stdout)
        print 'Exception: ', e


def generate_html_file(content, odir):
    curtime = time.strftime("%Y-%m-%d-%H:%M:%S", time.localtime())
    fname = 'logAnalysis_%s.html' % (curtime)
    fname = os.path.abspath(odir + os.sep + fname)
    try:
        out = open(fname, 'w')
        out.write(html_header)
        out.write(u"<h1>频率限制结果报表 [%s]</h1>\n" % (curtime))
        out.write(content)
        out.write(html_footer)
        out.close()
    except IOError:
        print "Cannot open the file:", fname
    with open(fname, 'r') as fp:
        return fp.read()
    return None

def externalExec(command, platform="Linux", timeout=30):
    if platform == "Linux":
        isStartupShell = True
    else:
        isStartupShell = False

    process = subprocess.Popen(command, stdout=subprocess.PIPE, shell=isStartupShell)

    startTime = datetime.now()
    returnValue = ()
    while None == process.poll():
        if datetime.now() - startTime >  timedelta(seconds=timeout):
            if None == process.returncode: #process is still running so kill it
                try:
                    process.terminate()
                except:
                    print "except when terminate process" % (command)
                    #LOGGER.warn("except when terminate process:\n%s" % (command))

            returnValue = process.communicate()
            print "process timeout:%s\n%s" % (str(datetime.now() - startTime), command)
            #LOGGER.info("process timeout:%s\n%s" % (str(datetime.now() - startTime), command))
            break
    else:
        returnValue = process.communicate()

    if not returnValue:
        return None

    scanResultJsonString = returnValue[0]

    return scanResultJsonString

def dictToString(resultDict, filternum=0):
    '''
    dict to string
    '''
    returnStr = ''
    print filternum
    if not resultDict:
        return returnStr
    for item in sorted(resultDict.items(), key=lambda d:d[1], reverse=True):
        if item[1] < filternum:
            continue
        if 'driver_order_conpon' in item[0]:
            returnStr = "%s<font color=\"red\">[%d]\t%s</font><br />\n" % (returnStr, item[1], item[0])
        else:
            returnStr = "%s[%d]\t%s<br />\n" % (returnStr, item[1], item[0])
    return returnStr

def sendTopForbidIpLog(topforbidiplog):
    if os.path.isfile(topforbidiplog):
        result = open(topforbidiplog).read().replace('\n','</br>')
        if not result:
            return
        to_list = [
            'ops@*-inc.cn',
        ]
        curtime = time.strftime("%a-%d-%b-%Y", time.localtime())
        send_email(result, to_list, u'昨天报警 >500次的ip对应所有用户 结果报表 [%s]' % curtime, [topforbidiplog,])

def getPreloginLog(preloginLog):
    if os.path.isfile(preloginLog):
        command = '''cat %s |awk '{print $1}'|awk -F'.' '{print $1"."$2"."$3".*"}' |sort|uniq -c |sort -nr|head -100''' % preloginLog
        result = externalExec(command)
        print result
        result = result.replace('\n','<br/>')
        to_list = [
            'ops@**-inc.cn',
        ]
        curtime = time.strftime("%a-%d-%b-%Y", time.localtime())

        send_email(result, to_list, u'用户登陆ip c段 top 100 结果报表 [%s]' % curtime, [preloginLog,])



def logAnalysis(logfile, odir = 'html', num=10):
    '''
    logfile: log20120606.txt
    apis: []
    '''
    result_str = ""
    i = 1
    actResult = {}
    historyActResult = {}
    tempActResult = {}
    global FILTER_NUM

    with open(logfile,'r') as fp:
        lines = [line.strip() for line in fp.readlines()]
        for line in lines:
            lineList = line.split()
            actResult[" ".join(lineList[1:])] = int(lineList[0])
    #print actResult

    with open(logfile+'.old','r') as fp:
        lines = [line.strip() for line in fp.readlines()]
        for line in lines:
            lineList = line.split()
            historyActResult[" ".join(lineList[1:])] = int(lineList[0])
    #print historyActResult

    tempActResult = copy.deepcopy(actResult)

    for key in historyActResult.keys():
        if tempActResult.has_key(key):
            num = tempActResult[key] - historyActResult[key]
            if num > 0 :
                tempActResult[key] = num
            else:
                tempActResult.pop(key)
    if not tempActResult:
        return result_str

    result_str += u"  <h2>最近1小时频率限制结果</h2>\n"
    alarm_result = dictToString(tempActResult, FILTER_NUM)
    result_str += "<div class='match impact-%d'>\n%s</div>\n" % (i, dictToString(tempActResult))
    i +=1

    result_str += u"  <h2>今天一天总频率限制结果</h2>\n"
    result_str += "<div class='match impact-%d'>\n%s</div>\n" % (i, dictToString(actResult))
    i +=1


    html_str = generate_html_file(result_str, odir)
    to_list = [
        'order-dev@*-inc.cn',
    ]
    if not alarm_result:
        to_list = [ 'ops@*-inc.cn',]

    curtime = time.strftime("%a-%d-%b-%Y", time.localtime())

    send_email(html_str, to_list, u'频率限制结果报表 [%s]' % curtime)

    return result_str

def help():
    print "analysis the access log! by * - http://www.edai*jia.cn"
    print "usage:  ./logAnalysis.py [--log|-l log_file] "
    print "                   [--sample|-s 4.2]"
    print "   --log         |-l:  the apache log file './access_log' by default"
    print "   --prelogin    |-p:  the prelogin log file '' "
    print "   --html        |-h:  generate an HTML output"
    print "   --topforbidip |-t:  top >500 forbid ip and user"
    print "   --output      |-o:  specifying the output directory; by default, scalp will try to write"
    print "                     in the same directory as the log file"

def main(argc, argv):

    logfile  = "access_log"
    odir  = ""
    preloginLog = ""
    topforbidiplog = ""


    if argc < 2 or sys.argv[1] == "--help":
        help()
        sys.exit(0)
    else:
        for i in range(argc):
            s = argv[i]
            if i < argc:
                if s in ("--log","-l"):
                    logfile = argv[i+1]
                elif s in ("--prelogin", "-p"):
                    preloginLog = argv[i+1]
                elif s in ("--output", "-o"):
                    odir = argv[i+1]
                elif s in ("--topforbidip", "-t"):
                    topforbidiplog = argv[i+1]
                else:
                    pass
            else:
                print "argument error, '%s' has been ignored" % s
        if len(odir) < 1:
            odir = "html"

        if preloginLog:
            getPreloginLog(preloginLog)
            return
        if topforbidiplog:
            sendTopForbidIpLog(topforbidiplog)
            return

        if not os.path.isfile(logfile):
            print "error: the log file doesn't exist" + logfile
            return
        if not os.path.isdir(odir):
            print "The directory %s doesn't exist, scalp will try to create it"
            try:
                os.mkdir(odir)
            except:
                print "/!\ scalp cannot write in",odir
                print "/!\ Ising /tmp/scalp/ as new directory..."
                odir = '/tmp/scalp'
                os.mkdir(odir)
        logAnalysis(logfile, odir)

if __name__ == "__main__":
    main(len(sys.argv), sys.argv)
    """
	import hotshot
	from hotshot import stats
	name = "hotshot_scalp_stats"
	if not os.path.isfile(name):
		prof = hotshot.Profile(name)
		prof.runcall(main)
		prof.close()
	s = stats.load(name)
	s.sort_stats("time").print_stats()
	"""
