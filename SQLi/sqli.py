import sys
import requests
from bs4 import BeautifulSoup
import urllib.parse

url = input("\n[*] Enter url: -> ")

HEADERS = {
	'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/75.0.3770.80 Safari/537.36'
	}

input_cookie = input("\n[*] Enter cookies if needed (ex: 'PHPSESSID=12345;par=something') [just enter if none] -> ")
if len(input_cookie) > 0:
	HEADERS['Cookie'] = input_cookie

r = requests.get(url, headers=HEADERS)
soup = BeautifulSoup(r.text, "html.parser")

queriesStr = []
parameters = {}
action = []
for form in soup.find_all("form"):
	qStrTemp = ""
	if(form.get('action') is not None):
		action.append(form.get('action'))
	else:
		action.append("")
	for child in form.descendants:
		name = ""
		value = ""
		if(child.name in ['input', 'select', 'button'] and child.attrs):
			
			if(child.get('name') is not None):
				name = child.get('name')
				if(child.get('value') is not None):
					value = child.get('value')
					qStrTemp += "%s=%s&" % (name, value)
				else:
					qStrTemp += "%s=None&" % (name)

	qStrTemp = qStrTemp[:-1]
	queriesStr.append(qStrTemp)

qStrLength = len(queriesStr)
for i in range(0, qStrLength):
	print ("~Query %d~" %i)
	print (queriesStr[i])
	print ("-----------------------------------------------------------")

qStrNum = input("Enter query number to inject: -> ")
try:
	qStrNum = int(qStrNum)
	if(qStrNum > -1):
		parameters = urllib.parse.parse_qs(queriesStr[qStrNum])
		print(parameters)
		while(True):
			key = input("Enter key to inject or automatic or exit: (ex:'name'; 'pass'; 'automatic()' or 'exit()') -> ")
			if(key in parameters):
				value = input("Enter value to inject: -> ")
				parameters[key] = value
			elif(key == 'automatic()'):
				pass
			elif(key == 'exit()'):
				break

except ValueError:
	print("That's not an int!")
	print("No.. input string is not an Integer. It's a string")

def post(url, HEADERS, parameters, qStrNum):
	pUrl = url
	pHeaders = HEADERS
	pPara = parameters
	pAction = action[qStrNum]
	if("http://" not in pAction and "https://" not in pAction and pAction != ""):
		if(pUrl[-1] != '/' and pAction == "#"):
			pUrl = "%s/%s" % (pUrl, pAction)
		else:
			pUrl = "%s%s" % (pUrl, pAction)
	r = requests.post(pUrl, data=pPara, headers=pHeaders)
	print(r.text)

def get(url, HEADERS, parameters):
	gUrl = url
	gHeaders = HEADERS
	gPara = parameters
	r = requests.get(gUrl, params=gPara, headers=gHeaders)
	print(r.text)

def main():
	global url, HEADERS, parameters, qStrNum
	post(url, HEADERS, parameters, qStrNum)

main()