import requests
import re

headers={'authority': 'dnslookup.online',
'path': '/',
'accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9',
'accept-language': 'en;q=0.9,zh-CN;q=0.8,zh-TW;q=0.7',
'cache-control': 'max-age=0',
'content-type': 'application/x-www-form-urlencoded',
'cookie': '_ga=GA1.2.940607263.1646202580; _gid=GA1.2.1462020337.1646202580; _gat_gtag_UA_6388236_17=1; __cf_bm=32kESxXfBYRbg1I1_ZQ511hMq8Hxl8daVdAfhjHA6SI-1646202582-0-AQ3r8A+BrzADgmdhbEXlOYTc3yfR5fl2q3966HQELnWPirDAD39Ry/13LkaOixdMDRrRzv8TNpjf123Fr5L8Cey54hfcIqZzTAfsyxhKeoya0fKFajsMrod7GreFbpstuw==; __utma=17161196.940607263.1646202580.1646202581.1646202581.1; __utmc=17161196; __utmz=17161196.1646202581.1.1.utmcsr=google|utmccn=(organic)|utmcmd=organic|utmctr=(not%20provided); __utmt=1; __utmb=17161196.1.10.1646202581',
'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/98.0.4758.102 Safari/537.36)'}

url='https://dnslookup.online'
t='docs.python-requests.org'
data='D=recursive&S=1.1.1.1&T=A&Q='+t


s=requests.Session()
s.headers=headers
s.get(url)
r=s.post(url,data=data)

pattern = re.compile(r'A</td><td>(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})')
ip=pattern.search(r.text)
ip2=ip.group(1)

print(ip2)