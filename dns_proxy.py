import socket
import dns.message
import dns.query
import dns.rdtypes.IN.A
import fnmatch
import requests
import re
from tkinter import *
from tkinter import ttk
import time

def DEBUGLOG(str):
    print(str)

def ERRORLOG(str):
    print ("ERR: {}".format(str))

#server_socket={}

blacklist='''
*luronews*
*ber2g8e3kele*
*ads*
'''

hostonly='''

****BT****
*bittorrent*

****VIDEO***
*acg*
*hentai*
*porn*
*r18*
*liuli*
*tumblr*
*hitomi*
*affect3d*
*player*
*stream*
*live*
*anime*
*ero*
*video*
*manga*
*jinshi*
*cartoon*
*prn*
*hnt*
*xx*
*tiava*
*hamster*
*hls*
*media*
*titan*

*****MEDIA*****
*redd*

*twitter*
*facebook*

*****NET*TOOL******
*tomatocloud.cloud*
*23445*
*suying222*
*hide*
*proxy*
*proxies*
*check-host*
*mxtoolbox*
*dns*
*cdn*
*ip*
*lookup*
*ns*

*****OTHER*****
*battlenet*
*wiki*
*steam*

'''

FILE_CACHE='dnscache.txt'

def match_url(url, datalist):
    items=datalist.split('\n')
    for i in items:
        if len(i)<4:
            continue
        if fnmatch.fnmatch(url,i):
            return True
    return False
    
dns_cache = {}

def add_custom_dns(domain, ip):
    # Strange parameters explained at:
    # https://docs.python.org/2/library/socket.html#socket.getaddrinfo
    # Values were taken from the output of `socket.getaddrinfo(...)`
    dns_cache[domain] = ip

def new_getaddrinfo(*args):
    #('check-host.net', 443, <AddressFamily.AF_UNSPEC: 0>, <SocketKind.SOCK_STREAM: 1>)
    # Uncomment to see what calls to `getaddrinfo` look like.
    # print(args)
    try:
        #(socket.AddressFamily.AF_INET, 0, 0, '', (ip, port))
        return [(socket.AddressFamily.AF_INET, 0, 0, '', (dns_cache[args[0]], 443))]
    except KeyError:
        return prv_getaddrinfo(*args)

def fake_header():
    return {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/63.0.3239.84 Safari/537.36',
    }

def check_host(target):
    url='https://check-host.net/ip-info?host='+target
    try:
        res=requests.post(url,timeout=7, headers=fake_header())
    except:
        ERRORLOG("EXCEPTION !!!  {}".format(target))
        return ""
    pattern = re.compile(r'<td><strong>(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})')
    ip=pattern.search(res.text)
    ip2=ip.group(1)
    DEBUGLOG("by web {} {}".format(target,ip2))
    return ip2
    
def dnslookup_online(target):
    url='https://dnslookup.online/D=recursive&S=8.8.8.8&T=A&Q='+target
    headers={'authority': 'dnslookup.online',
    'path': '/',
    'accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9',
    'accept-language': 'en;q=0.9,zh-CN;q=0.8,zh-TW;q=0.7',
    'cache-control': 'max-age=0',
    'content-type': 'application/x-www-form-urlencoded',
    'cookie': '_ga=GA1.2.940607263.1646202580; _gid=GA1.2.1462020337.1646202580; _gat_gtag_UA_6388236_17=1; __cf_bm=32kESxXfBYRbg1I1_ZQ511hMq8Hxl8daVdAfhjHA6SI-1646202582-0-AQ3r8A+BrzADgmdhbEXlOYTc3yfR5fl2q3966HQELnWPirDAD39Ry/13LkaOixdMDRrRzv8TNpjf123Fr5L8Cey54hfcIqZzTAfsyxhKeoya0fKFajsMrod7GreFbpstuw==; __utma=17161196.940607263.1646202580.1646202581.1646202581.1; __utmc=17161196; __utmz=17161196.1646202581.1.1.utmcsr=google|utmccn=(organic)|utmcmd=organic|utmctr=(not%20provided); __utmt=1; __utmb=17161196.1.10.1646202581',
    'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/98.0.4758.102 Safari/537.36)'}
    
    url='https://dnslookup.online'
    data='D=recursive&S=1.1.1.1&T=A&Q='+target
    try:
        s=requests.Session()
        s.headers=headers
        s.get(url)
        r=s.post(url,data=data)
    except:
        ERRORLOG("EXCEPTION !!!  {}".format(target))
        return ""        
    pattern = re.compile(r'A</td><td>(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})')
    ip=pattern.search(r.text)
    ip2=ip.group(1)
    DEBUGLOG("by web {} {}".format(target,ip2))
    return ip2

def reply(msg, name,ip, address):
    if not isinstance(ip, str):
        ERRORLOG("{} {} {}".format(type(ip),ip,len(ip)))
        
    rsp=dns.message.make_response(msg)
    r1=dns.rdtypes.IN.A.A(dns.rdataclass.IN,dns.rdatatype.A,ip)
    rrset=dns.rrset.from_rdata(name, 200,r1)
    #DEBUGLOG("22 {}".format(rrset))
    rsp.answer.append(rrset)
    server_socket.sendto(rsp.to_wire(), address)

def query_direct(message, name, address):
    try:
        rsp=dns.query.udp(message, '1.1.1.1', 2,53)
    except:
        return

    ip=rsp.answer
    for i in ip:
        for j in i:
            if not isinstance(j,dns.rdtypes.IN.A.A):
                continue
            v=j.address
            if not isinstance(v,str):
                ERRORLOG("is not str")
                raise Exception("")
            DEBUGLOG("by dns {} {}".format(name, v))
            dns_cache[name]=v
            #just need one
            break
    server_socket.sendto(rsp.to_wire(), address)

def query_web(message, name, address):
    ip=dnslookup_online(name)
    #ip=check_host(name)
    if len(ip)<7:
        return
    dns_cache[name]=ip
    reply(message, name, ip, address)

def do_request(address, wire_data):
    msg = dns.message.from_wire(wire_data)
    wirelen= len(msg.to_wire())
    for q in msg.question:
        if dns.rdatatype.A!=q.rdtype:
            continue
        #q is rrset
        name=q.name.to_text()
        #name is dns.name
        #DEBUGLOG("{} {} {}".format(type(name),name, dir(name)))
        
        if name in dns_cache:
            reply(msg,name, dns_cache[name],address)
            return wirelen
            
        if match_url(name,blacklist):
            DEBUGLOG("blacklist {}".format(name))
            reply(msg,name,'127.0.0.2',address)
        elif match_url(name, hostonly):
            DEBUGLOG("hostonly {}".format(name))
            query_web(msg, name, address)
        else:
            #DEBUGLOG("direct {}".format(name))
            query_direct(msg, name, address)
    #DEBUGLOG("len {}".format(wirelen))
    return wirelen

def init():
    # Inspired by: https://stackoverflow.com/a/15065711/868533
    global prv_getaddrinfo
    prv_getaddrinfo = socket.getaddrinfo
    socket.getaddrinfo = new_getaddrinfo
    add_custom_dns('check-host.net.','188.114.97.3')
    add_custom_dns('dnslookup.online.','104.21.6.37')
    
    try:
        f=open(FILE_CACHE,'r')
        while True:
            k=f.readline()
            v=f.readline()
            k=k.rstrip('\r\n')
            v=v.rstrip('\r\n')
            if len(k)>0 and len(v)>0:
                DEBUGLOG("{} {}".format(k,v))
                dns_cache[k]=v
            else:
                break
        DEBUGLOG("load cache {}".format(len(dns_cache)))
    except:
        ERRORLOG("can not load cache")

def test():
    ip=by_check_host('bing.com')
    DEBUGLOG("ip is "+ip)
    ip=by_check_host('google.com')
    DEBUGLOG("ip is "+ip)

def save_cache():
    try:
        f=open(FILE_CACHE,'w')
        for k,v in dns_cache.items():
            f.write(k)
            f.write('\n')
            f.write(v)
            f.write('\n')
        DEBUGLOG('save cache {}'.format(len(dns_cache)))
    except:
        ERRORLOG("can not save cache")


def dns_loop():
    s= socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(('', 53))
    global server_socket
    server_socket=s
    DEBUGLOG('binded to UDP port 53.')

    lasttime=time.time()
    while True:
        try:
            message, address = s.recvfrom(1024)
        except ConnectionResetError:
            pass
        wirelen= do_request(address, message)
        if len(message)!=wirelen:
            ERRORLOG("multi msg {} {}".format(len(message),wirelen))
        
        cur=time.time()
        if cur-lasttime>30:
            save_cache()
            lasttime=cur

def main():
    root=Tk()
    frm=ttk.Frame(root,padding=10)
    frm.grid()
    ttk.Label(frm,text="1111").grid(column=0,row=0)
    ttk.Button(frm,text="Quit",command=root.destroy).grid(column=1,row=0)
    root.mainloop()

init()
#dnslookup_online('docs.python-requests.org')
dns_loop()