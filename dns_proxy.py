import socket
import dns.message
import dns.query
import dns.rdtypes.IN.A
import fnmatch
import requests
import re
from tkinter import *
from tkinter import ttk

def DEBUGLOG(str):
    print(str)

def ERRORLOG(str):
    print ("ERR: {}".format(str))

#server_socket={}

blacklist='''
*luronews*
*ber2g8e3kele*
'''

hostonly='''
*bittorrent*

*hacg*
*hentai*
*porn*
*r18*
*liuli*
*tumblr*
*hitomi*
*affect3d*
*player*
*pvvstream*

*redd*
*video*
*twitter*
*facebook*


*tomatocloud.cloud*
*23445*
*suying222*
*hide*
*proxy*
*proxies*
*check-host*
*mxtoolbox*
*dnschecker*

*battlenet*
*wiki*
*steam*

'''

def match_url(url, datalist):
    items=datalist.split('\n')
    for i in items:
        if len(i)<4:
            continue
        if fnmatch.fnmatch(url,i):
            return True
    return False
    
dns_cache = {}

def add_custom_dns(domain, port, ip):
    key = (domain, port)
    # Strange parameters explained at:
    # https://docs.python.org/2/library/socket.html#socket.getaddrinfo
    # Values were taken from the output of `socket.getaddrinfo(...)`

    value = (socket.AddressFamily.AF_INET, 0, 0, '', (ip, port))
    dns_cache[key] = [value]

def new_getaddrinfo(*args):
    # Uncomment to see what calls to `getaddrinfo` look like.
    # print(args)
    try:
        return dns_cache[args[:2]] # hostname and port
    except KeyError:
        return prv_getaddrinfo(*args)


def by_check_host(target):
    url='https://check-host.net/ip-info?host='+target
    try:
        res=requests.get(url,timeout=3)
    except:
        ERRORLOG("network fail")
        return ""
    
    if 200!=res.status_code:
        return ""
    pattern = re.compile(r'<td><strong>(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})')
    ip=pattern.search(res.text)
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
    ip=by_check_host(name)
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
    prv_getaddrinfo = socket.getaddrinfo
    socket.getaddrinfo = new_getaddrinfo
    add_custom_dns('check-host.net',443,'188.114.97.3')
    
def test():
    ip=by_check_host('bing.com')
    DEBUGLOG("ip is "+ip)
    ip=by_check_host('google.com')
    DEBUGLOG("ip is "+ip)
    
def dns_loop():
    s= socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(('', 53))
    global server_socket
    server_socket=s
    DEBUGLOG('binded to UDP port 53.')

    while True:
        try:
            message, address = s.recvfrom(1024)
        except ConnectionResetError:
            pass
        wirelen= do_request(address, message)
        if len(message)!=wirelen:
            ERRORLOG("multi msg {} {}".format(len(message),wirelen))

def main():
    root=Tk()
    frm=ttk.Frame(root,padding=10)
    frm.grid()
    ttk.Label(frm,text="1111").grid(column=0,row=0)
    ttk.Button(frm,text="Quit",command=root.destroy).grid(column=1,row=0)
    root.mainloop()

init()
dns_loop()