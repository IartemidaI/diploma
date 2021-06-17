#import libraries
from tkinter import *
from socket import *
from tkinter import scrolledtext, messagebox
from queue import Queue
import speedtest
import ifaddr
import dns
import dns.resolver
import socket
import threading
import netifaces
import uuid
import struct
import sys
import re
#functions
#1) Scanning ports
def port_scan(event):
    socket.setdefaulttimeout(0.25)
    print_lock = threading.Lock()
    target = resourse_to_scan.get()
    #checking if resouse is reachable
    try:
        t_IP = socket.gethostbyname(target)
    except socket.gaierror:
        messagebox.showinfo("Error occured!", "Destination host unreacheble or wrong format!")
        return
    opened_ports=[] #list for ports
    #trying to connect to port
    def portscan(port):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            con = s.connect((t_IP, port))
            with print_lock:
                opened_ports.append(port)
            con.close()
        except:
            pass
    #distribution between threads
    def threader():
        while True:
            worker = q.get()
            portscan(worker)
            q.task_done()    
    q = Queue() #creating queue
    #creating threads 
    for x in range(1000):
        t = threading.Thread(target = threader)
        t.daemon = True
        t.start()
    #sending number of port into threads
    for worker in range(1, 65535):
        q.put(worker)  
    q.join()
    #creating window with results of scanning
    opened_ports_window=Toplevel()
    opened_ports_window.title("List of opened port")
    opened_ports_window.geometry()
    #scan result into text 
    opened_ports_text_format="Scaned host: {} \nIP address of host: {}\n".format(target, t_IP)
    for i in opened_ports:
        opened_ports_text_format+="\tPort №{} is opened!\n".format(i)
    l=scrolledtext.ScrolledText(opened_ports_window, font="14")
    l.insert(INSERT, opened_ports_text_format)
    l.pack()
# 2) Scanning DNS records
def DNS_scan(event):
    #list of possible DNS record types
    DNS_records_types=['NONE', 'A', 'NS', 'MD', 'MF', 'CNAME', 'SOA', 'MB', 'MG', 'MR', 'NULL', 'WKS', 'PTR', 'HINFO', 'MINFO', 'MX', 'TXT', 'RP', 'AFSDB', 'X25', 'ISDN', 'RT', 'NSAP', 'NSAP-PTR', 'SIG', 'KEY', 'PX', 'GPOS', 'AAAA', 'LOC', 'NXT', 'SRV', 'NAPTR', 'KX', 'CERT', 'A6', 'DNAME', 'OPT', 'APL', 'DS', 'SSHFP', 'IPSECKEY', 'RRSIG', 'NSEC', 'DNSKEY', 'DHCID', 'NSEC3', 'NSEC3PARAM', 'TLSA', 'HIP', 'CDS', 'CDNSKEY', 'CSYNC', 'SPF', 'UNSPEC', 'EUI48', 'EUI64', 'TKEY', 'TSIG', 'IXFR', 'AXFR', 'MAILB', 'MAILA', 'ANY', 'URI', 'CAA', 'TA', 'DLV']
    host=DNS_to_scan.get()
    DNS_records=""
    #trying to find records for each type
    for a in DNS_records_types:
        try:
            answers = dns.resolver.resolve(host, a)
            for rdata in answers:
                DNS_records+="DNS record type " + a + ":\t" + rdata.to_text() + "\n"  
        except Exception as e:
            pass
    #if string still empty it means that DNS records wasn't found
    if DNS_records=="":
        DNS_records="No DNS records found for this host name or you entered wrong hostname."
    #creating window for results of scanning
    DNS_records_window=Toplevel()
    DNS_records_window.title("List of DNS record")
    DNS_records_window.geometry()
    l=scrolledtext.ScrolledText(DNS_records_window, font="14")
    l.insert(INSERT, DNS_records)
    l.pack()
# 3) Packet sniffer
def sniffer(event):
    #receiving datagram
    def receiveData(soc):
        data = ''
        try:
            #receive data from socket
            data = soc.recvfrom(65565)
        except timeout:
            data = ''
        except:
            messagebox.showinfo("Error occured!", "Unexpected error!")
            sys.exc_info()
        return data[0]
    #get type of service bits (8 bits)
    def getTOS(data):
        priority = {0: "Routine", 1: "Priority", 2: "Immediate", 3: "Flash", 4: "Flash override", 5: "CRITIC/ECP",
                  6: "Internetwork control", 7: "Network control"}
        delay = {0: "Normal delay", 1: "Low delay"}
        throughput = {0: "Normal throughput", 1: "High throughput"}
        reliability = {0: "Normal reliability", 1: "High reliability"}
        cost = {0: "Normal monetary cost", 1: "Minimize monetary cost"}
        #reading bits and shift right
        D = data & 0x10
        D >>= 4
        T = data & 0x8
        T >>= 3
        R = data & 0x4
        R >>= 2
        M = data & 0x2
        M >>= 1
        #formatting for output
        tabs = '\n\t\t\t'
        TOS = priority[data >> 5] + tabs + delay[D] + tabs + throughput[T] + tabs + \
            reliability[R] + tabs + cost[M]
        return TOS
    #Flag bits (3 bits)
    def getFlags(data):
        flagR = {0: "0 - Reserved bit"}
        flagDF = {0: "0 - Fragment if necessary", 1: "1 - Do not fragment"}
        flagMF = {0: "0 - Last fragment", 1: "1 - More fragments"}
        #reading bits and shift right
        R = data & 0x8000
        R >>= 15
        DF = data & 0x4000
        DF >>= 14
        MF = data & 0x2000
        MF >>= 13
        #formatting for output
        tabs = '\n\t\t\t'
        flags = flagR[R] + tabs + flagDF[DF] + tabs + flagMF[MF]
        return flags
    #getting transfer protocol (8 bits)
    def getProtocol(protocolNr):
        #opening of file with possible protocol types list and it's reading
        protocolFile = open('Protocol.txt', 'r')
        protocolData = protocolFile.read()
        #regexp to find protocol number
        protocol = re.findall(r'\n' + str(protocolNr) + ' (?:.)+\n', protocolData)
        #formatting for output
        if protocol:
            protocol = protocol[0]
            protocol = protocol.replace("\n", "")
            protocol = protocol.replace(str(protocolNr), "")
            protocol = protocol.lstrip()
            return protocol
        else:
            return 'No such protocol.'
    #list of captured protocols
    protocols=[]
    #string to output
    output=""
    for i in range (100):
        #get public-interface ip
        HOST = gethostbyname(gethostname())
        #creating socket, binding it with all ports and public-interface ip
        soc = socket.socket(AF_INET, SOCK_RAW, IPPROTO_IP)
        soc.bind((HOST, 0))
        #include processing of IP headers 
        soc.setsockopt(IPPROTO_IP, IP_HDRINCL, 1)
        soc.ioctl(SIO_RCVALL, RCVALL_ON)
        data = receiveData(soc)
        #unpack ip header
        unpackedData = struct.unpack('!BBHHHBBH4s4s' , data[:20])
        #unpacking other data
        version_IHL = unpackedData[0]
        version = version_IHL >> 4
        IHL = version_IHL & 0xF
        TOS = unpackedData[1]
        totalLength = unpackedData[2]
        ID = unpackedData[3]
        flags = unpackedData[4]
        fragmentOffset = unpackedData[4] & 0x1FFF
        TTL = unpackedData[5]
        protocolNr = unpackedData[6]
        checksum = unpackedData[7]
        sourceAddress = inet_ntoa(unpackedData[8])
        destinationAddress = inet_ntoa(unpackedData[9])
        protocols.append(str(getProtocol(protocolNr)))
        #forming output
        output+="\nPacket № " + str(i) + "\n"
        output+= "An IP packet with the size " + str(unpackedData[2]) + " was captured.\n"
        output+= "Version:\t\t" + str(version) + "\n"
        output+= "Header Length:\t\t" + str(IHL*4) + " bytes\n"
        output+= "Type of Service:\t" + getTOS(TOS) + "\n"
        output+= "Length:\t\t\t" + str(totalLength) + "\n"
        output+= "ID:\t\t\t" + str(hex(ID)) + " (" + str(ID) + ")\n"
        output+= "Flags:\t\t\t" + getFlags(flags) + "\n"
        output+= "Fragment offset:\t" + str(fragmentOffset) + "\n"
        output+= "TTL:\t\t\t" + str(TTL) + "\n"
        output+= "Protocol number:\t" + str(protocolNr) + "\n"
        output+= "Protocol:\t\t" + getProtocol(protocolNr) + "\n"
        output+= "Checksum:\t\t" + str(checksum) + "\n"
        output+= "Source:\t\t" + str(sourceAddress) + "\n"
        output+= "Destination:\t\t" + str(destinationAddress) + "\n"
    soc.ioctl(SIO_RCVALL, RCVALL_OFF)
    #counting amounnt of each protocol packets
    temp_dict={i:protocols.count(i) for i in protocols}
    protocols_text=""
    for keys in temp_dict:
        protocols_text+=keys + ":\t" + str(temp_dict[keys]) + "\n"
    #creating window with results
    sniffer_window=Toplevel()
    sniffer_window.title("Results")
    sniffer_window.geometry()
    packets_frame=LabelFrame(sniffer_window, text="Captured packets", width=70)
    number_proto_frame=LabelFrame(sniffer_window, text="Trafic_structure", width=30)
    trafic_label=Label(number_proto_frame, text=protocols_text, font="14")
    r=scrolledtext.ScrolledText(packets_frame, font=14)
    r.insert(INSERT, output)
    packets_frame.grid(row=0, column=0, padx=(10, 10), pady=(5, 5))
    number_proto_frame.grid(row=0, column=1, padx=(10, 10), pady=(5, 5))
    r.pack()
    trafic_label.pack()
#creating root window
root = Tk()
root.title("Connection tester")
sw = root.winfo_screenwidth()
sh = root.winfo_screenheight()
root.geometry('%dx%d+0+0' % (sw, sh))
#Get DNS servers
dns_resolver = dns.resolver.Resolver()
number = 0
DNS_server_list=""
for i in dns_resolver.nameservers:
    try:
        ip_add=str(i)
        hostname_URL = socket.gethostbyaddr(ip_add)
        DNS_server_list += "DNS №" + str(number) + ": " + i + "\n\tURL: " + str(hostname_URL[0]) + "\n"
        number+=1
    except Exception:
        DNS_server_list += "DNS №" + str(number) + ": " + i + "\n"
        number+=1
#DNS servers output
DNS_servers_frame=LabelFrame(root, text="DNS servers", width=15)
servers=scrolledtext.ScrolledText(DNS_servers_frame, font="14", width=30, height=10)
servers.insert(INSERT, DNS_server_list)
#get ping, download and upload speed
test = speedtest.Speedtest()
download = test.download()
upload = test.upload()
download_speed=str("{0:.2f} Mb/s".format((download/1024)/1024))
upload_speed=str("{0:.2f} Mb/s".format((upload/1024)/1024))
ping_value=str(f"{test.results.ping} Ms")
#get info about IP adapters
adapters = ifaddr.get_adapters()
text_format=""
for adapter in adapters:
    text_format+="Intenet adapter name: " + "\n"+ adapter.nice_name + "\n"
    temp=0
    for ip in adapter.ips:
        if temp==0:
            text_format += "\tIPv6 address:" + "\n\t" + str(ip.ip[0]) + "/" + str(ip.network_prefix) + "\n"
            temp=1
        else:
            text_format += "\tIPv4 address:" + "\n\t" + str(ip.ip) + "/" + str(ip.network_prefix) + "\n"
            temp=0
#get default gateway and Physical Address (MAC)
mac=':'.join(['{:02x}'.format((uuid.getnode() >> ele) & 0xff) for ele in range(0,8*6,8)][::-1])
gateways = netifaces.gateways()
default_gateway = gateways['default'][netifaces.AF_INET][0]
#default gateway and MAC output, enter DNS host to scan, sniffer button
addresses_frame=LabelFrame(root, width=30)
mac_frame=LabelFrame(addresses_frame, text="Physical Address (MAC)", width=35)
mac_label=Label(mac_frame, text=mac, font="14", width=30)
gateway_frame=LabelFrame(addresses_frame, text="Default gateway", width=35)
gateway_label=Label(gateway_frame, text=default_gateway, font="14", width=35)
enter_DNS_frame=LabelFrame(addresses_frame, text="Scan for DNS records", width=35)
welcome_DNS=Label(enter_DNS_frame, text="↓ Enter hostname to scan for DNS records ↓", font="Georgia 13", width=30)
DNS_to_scan=Entry(enter_DNS_frame, width=30, bd=3)
DNS_button=Button(enter_DNS_frame, text="Scan!", background="#FFFFE0", activebackground="#FFFFE0", font="Georgia 14", width=20, bd=3)
DNS_button.bind("<Button-1>", DNS_scan)
Sniffer_button=Button(addresses_frame, text="Start packet sniffing", background="#FFFFE0", activebackground="#FFFFE0", font="Georgia 14", width=20, bd=3)
Sniffer_button.bind("<Button-1>", sniffer)
#speedtest output
speedtest_frame=LabelFrame(root, text="Speed test", width=15)
download_frame=LabelFrame(speedtest_frame, text = "Download speed", width=15)
uploadd_frame=LabelFrame(speedtest_frame, text="Upload speed", width=15)
ping_frame=LabelFrame(speedtest_frame, text="Ping", width=15)
d = Label(download_frame, text=download_speed, font="Mistral 30", width=15)
u = Label(uploadd_frame, text=upload_speed, font="Mistral 30", width=15)
p = Label(ping_frame, text=ping_value, font="Mistral 30", width=15)
#adapters output
adapters_frame=LabelFrame(root, text = "Adapters", width=45)
a = scrolledtext.ScrolledText(adapters_frame, width=45)
a.insert(INSERT, text_format)
#enter resource to scan ports
scan_port_frame=LabelFrame(root, text="Scan ports", width=45)
welcome=Label(scan_port_frame, text="↓ Enter URL or IP to scan for opened ports ↓", font="Georgia 13", width=45)
resourse_to_scan=Entry(scan_port_frame, width=45, bd=3)
scan_button=Button(scan_port_frame, text="Scan!", background="#FFFFE0", activebackground="#FFFFE0", font="Georgia 14", width=20, bd=3)
scan_button.bind("<Button-1>", port_scan)
#packing frames
speedtest_frame.grid(row=0, column=0, padx=(10, 10), pady=(5, 5))
download_frame.grid(row=0, column=0, padx=(10, 10), pady=(5, 5))
uploadd_frame.grid(row=1, column=0, padx=(10, 10), pady=(5, 5))
ping_frame.grid(row=2, column=0, padx=(10, 10))
scan_port_frame.grid(row=1, column=1, padx=(10, 10))
addresses_frame.grid(row=0, column=2, rowspan=2, padx=(10, 10), pady=(5, 5))
mac_frame.grid(row=0, column=0, padx=(10, 10), pady=(5, 5))
gateway_frame.grid(row=1, column=0, padx=(10, 10), pady=(5, 5))
enter_DNS_frame.grid(row=2, column=0, padx=(10, 10), pady=(5, 5))
welcome_DNS.pack(side=TOP, pady=(5, 5))
DNS_to_scan.pack()
DNS_button.pack()
adapters_frame.grid(row=0, column=1, padx=(10, 10))
DNS_servers_frame.grid(row=1, column=0, padx=(10, 10), pady=(10, 10))
Sniffer_button.grid(row=3, column=0, padx=(10, 10), pady=(10, 10))
welcome.pack(side=TOP, pady=(5, 5))
resourse_to_scan.pack()
scan_button.pack()
gateway_label.pack()
mac_label.pack()
d.pack()
u.pack()
p.pack()
a.pack()
servers.pack()
root.mainloop()
