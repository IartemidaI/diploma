#import libraries
from tkinter import *
from tkinter import scrolledtext
from queue import Queue
import speedtest
import ifaddr
import socket
import time
import threading
#functions
#1) Scanning ports
def port_scan(event):
    pass  
#creating root window
root = Tk()
root.title("Connection tester")
sw = root.winfo_screenwidth()
sh = root.winfo_screenheight()
root.geometry('%dx%d+0+0' % (sw, sh))
#top label
selffuction = Label(root, bg="#FFFFE0", text="You are welcome! We will help you to make you connection better!", font="Mistral 30", width="95")
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
resourse_to_scan=Entry(scan_port_frame, width=45, bd=3)
scan_button=Button(scan_port_frame, text="Scan!", font="14", width=20, bd=3)
scan_button.bind("<Button-1>", port_scan)
#packing frames
speedtest_frame.grid(row=1, column=0, padx=(10, 10), pady=(5, 5))
download_frame.grid(row=0, column=0, padx=(10, 10), pady=(5, 5))
uploadd_frame.grid(row=1, column=0, padx=(10, 10), pady=(5, 5))
ping_frame.grid(row=2, column=0, padx=(10, 10))
scan_port_frame.grid(row=4, column=1, padx=(10, 10))
adapters_frame.grid(row=1, column=1, rowspan=3, padx=(10, 10))
resourse_to_scan.pack()
scan_button.pack()
d.pack()
u.pack()
p.pack()
a.pack()
selffuction.grid(row=0, column=0, columnspan=3)
root.mainloop()
