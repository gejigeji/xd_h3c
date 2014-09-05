#-*-coding:utf-8-*
__all__ = ["EAPAuth"]

import socket
import os, sys, pwd
import time
from subprocess import call
import md5
# init() # required in Windows
from eappacket import *

H3C_KEY = 'HuaWei3COM1X'
H3C_VERSION = 'EN V3.60-6303'
H3C_VERSION += '\x00' * (16-len(H3C_VERSION))
Windows_VERSION = 'r70393861'
Windows_VERSION += '\x00' * (20-len(Windows_VERSION))

class EAPAuth:
    def __init__(self, login_info):
        # bind the h3c client to the EAP protocal 
        self.client = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ETHERTYPE_PAE))
        self.client.bind((login_info['ethernet_interface'], ETHERTYPE_PAE))
        # get local ethernet card address
        self.mac_addr = self.client.getsockname()[4]
        self.ip = ''
        self.ethernet_header = get_ethernet_header(self.mac_addr, PAE_GROUP_ADDR, ETHERTYPE_PAE)
        self.has_sent_logoff = False
        self.login_info = login_info

    def get_local_ip():  
        ifname = login_info(['ethernet_interface'])
        import fcntl 
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)  
        inet = fcntl.ioctl(s.fileno(), 0x8915, pack('256s', ifname[:15]))  
        ret = socket.inet_ntoa(inet[20:24])  
        return ret

    def get_ip(self):
        try:
            self.ip = get_local_ip()
            return True
        except:
            return False

    def send_start(self):
        # sent eapol start packet
        eap_start_packet = self.ethernet_header + get_EAPOL(EAPOL_START)
        self.client.send(eap_start_packet)

    def send_logoff(self):
        # sent eapol logoff packet
        eap_logoff_packet = self.ethernet_header + get_EAPOL(EAPOL_LOGOFF)
        self.client.send(eap_logoff_packet)
        self.has_sent_logoff = True

    def send_response_id(self, packet_id):
        data = '\x15\x04'
        if self.get_ip():
            data += ''.join([chr(int(i)) for i in self.ip.split('.')])+ '\x06\x07'
        else:
            data +='\x00\x00\x00\x00\x06\x07'
        data += self.fillbase64area()

        id_msg = self.ethernet_header + get_EAPOL(EAPOL_EAPPACKET, pack('!BBHB', EAP_RESPONSE, packet_id, len(data)+5, EAP_TYPE_ID) + data
)
        self.client.send(id_msg)

    def send_response_noti(self, packet_id):
        data = '\x01\x16'
        data += self.fillclientversion() + '\x02\x16' + self.fillwindowsversion()
        noti_msg = self.ethernet_header + get_EAPOL(EAPOL_EAPPACKET, pack('!BBHB', EAP_RESPONSE, packet_id, len(data)+5, EAP_TYPE_NOTI)+ data)
        self.client.send(noti_msg)
        
    def send_response_md5(self, packet_id, md5data):
        data = '\x10'
        md5buf = pack('!B', packet_id)
        md5buf += self.login_info['password']
        md5buf += md5data
        m = md5.new()
        m.update(md5buf)
        data += m.digest()
        data += self.login_info['username']
        eap_packet = self.ethernet_header + get_EAPOL(EAPOL_EAPPACKET, pack("!BBHB", EAP_RESPONSE, packet_id, 5+len(data), EAP_TYPE_MD5) + data )
        try:
            self.client.send(eap_packet)
        except socket.error, msg:
            exit(-1)

    def send_response_avai(self, packet_id):
        data = '\x00\x15\x04'
        if self.get_ip():
            data += ''.join([chr(int(i)) for i in self.ip.split('.')])+ '\x06\x07'
        else:
            data +='\x00\x00\x00\x00\x06\x07'
        data += self.fillbase64area()
        data += '  '
        data += self.login_info['username']
        avai_msg = self.ethernet_header + get_EAPOL(EAPOL_EAPPACKET, pack('!BBHB', EAP_RESPONSE, packet_id, len(data)+5, EAP_TYPE_AVAI) + data)
        self.client.send(avai_msg)

    def send_response_h3c(self, packet_id):
        resp = chr(len(self.login_info['password'])) + self.login_info['password'] + self.login_info['username']
        eap_packet = self.ethernet_header + get_EAPOL(EAPOL_EAPPACKET, get_EAP(EAP_RESPONSE, packet_id, EAP_TYPE_H3C, resp))
        try:
            self.client.send(eap_packet)
        except socket.error, msg:
            exit(-1)

    def fillclientversion(self):
        random = time.time()
        randstr = '%08x' %random
        randint = [ord(i) for i in randstr]
        versionint = [ord(i) for i in H3C_VERSION]
        tmp = self.XOR(versionint, 16, randint, len(randint)) 
        tmp += randint[:-5:-1]
        h3c_key = [ord(i) for i in H3C_KEY]
        tmp = self.XOR(tmp, 20, h3c_key, len(h3c_key))
        ans = ''
        for i in tmp:
            ans += chr(i)
        return ans

    def fillwindowsversion(self):
        windows_version = [ord(i) for i in Windows_VERSION]
        h3c_key = [ord(i) for i in H3C_KEY]
        tmp = self.XOR(windows_version, len(windows_version), h3c_key, len(h3c_key))
        ans = ''
        for i in tmp:
            ans += chr(i)
        return ans
    
    def XOR(self, packet, plen, key, klen):
        for i in range(plen):
            packet[i] = packet[i] ^ key[i%klen]
        i = plen - 1
        j = 0
        while j < plen :
            packet[i] = packet[i] ^ key[j%klen]
            i -= 1
            j += 1
        return packet

    def fillbase64area(self):
        area = ''
        tmp = self.fillclientversion()
        tmp = [ord(i) for i in tmp]
        table= "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
        m = 0
        while m < 18:
            c1 = tmp[m]
            m += 1
            c2 = tmp[m]
            m += 1
            c3 = tmp[m]
            m += 1
            area += table[(c1&0xfc)>>2]
            area += table[((c2&0xf0)>>4) | ((c1&0x03)<<4)]
            area += table[((c3&0xc0)>>6) | ((c2&0x0f)<<2)]
            area += table[c3&0x3f]
        c1 = tmp[18]
        c2 = tmp[19]
        area += table[(c1&0xfc)>>2]
        area += table[((c2&0xf0)>>4) | ((c1&0x03)<<4)]
        area += table[(c2&0x0f)>>2]
        area += '='

        area += ' '*2
        area += self.login_info['username']
        return area

    def EAP_handler(self, eap_packet):
        vers, type, eapol_len  = unpack("!BBH",eap_packet[:4])

        # EAPOL_EAPPACKET type
        code, id, eap_len = unpack("!BBH", eap_packet[4:8])
        if code == EAP_SUCCESS:
            
            if self.login_info['dhcp_command']:
                call( [self.login_info['dhcp_command'], self.login_info['ethernet_interface']])

        elif code == EAP_FAILURE:
            exit(-1)
        elif code == EAP_RESPONSE:
            pass
        elif code == EAP_REQUEST:
            reqtype = unpack("!B", eap_packet[8:9])[0]
            reqdata = eap_packet[9:4 + eap_len]
            if reqtype == EAP_TYPE_ID:
                self.send_response_id(id)
            elif reqtype == EAP_TYPE_H3C:
                self.send_response_h3c(id)
            elif reqtype == EAP_TYPE_MD5:
                data_len = unpack("!B", reqdata[0:1])[0]
                md5data = reqdata[1:1 + data_len]
                self.send_response_md5(id, md5data)
            elif reqtype == EAP_TYPE_NOTI:
                self.send_response_noti(id)
            elif reqtype == EAP_TYPE_AVAI:
                self.send_response_avai(id)
            else:
                pass

    def serve_forever(self):
        try:
            self.send_start()

            while True:
                eap_packet = self.client.recv(1600)
                self.dstmac = eap_packet[6:12]
                self.ethernet_header = get_ethernet_header(self.mac_addr, self.dstmac, ETHERTYPE_PAE)
                # strip the ethernet_header and handle
                self.EAP_handler(eap_packet[14:])
        except KeyboardInterrupt:
            exit(-1)
            self.send_logoff()
        except socket.error , msg:
            exit(-1)
