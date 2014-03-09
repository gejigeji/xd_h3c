#-*-coding:utf-8-*
""" EAP authentication handler

This module sents EAPOL begin/logoff packet
and parses received EAP packet 

"""

__all__ = ["EAPAuth"]

import socket
import os, sys, pwd
import time
from subprocess import call
import md5

from colorama import Fore, Style, init
# init() # required in Windows
from eappacket import *

H3C_KEY = 'HuaWei3COM1X'
H3C_VERSION = 'EN V3.60-6303'
H3C_VERSION += '\x00' * (16-len(H3C_VERSION))
Windows_VERSION = 'r70393861'
Windows_VERSION += '\x00' * (20-len(Windows_VERSION))

def display_prompt(color, string):
    prompt = color + Style.BRIGHT + '==> ' + Style.RESET_ALL
    prompt += Style.BRIGHT + string + Style.RESET_ALL
    print prompt

def display_packet(packet):
    # print ethernet_header infomation
    print 'Ethernet Header Info: '
    print '\tFrom: ' + repr(packet[0:6])
    print '\tTo: ' + repr(packet[6:12])
    print '\tType: ' + repr(packet[12:14])

class EAPAuth:
    def __init__(self, login_info):
        # bind the h3c client to the EAP protocal 
        self.client = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ETHERTYPE_PAE))
        self.client.bind((login_info['ethernet_interface'], ETHERTYPE_PAE))
        # get local ethernet card address
        self.mac_addr = self.client.getsockname()[4]
        self.ip = ''
        print [hex(i) for i in unpack('B'*len(self.mac_addr),self.mac_addr)]
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
        print 'send start : ' + repr(eap_start_packet)
        self.client.send(eap_start_packet)

        display_prompt(Fore.GREEN, 'Sending EAPOL start')

    def send_logoff(self):
        # sent eapol logoff packet
        eap_logoff_packet = self.ethernet_header + get_EAPOL(EAPOL_LOGOFF)
        self.client.send(eap_logoff_packet)
        self.has_sent_logoff = True

        display_prompt(Fore.GREEN, 'Sending EAPOL logoff')

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
        print 'send response id : ' + repr(id_msg)

    def send_response_noti(self, packet_id):
        data = '\x01\x16'
        data += self.fillclientversion() + '\x02\x16' + self.fillwindowsversion()
        noti_msg = self.ethernet_header + get_EAPOL(EAPOL_EAPPACKET, pack('!BBHB', EAP_RESPONSE, packet_id, len(data)+5, EAP_TYPE_NOTI)+ data)
        self.client.send(noti_msg)
        print 'send response noti : ' + repr(noti_msg)
        
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
        print 'send eap_packet : ', repr(eap_packet)
        try:
            self.client.send(eap_packet)
        except socket.error, msg:
            print "Connection error!"
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
        print 'send response avai : ' + repr(avai_msg)
        

    def send_response_h3c(self, packet_id):
        resp = chr(len(self.login_info['password'])) + self.login_info['password'] + self.login_info['username']
        eap_packet = self.ethernet_header + get_EAPOL(EAPOL_EAPPACKET, get_EAP(EAP_RESPONSE, packet_id, EAP_TYPE_H3C, resp))
        try:
            self.client.send(eap_packet)
        except socket.error, msg:
            print "Connection error!"
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

    def display_login_message(self, msg):
        """
            display the messages received form the radius server,
            including the error meaasge after logging failed or 
            other meaasge from networking centre
        """
        try:
            print msg.decode('gbk')
        except UnicodeDecodeError:
            print msg

    def EAP_handler(self, eap_packet):
        vers, type, eapol_len  = unpack("!BBH",eap_packet[:4])
        print 'vers, type, eapol_len :', vers, type, eapol_len
        print 'EAPOL_EAPPACKET :', EAPOL_EAPPACKET
        print type == EAPOL_EAPPACKET
        if type != EAPOL_EAPPACKET:
            display_prompt(Fore.YELLOW, 'Got unknown EAPOL type %i' % type)

        # EAPOL_EAPPACKET type
        code, id, eap_len = unpack("!BBH", eap_packet[4:8])
        print 'code, id, eap_len :', code, id, eap_len
        if code == EAP_SUCCESS:
            display_prompt(Fore.YELLOW, 'Got EAP Success')
            
            if self.login_info['dhcp_command']:
                display_prompt(Fore.YELLOW, 'Obtaining IP Address:')
                call( ['nohup', self.login_info['dhcp_command'], self.login_info['ethernet_interface']])

            '''
            if self.login_info['daemon'] == 'True':
                daemonize('/dev/null','/tmp/daemon.log','/tmp/daemon.log')
            '''
        
        elif code == EAP_FAILURE:
            if (self.has_sent_logoff):
                display_prompt(Fore.YELLOW, 'Logoff Successfully!')

                #self.display_login_message(eap_packet[10:])
            else:
                display_prompt(Fore.YELLOW, 'Got EAP Failure')

                #self.display_login_message(eap_packet[10:])
            exit(-1)
        elif code == EAP_RESPONSE:
            display_prompt(Fore.YELLOW, 'Got Unknown EAP Response')
        elif code == EAP_REQUEST:
            reqtype = unpack("!B", eap_packet[8:9])[0]
            reqdata = eap_packet[9:4 + eap_len]
            if reqdata == '':
                print 'reqtype, reqdata :', reqtype
            else:
                print 'reqtype, reqdata :', reqtype, reqdata
            if reqtype == EAP_TYPE_ID:
                display_prompt(Fore.YELLOW, 'Got EAP Request for identity')
                self.send_response_id(id)
                display_prompt(Fore.GREEN, 'Sending EAP response with identity = [%s]' % self.login_info['username'])
            elif reqtype == EAP_TYPE_H3C:
                display_prompt(Fore.YELLOW, 'Got EAP Request for Allocation')
                self.send_response_h3c(id)
                display_prompt(Fore.GREEN, 'Sending EAP response with password')
            elif reqtype == EAP_TYPE_MD5:
                data_len = unpack("!B", reqdata[0:1])[0]
                md5data = reqdata[1:1 + data_len]
                display_prompt(Fore.YELLOW, 'Got EAP Request for MD5-Challenge')
                self.send_response_md5(id, md5data)
                display_prompt(Fore.GREEN, 'Sending EAP response with MD5-Challenge')
            elif reqtype == EAP_TYPE_NOTI:
                display_prompt(Fore.YELLOW, 'Got EAP Request for Notification')
                self.send_response_noti(id)
                display_prompt(Fore.GREEN, 'Sending EAP response with notification ')
            elif reqtype == EAP_TYPE_AVAI:
                display_prompt(Fore.YELLOW, 'Got EAP Request for available')
                self.send_response_avai(id)
                display_prompt(Fore.GREEN, 'Send EAP response with available')
            else:
                display_prompt(Fore.YELLOW, 'Got unknown Request type (%i)' % reqtype)
        elif code==10 and id==5:
            self.display_login_message(eap_packet[12:])
        else:
            display_prompt(Fore.YELLOW, 'Got unknown EAP code (%i)' % code)

    def serve_forever(self):
        try:
            self.send_start()

            while True:
                eap_packet = self.client.recv(1600)
                print(repr(eap_packet))
                self.dstmac = eap_packet[6:12]
                self.ethernet_header = get_ethernet_header(self.mac_addr, self.dstmac, ETHERTYPE_PAE)
                # strip the ethernet_header and handle
                self.EAP_handler(eap_packet[14:])
        except KeyboardInterrupt:
            exit(-1)
            print Fore.RED + Style.BRIGHT + 'Interrupted by user' + Style.RESET_ALL
            self.send_logoff()
        except socket.error , msg:
            print "Connection error: %s" %msg
            exit(-1)

def daemonize (stdin='/dev/null', stdout='/dev/null', stderr='/dev/null'):

    '''This forks the current process into a daemon. The stdin, stdout, and
    stderr arguments are file names that will be opened and be used to replace
    the standard file descriptors in sys.stdin, sys.stdout, and sys.stderr.
    These arguments are optional and default to /dev/null. Note that stderr is
    opened unbuffered, so if it shares a file with stdout then interleaved
    output may not appear in the order that you expect. '''

    # Do first fork.
    try: 
        pid = os.fork() 
        if pid > 0:
            sys.exit(0)   # Exit first parent.
    except OSError, e: 
        sys.stderr.write ("fork #1 failed: (%d) %s\n" % (e.errno, e.strerror) )
        sys.exit(1)

    # Decouple from parent environment.
    os.chdir("/") 
    os.umask(0) 
    os.setsid() 

    # Do second fork.
    try: 
        pid = os.fork() 
        if pid > 0:
            sys.exit(0)   # Exit second parent.
    except OSError, e: 
        sys.stderr.write ("fork #2 failed: (%d) %s\n" % (e.errno, e.strerror) )
        sys.exit(1)

    # Now I am a daemon!
    
    # Redirect standard file descriptors.
    si = open(stdin, 'r')
    so = open(stdout, 'a+')
    se = open(stderr, 'a+', 0)
    os.dup2(si.fileno(), sys.stdin.fileno())
    os.dup2(so.fileno(), sys.stdout.fileno())
    os.dup2(se.fileno(), sys.stderr.fileno())
