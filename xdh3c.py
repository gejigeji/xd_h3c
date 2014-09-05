#!/usr/bin/env python
# -*- coding:utf-8 -*-
""" Main program for YaH3C.

"""

__version__ = '0.5'

import os, sys
import ConfigParser
import getpass
import argparse
import logging

import eapauth

def usermanager():
    user_info = {}
    user_info['username'] = '1201120226'
    user_info['password'] = '966733'
    user_info['ethernet_interface'] = 'eth0'
    user_info['dhcp_command'] = 'dhclient'
    return user_info

def start_yah3c(login_info):
    yah3c = eapauth.EAPAuth(login_info)
    yah3c.serve_forever()

def main():
    start_yah3c(usermanager())

if __name__ == "__main__":
    main()
