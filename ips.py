#!/usr/bin/python3

#------------------------------------------------------------------------------
# SOURCE: ips.py
#
# PROGRAM: COMP 8006 IPS
#
# FUNCTIONS:
#	parse_arguments()
#	parse_ip(attempts, delay)
#
# DATE: March 2, 2016
#
# DESIGNERS: Rizwan Ahmed, Vishav Singh
# PROGRAMMERS: Rizwan Ahmed, Vishav Singh
#
# NOTES:
#  This script is activated via crontab. It will monitor the/var/log/secure file
# and track failed password attempts. If an IP has exceeded the maximum number
# of attempts specified by the user, the script will use Netfilter to block that
# IP indefinitely. The script will also make a list of blocked IPs.
#------------------------------------------------------------------------------
import time
import string
import re
import os
import argparse
import sys

#------------------------------------------------------------------------------
# FUNCTION: parse_arguments
#
# RETURNS:
#  attempts - maximum number of allowed attempts before blocking
#  delay - time between attempts for slow scan (not implemented)
#  tBan - duration of ban (not implemented)
#
# NOTES: Parses the arguments set in the crontab.
#------------------------------------------------------------------------------
def parse_arguments():
    parser = argparse.ArgumentParser()
    parser.add_argument('-a', '--attempt', nargs=1, help='Number of attempts before blocking the IP.', required=True, dest='attempt')
    parser.add_argument('-t', '--time', nargs=1, help='Time Limit an IP is blocked for.', required=True, dest='time')
    parser.add_argument('-d', '--delay', nargs=1, help='Delay between Attempts', required=True, dest='delay')
    args = parser.parse_args()
    attempts = int(args.attempt[0])
    #Multiply the numbers by 60 to convert the minutes to seconds
    delay = int(args.delay[0])
    delay = delay * 60
    tBan = int(args.time[0])
    tBan = tBan * 60
    return attempts, delay, tBan

#------------------------------------------------------------------------------
# FUNCTION: parse_ip
#
# PARAMETERS:
#  attempts - maximum number of allowed attempts before blocking
#  delay - time between attempts for slow scan (not implemented)
#
# RETURNS: nothing
#
# NOTES: Reads through a list of failed attempts from /var/log/secure and
# keeps track of the number of attempts for each IP address. If an IP exceeds
# the maximum number of attempts, iptables is used to block that IP. A list of
# blocked IP addresses is written to another file.
#------------------------------------------------------------------------------
def parse_ip(attempts, delay):
    f = open("ip.txt", 'r')
    bf = open("block.txt", 'w')
    count = 0
    #for line in f:
    #    time,ip,port = line.split()
    #    print("IP", ip , "time", time)
    log_data = f.readlines()
    f.close()
    ips = []
    occurence = {}
    with open ("ip.txt", 'r') as file:
        for ip in file:
            ip_data=re.findall(r'(?:[\d]{1,3})\.(?:[\d]{1,3})\.(?:[\d]{1,3})\.(?:[\d]{1,3})',ip)
            for i in ip_data:
                ips.append(i)
        for ipaddr in ips:
            if ipaddr in occurence:
                occurence[ipaddr] = occurence[ipaddr] + 1
            else:
                occurence[ipaddr] = 1
    for key, value in occurence.items():
        if value > attempts:
            bf.write('{} Value {}\n'.format(key,value))
            os.system("/usr/sbin/iptables -A INPUT -s %s -j DROP" % key)
            os.system("/usr/sbin/iptables -A OUTPUT -d %s -j DROP" % key)

    bf.close()
    return None

if __name__ == "__main__":
    attempts, delay, tBan = parse_arguments()
    os.system("cat /var/log/secure | grep 'Failed password' > data.txt")
    os.system("awk -F\" \" '{ print $3 \" \" $11 \" \" $13}' /root/Documents/data.txt > ip.txt")
    parse_ip(attempts,delay)
