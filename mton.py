#!/usr/bin/env python
# mton.py - masscan to nmap
# This script parses the masscan standard output (text), creating simple ip:port file report
# and feed nmap in order to run versioning and scripts
#
#
# author: dogasantos
# https://github.com/dogasantos/mton
#######

import sys
import nmap
import argparse



def banner():
    print "mton v0.1 - masscan-to-nmap"
    print "---------------------------"

def parser_error(errmsg):
    banner()
    print("Usage: python " + sys.argv[0] + " [Options] use -h for help")
    print("Error: %s" %errmsg)
    sys.exit()

def parse_args():
    parser = argparse.ArgumentParser(epilog='\tExample: \r\npython ' + sys.argv[0] + "-m masscan-report-file.txt")
    parser.error = parser_error
    parser._optionals.title = "Options:"
    parser.add_argument('-m', '--masscan', help="masscan report file", required=True)
    parser.add_argument('-o', '--nmap-output', help="nmap output file", required=True)
    parser.add_argument('-sl', '--script-list', help="Comma separated list of nmap scripts to run", required=False)
    parser.add_argument('-v', '--verbose', help='Enable Verbosity', nargs='?', default=False)
    return parser.parse_args()


def parseMasscan(masscanreport):
    m = open(masscanreport, "r")
    masscan_report_content = m.readlines()
    iplist = list()
    for item in masscan_report_content:
        if '#' in item:
            continue
        iplist.append(item.split(" ")[3])
    iplist = list(set(iplist))  # uniq
    ipdict = dict((el, 0) for el in iplist)

    for unique_ip in iplist:
        pl = list()
        for item in masscan_report_content:
            if '#' in item:
                continue
            if unique_ip == item.split(" ")[3]:
                pl.append(item.split(" ")[2])
        ipdict[unique_ip] = list(pl)

    f = open(masscanreport + ".new", "w")
    for ip,ports in ipdict.iteritems():
        target_ports = ','.join(ports)
        f.write(ip+":"+target_ports+"\n")

    f.close()

    return ipdict





def executeNmap(targets,verbose,script_list,output):
    for ip,ports in targets.iteritems():
        target_ports = ','.join(ports)
        if script_list:
            NMAP_SCRIPTS = script_list
        else:
            NMAP_SCRIPTS = 'http-cors,http-apache-server-status,http-aspnet-debug,http-backup-finder,http-cookie-flags,http-webdav-scan,http-title,http-server-header,http-robots.txt,http-put,http-open-redirect,http-open-proxy,http-method-tamper,http-methods,http-enum,http-errors,http-git,http-headers,http-iis-webdav-vuln,http-internal-ip-disclosure,http-passwd,http-devframework,ssl-enum-ciphers,hostmap-bfk,hostmap-robtex,memcached-info,rtsp-methods,sip-methods,smtp-commands,smtp-open-relay'

        NMAP_ARGUMENTS = "-sV -oG " + output + ".grepable." + ip + " -oN  " + output + ".text." + ip + " --script=" + NMAP_SCRIPTS + " --privileged -Pn "
        if verbose:
            print "Scanning: %s : %s" %(str(ip),target_ports)
        nm = nmap.PortScanner()
        results = nm.scan(hosts=ip, ports=target_ports, arguments=NMAP_ARGUMENTS)
        if verbose:
            print results
            print "="*200
        xmlout = nm.get_nmap_last_output()
        xmlreportfile=output +".xml."+ip
        fx = open(xmlreportfile, "w")
        fx.write(xmlout)
        fx.close()
    return True


if __name__ == "__main__":
    args = parse_args()
    user_masscan = args.masscan
    user_script_list = args.script_list
    user_verbose = args.verbose
    user_output = args.nmap_output

    ipdict = parseMasscan(user_masscan)
    executeNmap(ipdict,user_verbose,user_script_list,user_output)

