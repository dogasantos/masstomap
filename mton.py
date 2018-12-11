#!/usr/bin/env python
# mton.py - masscan to nmap
# This script parses the masscan standard output (text), creating simple ip:port file report
# and feed nmap in order to run versioning and scripts
#
# version: v0.1
# Author: dogasantos
# url: https://github.com/dogasantos/mton
#######

import os
import sys
import nmap
import argparse



def banner():
    print "mton v0.1 - masscan-to-nmap @dogasantos"
    print "---------------------------------------"

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


def parseMasscan(masscanreport,verbose):
    if verbose:
        print "  + Opening masscan report"
    m = open(masscanreport, "r")
    masscan_report_content = m.readlines()
    iplist = list()
    for item in masscan_report_content:
        if '#' in item:
            continue
        iplist.append(item.split(" ")[3])
    iplist = list(set(iplist))  # uniq
    ipdict = dict((el, 0) for el in iplist)

    if verbose:
        print "  + Filtering entries"

    for unique_ip in iplist:
        pl = list()
        for item in masscan_report_content:
            if '#' in item:
                continue
            if unique_ip == item.split(" ")[3]:
                pl.append(item.split(" ")[2])
        ipdict[unique_ip] = list(pl)

    if verbose:
        print "  + Creating new report"

    f = open(masscanreport + ".new", "w")
    for ip,ports in ipdict.iteritems():
        target_ports = ','.join(ports)
        f.write(ip+":"+target_ports+"\n")

    f.close()
    if verbose:
        print "  + Report created and list of targets generated"

    return ipdict

def executeNmap(targets,verbose,script_list,output):
    if verbose:
        print "  + Configuring nmap parameterization"

    for ip,ports in targets.iteritems():
        target_ports = ','.join(ports)
        if script_list:
            NMAP_SCRIPTS = script_list
        else:
            NMAP_SCRIPTS = 'http-aspnet-debug,http-title,http-server-header,http-open-proxy,http-methods,http-headers,http-internal-ip-disclosure'

        NMAP_ARGUMENTS = "-sV -oG " + output + ".nmap.grepable." + ip + " -oN  " + output + ".nmap.text." + ip + " --script=" + NMAP_SCRIPTS + " --privileged -Pn "
        if verbose:
            print "  + Target:  %s : %s" %(str(ip),target_ports)
        nm = nmap.PortScanner()
        results = nm.scan(hosts=ip, ports=target_ports, arguments=NMAP_ARGUMENTS)
        if verbose:
            #print results
            print "  + Target scanned."

        xmlout = nm.get_nmap_last_output()
        if verbose:
            print "  + Dumping report files (text,xml,grepable)"
        xmlreportfile=output +".nmap.xml."+ip
        fx = open(xmlreportfile, "w")
        fx.write(xmlout)
        fx.close()
    return True

def finalize(user_output,verbose):
    if verbose:
        print "  + Merging report files"

    grepable_final_report = open(user_output + ".nmap.grepable", "a")
    text_final_report = open(user_output + ".nmap.txt", "a")
    xml_final_report = open(user_output + ".nmap.xml", "a")

    for fname in sorted(files):

        if ".nmap.grepable." in fname:
            gp=open(fname,"r")
            contents = gp.readlines()
            for line in contents:
                print line
                grepable_final_report.write(line.encode(encoding='UTF-8',errors='strict'))
            gp.close()
            if verbose:
                print "  + Removing: %s" %str(fname)
            os.unlink(fname)

        if ".nmap.text." in fname:
            tf=open(fname,"r")
            contents = tf.readlines()
            for line in contents:
                text_final_report.write(line.encode(encoding='UTF-8',errors='strict'))
            tf.close()
            if verbose:
                print "  + Removing: %s" % str(fname)
            os.unlink(fname)

        if ".nmap.xml." in fname:
            xl=open(fname,"r")
            contents = xl.readlines()
            for line in contents:
                xml_final_report.write(line.encode(encoding='UTF-8',errors='strict'))
            xl.close()
            if verbose:
                print "  + Removing: %s" % str(fname)
            os.unlink(fname)


    grepable_final_report.close()
    xml_final_report.close()
    text_final_report.close()
    return True


def mtonStart(user_masscan,user_script_list,user_verbose,user_output):
    if user_verbose:
        print "[*] Preparing environment"

    if os.path.isfile(user_masscan) == False:
        print "[x] The specified masscan report file does not exist. Please review."
        sys.exit(1)

    if user_verbose:
        print "[*] Starting masscan report parsing"

    ipdict = parseMasscan(user_masscan,user_verbose)
    if user_verbose:
        print "[*] Starting nmap scan phase"
    executeNmap(ipdict,user_verbose,user_script_list,user_output)
    if user_verbose:
        print "[*] Finishing process"

    finalize(user_output,user_verbose)


if __name__ == "__main__":
    args = parse_args()
    user_masscan = args.masscan
    user_script_list = args.script_list
    user_verbose = args.verbose
    user_output = args.nmap_output

    mtonStart(user_masscan,user_script_list,user_verbose,user_output)

