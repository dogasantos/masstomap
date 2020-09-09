#!/usr/bin/env python
# masstomap.py - masscan to nmap
# This script parses the masscan standard output (text), creating simple ip:port file report
# and feed nmap in order to run versioning and scripts
#
# version: v0.3
# Author: dogasantos
# url: https://github.com/dogasantos/masstomap
###############################################################################################

import re
import os
import sys
import nmap
import argparse
import xml.dom.minidom

def banner():
    print("masstomap v0.2 - masscan-to-nmap @dogasantos")
    print("--------------------------------------------")
    print("This script will execute a fast masscan task")
    print("and produce different reports based on provided options:")
    print(" - masscan default report")
    print(" - masscan report with different notation ip:port1,port2,portN ")
    print(" - nmap xml report")
    print(" - nmap text report")
    print(" - nmap grepable report")
    print("\nNOTE: it will produce a xml per target while running, then sumarize into 1 (valid) xml file in the end")
    

def parser_error(errmsg):
    banner()
    print("Usage: python " + sys.argv[0] + " [Options] use -h for help")
    print("Error: %s" % errmsg)
    sys.exit()


def parse_args():
    parser = argparse.ArgumentParser(epilog='\tExample: \r\npython ' + sys.argv[0] + "-m masscan-report-file.txt")
    parser.error = parser_error
    parser._optionals.title = "Options:"
    parser.add_argument('-m', '--masscan', help="masscan report file", required=True)
    parser.add_argument('-n', '--noscan', help="Just convert to ip:port1,port2 notation. Do not execute nmap scan.", required=False, action='store_true')
    parser.add_argument('-o', '--nmap-output', help="nmap output file", required=False)
    parser.add_argument('-sl', '--script-list', help="Comma separated list of nmap scripts to run", required=False)
    parser.add_argument('-v', '--verbose', help='Enable Verbosity', nargs='?', default=False)
    return parser.parse_args()


def parseMasscan(masscanreport, verbose):
    print("[*] Parsing masscan report file")
    m = open(masscanreport, "r")
    masscan_report_content = m.readlines()
    iplist = list()
    for item in masscan_report_content:
        if '#' in item:
            continue
        if "Discovered open port" in item:
            iplist.append(item.split()[5])
            # ['Discovered', 'open', 'port', '45507/tcp', 'on', '192.168.0.1']
        if "open tcp" in item:
            iplist.append(item.split()[3])
    iplist = list(set(iplist))  # uniq
    ipdict = dict((el, 0) for el in iplist)

    if verbose:
        print("  + Filtering entries")

    for unique_ip in iplist:
        pl = list()
        for item in masscan_report_content:
            if '#' in item:
                continue
            if "open tcp" in item:
                if unique_ip == item.split()[3]: #ip
                    pl.append(item.split()[2]) #port
            if "Discovered open port" in item:
                if unique_ip == item.split()[5]: #ip
                    pl.append(item.split()[3].split("/")[0]) #port
        ipdict[unique_ip] = list(pl)

    if verbose:
        print("  + Creating new report")

    f = open(masscanreport + ".new", "w")
    for ip, ports in ipdict.items():
        target_ports = ','.join(ports)
        f.write(ip + ":" + target_ports + "\n")

    f.close()
    if verbose:
        print("  + Done")

    return ipdict

def executeNmap(targets, verbose, script_list, output):
    print("[*] Executing nmap scan")

    for ip, ports in targets.items():
        if os.path.isfile(output + ".nmap.xml." + ip) and os.path.getsize(output + ".nmap.xml." + ip) > 5:
            with open(output + ".nmap.xml." + ip) as r:
                xmlfile = r.read()
                if 'finished time' in xmlfile:
                    print("  + Skipping nmap scan for: "+ ip +" (reason: report file found)")
                    continue

        target_ports = ','.join(ports)
        if script_list:
            NMAP_SCRIPTS = script_list
        else:
            NMAP_SCRIPTS = 'http-title,http-server-header,http-open-proxy,http-methods,http-headers,ssl-cert'

        NMAP_ARGUMENTS = "-sV -oG " + output + ".nmap.grepable." + ip + " -oN  " + output + ".nmap.text." + ip + " --script=" + NMAP_SCRIPTS + " --privileged -Pn --open"
        if verbose:
            print("  + Target:  %s : %s" % (str(ip), target_ports))
        nm = nmap.PortScanner()
        nm.scan(hosts=ip, ports=target_ports, arguments=NMAP_ARGUMENTS)

        if verbose:
            print("  + Target scanned.")
        xmlout = nm.get_nmap_last_output()

        if verbose:
            print("  + Dumping report files (text,xml,grepable)")
        xmlreportfile = output + ".nmap.xml." + ip
        fx = open(xmlreportfile, "w")
        fx.write(xmlout)
        fx.close()
    return True


def wrapupxml(user_output, verbose):
    print("[*] Wrapping up...")
    regex = r"<runstats>.*?</runstats></nmaprun><\?xml\sversion=\"1.0\"\sencoding=.*?<!DOCTYPE nmaprun><\?xml-stylesheet\shref=.*?\?><!--\sNmap\s.*?--><nmaprun\sscanner=\"nmap\".*?xmloutputversion=\"\d\.\d\d\">"
    if verbose:
        print("  + Merging report files")

    grepable_final_report = open(user_output + ".nmap.grepable", "a")
    text_final_report = open(user_output + ".nmap.txt", "a")
    xml_final_report = open(user_output + ".nmap.xml", "a")

    files = os.listdir(".")
    for fname in sorted(files):
        if ".nmap.grepable." in fname:
            gp = open(fname, "r")
            contents = gp.readlines()
            for line in contents:
                line_clean = re.sub('\#\sNmap\sdone\sat\s.*\n#\sNmap\s\d\.\d\d\sscan\sinitiated\s.*\n', '',line)
                if type(line_clean) == 'bytes':
                    line_clean = str(line_clean, 'utf-8' , errors='strict')

                grepable_final_report.write(line_clean)
            gp.close()
            if verbose:
                print("  + Removing: %s" % str(fname))
            os.unlink(fname)

        if ".nmap.text." in fname:
            tf = open(fname, "r")
            contents = tf.readlines()
            for line in contents:
                line_clean = re.sub('Service detection.*?\n\#\sNmap\sDone\sat\s.*?\n\#\sNmap\s\d\.\d\d\sscan\sinitiated\s.*$','',line)
                if type(line_clean) == 'bytes':
                    line_clean = str(line_clean, 'utf-8' , errors='strict') 
                text_final_report.write(line_clean)
            tf.close()
            if verbose:
                print("  + Removing: %s" % str(fname))
            os.unlink(fname)

        if ".nmap.xml." in fname:
            xl = open(fname, "r")
            contents = xl.readlines()
            for line in contents:
                line = str(line, 'utf-8' , errors='strict') 
                xml_final_report.write(line)
            xl.close()
            if verbose:
                print("  + Removing: %s" % str(fname))
            os.unlink(fname)

    grepable_final_report.close()
    xml_final_report.close()
    text_final_report.close()

    with open(user_output + ".nmap.xml", 'r') as fd:
        xmlcontent = fd.read().replace('\n', '')

    #fixing xml report - removing overhead content and make it pareseable
    new = str(re.sub(regex, '', xmlcontent))
    xml_content = xml.dom.minidom.parseString(new)
    pretty_xml_as_string = xml_content.toprettyxml()
    x = open(user_output + ".nmap.xml.clean", "a")
    x.write(pretty_xml_as_string)
    x.close()
    os.unlink(user_output + ".nmap.xml")
    os.rename(user_output + ".nmap.xml.clean",user_output + ".nmap.xml")
    return True

if __name__ == "__main__":
    args = parse_args()
    user_masscan = args.masscan
    user_script_list = args.script_list
    user_verbose = args.verbose
    user_output = args.nmap_output
    noscan = args.noscan

    if os.path.isfile(user_masscan) == False:
        print("[x] The specified masscan file can't be found.")
        sys.exit(1)

    if user_output and noscan:
        print("[x] -n and -o can't work together. Choose just one.")
        sys.exit(1)

    if not user_output:
        user_output="scanreport"

    ipdict = parseMasscan(user_masscan, user_verbose)
    if noscan:
        sys.exit(0)

    ret=executeNmap(ipdict, user_verbose, user_script_list, user_output)
    if ret == False:
        print("[x] Nmap can't reach those targets.")
    else:
        wrapupxml(user_output, user_verbose)
        createxlsx(user_output, user_verbose)

    
