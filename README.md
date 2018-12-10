# MTON

mton is a simple python script that can be used to read masscan reports and execute nmap powerful service versioning and scripting tasks. 

You need to specify a masscan standard report file and a name for the nmap report file this tool should create. A nmap grepable, text and xml report will be created. Yes, all of them so you can feed any tool you may need.

FILES

This tool will generate 4 files:

massscan.new - a new masscan report using different notation (ip:port1,port2,portN) so you can run your own (custom) nmap scanning whenever you need.
project-client-a.nmap.grepable - a grepable nmap report
project-client-a.nmap.text - a standard text nmap report
project-client-a.nmap.xml - a xml formated nmap report


Usage:

$ python mton.py [-h] -m MASSCAN -o NMAP_OUTPUT [-sl SCRIPT_LIST] [-v [VERBOSE]]


Options::

  -h, --help                                      show this help message and exit
  -m MASSCAN, --masscan MASSCAN                   masscan report file
  -o NMAP_OUTPUT, --nmap-output NMAP_OUTPUT       nmap output file
  -sl SCRIPT_LIST, --script-list SCRIPT_LIST      Comma separated list of nmap scripts to run
  -v [VERBOSE], --verbose [VERBOSE]               Enable Verbosity

Requirements;

python-nmap
argparse

Resolve requirements by running pip install -p requirements.txt

NOTES:

This tool needs nmap in the $PATH so it can be executed, and by default, the following nmap scripts should be executed:
http-title
http-server-header
http-robots.txt
http-open-proxy
http-methods
http-headers
http-internal-ip-disclosure



NOTE: Remove --privileged if you don't plan to execute nmap as root.



