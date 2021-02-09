# MASSTOMAP

masstomap is a simple python script that can be used to read masscan reports and execute nmap powerful service versioning and scripting tasks. 

You need to specify a masscan standard report file (-oL) and a name for the nmap report file this tool should create. 
A nmap grepable, text and xml report will be created. 

### Pause and Resume scan

Masstomap creates a single nmap report per IP/target while it is running against a list of targets. The reason is that you can stop the scan and resume later. Soon as every target is scanned, masstomap will craft a single compliant nmap report using 3 different formats.

### FILES

This tool will generate 4 files:<br>
<br>
`<given-report-name>.new` - a new masscan report using different notation (ip:port1,port2,portN) so you can run your own (custom) nmap scanning whenever you need.<br>
`<given-report-name>.nmap.grepable` - a grepable nmap report<br>
`<given-report-name>.nmap.text` - a standard text nmap report<br>
`<given-report-name>.nmap.xml` - a xml formated nmap report<br>



### Usage:

<table style="width:100%">
  <tr>
    <th colspan="2">>$ python masstomap.py [-h] -m MASSCAN -o NMAP_OUTPUT [-sl SCRIPT_LIST] [-v [VERBOSE]]</th>
  </tr>
  <tr>
    <td>-h, --help</td>
    <td> show this help message and exit</td>
  </tr>
  <tr>
    <td>-m MASSCAN, --masscan MASSCAN</td>
    <td> masscan report file</td> 
   </tr>
  <tr>
    <td>-o NMAP_OUTPUT, --nmap-output NMAP_OUTPUT</td>
    <td> nmap output file</td> 
  </tr>
  <tr>
    <td>-sl SCRIPT_LIST, --script-list SCRIPT_LIST</td>
    <td> Comma separated list of nmap scripts to run</td> 
  </tr>
  <tr>
    <td>-v [VERBOSE], --verbose [VERBOSE]</td>
    <td> Enable Verbosity</td> 
  </tr>
  
</table>



###EXAMPLE:
<br>
First, masscan:<br>
<br>
`$ sudo masscan -p1-65535 --rate 1000 --open -oL output.masscan <target>`<br>
<br>
Then masstomap:<br>
<br>
`$ python /usr/share/masstomap/masstomap.py -m output.masscan -o target.tcp`<br>
`$ ls`<br>
`output.masscan  output.masscan.new  target.tcp.nmap.grepable  target.tcp.nmap.txt  target.tcp.nmap.xml`<br>
`$`<br>
<br>
<br>

### Requirements:

python-nmap<br>
argparse<br>

Resolve requirements by running 
`pip install -p requirements.txt`

### NMAP SCRIPTS:

This tool needs nmap in the $PATH so it can be executed, and by default, the following nmap scripts should be executed:
http-title
http-server-header
http-robots.txt
http-open-proxy
http-methods
http-headers
http-internal-ip-disclosure



#### NOTE: 

Remove --privileged if you don't plan to execute nmap as root.

If you're looking for XLSX (excel) nmap output, check my other script here: https://github.com/dogasantos/nmapxml-to-xlsx
I have plans to add this feature as optional, in this tool in the future.

twitter: @dogasantos

