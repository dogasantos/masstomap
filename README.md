# MASSTOMAP

masstomap is a simple python script that can be used to read masscan reports and execute nmap powerful service versioning and scripting tasks. 

You need to specify a masscan standard report file (-oL) and a name for the nmap report file this tool should create. 
A nmap grepable, text and xml report will be created. 

### Pause and Resume scan

Masstomap creates a single nmap report per IP/target while it is running against a list of targets. The reason is that you can stop the scan and resume later. Soon as every target is scanned, masstomap will craft a single compliant nmap report using 3 different formats.

### NOTE ###
Again, this tool will create 3 report files per IP/target (text, grepable, xml). All those files will be merged automatically in the end. Don't freak out.

### FILES

This tool will generate 4 files:<br>
<br>
```
<given-report-name>.new - a new masscan report using different notation (ip:port1,port2,portN) so you can run your own (custom) nmap scanning whenever you need.
<given-report-name>.nmap.grepable - a grepable nmap report
<given-report-name>.nmap.text - a standard text nmap report
<given-report-name>.nmap.xml - a xml formated nmap report
```



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
  <tr>
    <td>-t THREADS, --threads THREADS</td>
    <td> number of nmap threads</td>
   </tr>
  <tr>  
</table>



### EXAMPLE:
<br>
First, masscan:<br>
<br>

```
$ sudo masscan -p1-65535 --rate 1000 --open -oL output.masscan <target>
```

<br>
Then masstomap:<br>
<br>

```

$ python /usr/share/masstomap/masstomap.py -m output.masscan -o target.tcp
$ ls
output.masscan  output.masscan.new  target.tcp.nmap.grepable  target.tcp.nmap.txt  target.tcp.nmap.xml
$

```


### Requirements:

check requirements.txt file

Resolve requirements by running 
```
pip install -p requirements.txt
```

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

Remove --privileged if you don't plan to execute nmap as root (won't be able to use synscan, just full tcp scan which is slower)

## RECOMMENDED TOOLS:

### EXCEL OUTPUT

Generate a XLSX (Excel) nmap report:
```
https://github.com/dogasantos/nmapxml-to-xlsx
```

### INTELIGENT WEB TARGETS
Generate a list of WEB targets (with protocol and port):

```
https://github.com/dogasantos/webmapper
```




twitter: @dogasantos
<br>
<br>
Contributers:
<br>
twitter: @R4g3D_
