#!/usr/bin/env python
# -*- coding:utf-8 -*- 

import os
import sys
import time
import logging
import json
import nmap
import multiprocessing





def checkisroot():
    if os.getuid() != 0:
        status = 1
    else:
        status = 0
    return status



def json2python(input_file='testscan.json'):
    '''This function is used for 
    decode the input json file to python format, 
    input should be a json file, 
    proposed to be :
    {"192.168.34.100": {"status": {"state": "up", "reason": "syn-ack"}, 
                        "hostname": "", "tcp": {"20": {"state": "filtered", 
                                                       "reason": "no-response", 
                                                       "name": "ftp-data"}}}}
    output should be a dictionary of the original state, proposed to be:
    {u'192.168.34.101': {u'status': {u'state': u'up', u'reason': u'syn-ack'}, 
                         u'hostname': u'', 
                         u'tcp': {u'20': {u'state': u'filtered', 
                                                    u'reason': u'no-response', 
                                                    u'name': u'ftp-data'}}}}
    and a dictionary of IP address and protocol for scanning input'''
    if not os.path.isfile(input_file):
        print "there is no such file for input !!"
        status = 1
        return status
    f = open(input_file, 'r')
    try:
        original_state = json.load(f)
    except Exception, e:
        print e
        status = 2
        return status
    scan_plan = {}
    for host in original_state.keys():
        scan_plan[host] = []
        if 'tcp' in original_state[host].keys():
            scan_plan[host].append('tcp')
        if 'udp' in original_state[host].keys():
            scan_plan[host].append('udp')
    status = 0
    return status, original_state, scan_plan


def python2json(ultimate_results, outputfile_name):
    try:
        print outputfile_name
        f = open(outputfile_name, 'w+')
    except Exception, e:
        print e
        status = 1
        return status
    json.dump(ultimate_results, f)
    f.seek(0)
    f.close()
    status = 0
    return status
    

	
def portscan(host='127.0.0.1', port='T:-, U:-', 
        arguments=' -PE -PP -PS80,443 -PA3389 -PU40,125 -sS -sU --min-parallelism 30 -T4'):
    '''This function is used for scanning a single IP address'''
    nm = nmap.PortScanner()
    #print nm.listscan('')
    
    try:
        nm.scan(host, port, arguments)
    except:
        print "scan %s failed!!"%(host)
        status = 1
        return status
    print nm.command_line()
    status = 0
    return status,nm[host]

    

def multiportscan(process_num, scan_plan):
    hostlist = scan_plan.keys()
    p = multiprocessing.Pool(processes=process_num)
    results = {}
    for host in hostlist:
        if 'tcp' in scan_plan[host] and 'udp' in scan_plan[host]:
            print "scan tcp and udp port in host %s" %(host)
            scanprogress = p.apply_async(portscan, (host, 'T:912, U:111', 
                '-PE -PP -PS80,443 -PA3389 -PU40,125 -sS -sU --min-parallelism 30 -T4'))
        elif 'tcp' in scan_plan[host]:
            print "scan only tcp port in host %s" %(host)
            scanprogress = p.apply_async(portscan, (host, '912', 
                '-PE -PP -PS80,443 -PA3389 -PU40,125 -sS --min-parallelism 30 -T4'))
        elif 'udp' in scan_plan[host]:
            print "scan only udp port in host %s" %(host)
            scanprogress = p.apply_async(portscan, (host, '111', 
                '-PE -PP -PS80,443 -PA3389 -PU40,125 -sU --min-parallelism 30 -T4'))
        scanresult = scanprogress.get()
        if type(scanresult) == int or scanresult[0] == 1:
            failedresult = {host:{'scanstatus':'failed'}}
            results.update(failedresult)
        else:
            successresult = {host:scanresult[1]}
            successresult[host]['scanstatus'] = 'success'
            results.update(successresult)   
    p.close()
    return results
    

def main(input_file):
    if checkisroot() == 1:
        print "please execute this script by a root user"
        return 1
    timestamp = time.strftime("%Y%m%d_%H:%M:%S")
    input_json = str(input_file)
    output_json = 'port_scan_output.json_%s' %(timestamp)
    python_format = json2python(input_json)
    if type(python_format) == int and python_format == 1:
        print "there is no such file for input !!"
        return 1
    elif type(python_format) == int and python_format == 2:
        print "format of input file is not json !!"
        return 1
    elif type(python_format) == tuple and python_format[0] == 0:
        print "transform to python success !!"
        original_state = python_format[1]
        scan_plan = python_format[2]
    ultimate_results = multiportscan(5, scan_plan)
    print "checkmulti"
    output_result = python2json(ultimate_results, output_json)
    print "check output"
    if output_result == 1:
        print "transform to output file failed !!"
        return 1
    else:
        f = open(output_json, 'r')
        print f.readline()
    
if __name__ == '__main__':
    # hostlist = []
    # for i in range(255):
        # if i == 0:
            # continue
        # hostlist.append('192.168.34.%s'%(i))
    
    # p = multiprocessing.Pool(processes=10)
    # results = []
    # for host in hostlist:
        # scanprogress = p.apply_async(portscan, (host, ))
        # scanresult = scanprogress.get()
        # if type(scanresult) == int or scanresult[0] == 0:
            # results.append()
            # continue
        # else:
            # results.append(scanresult[1])
    main(sys.argv[1])
    sys.exit()