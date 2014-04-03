#!/usr/bin/env python
# -*- coding:utf-8 -*-

##测试测试
import os
import sys
import time
import logging
import json
import nmap
import multiprocessing

# def func(host='127.0.0.1', port=None, 
        # arguments=' -PE -PP -PS80,443 -PA3389 -PU40,125 -sS --min-parallelism 30 -T4'):
    # for i in xrange(3):
        # print "%s\n %s\n %s\n" %(host, port, arguments)
        # time.sleep(1)


def json2python(input_file='testscan.json'):
    if not os.path.isfile(input_file):
        print "there is no such file for input !!"
        status = 1
        return status
    testf = open(input_file, 'r')
    original_state = json.load(testf)
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
    
    # f.seek(0)
    f.close()
    status = 0
    return status

        
def portscan(host='127.0.0.1', port='3389', 
        arguments=' -PE -PP -PS80,443 -PA3389 -PU40,125 -sS --min-parallelism 30 -T4'):
    nm = nmap.PortScanner()
    #print nm.listscan('')
    
    try:
        nm.scan(host, port, arguments)
    except :
        print "scan %s failed!!"%(host)
        status = 1
        return status
    print nm.command_line()
    status = 0
    return status,nm[host]

def multiportscan(scan_plan):
    hostlist = scan_plan.keys()
    p = multiprocessing.Pool(processes=5)
    scanprogress = {}
    results = {}
    for host in hostlist:
        if 'tcp' in scan_plan[host] and 'udp' in scan_plan[host]:
            print "scan tcp and udp port in host %s" %(host)
            scanprogress[host] = p.apply_async(portscan, (host, 'T:1-100, U:111', 
                '-PE -PP -PS80,443 -PA3389 -PU40,125 -sS -sU --min-parallelism 30 -T4'))
        elif 'tcp' in scan_plan[host]:
            print "scan only tcp port in host %s" %(host)
            scanprogress[host] = p.apply_async(portscan, (host, '1-100', 
                '-PE -PP -PS80,443 -PA3389 -PU40,125 -sS --min-parallelism 30 -T4'))
        elif 'udp' in scan_plan[host]:
            print "scan only udp port in host %s" %(host)
            scanprogress[host] = p.apply_async(portscan, (host, '111', 
                '-PE -PP -PS80,443 -PA3389 -PU40,125 -sU --min-parallelism 30 -T4'))
    p.close()
    # p.join()
    for host in scanprogress.keys():
        scanresult = scanprogress[host].get()
        print "------------------"
        print host, scanresult
        print "------------------"
        # if type(scanresult) == int or scanresult[0] == 1:
            # failedresult = {host:{'scanstatus':'failed'}}
            # results.update(failedresult)
        # else:
            # successresult = {host:scanresult[1]}
            # successresult[host]['scanstatus'] = 'success'
            # results.update(successresult)
    #sys.exit()    
    
    # return results
    return 0
    # for host in results:
        # print host
    
    
    
    
    
def test_json2python():
    input_results = json2python('testscan.json')
    print input_results
    if type(input_results) == tuple and input_results[0] == 0:
        print input_results[0]
        print "****************************************"
        print input_results[1]
        print "****************************************"
        print input_results[2]
    if type(input_results) == int and input_results == 1:
        print input_results

        
def test_python2json():
    testd = {u'192.168.34.101': {'status': {'state': u'up', 'reason': u'reset'}, 
                u'udp': {111: {'state': u'open|filtered', 'reason': u'no-response', 'name': u'rpcbind'}}, 
                'hostname': '', 'scanstatus': 'success'}, 
            u'192.168.34.100': {'status': {'state': u'up', 'reason': u'echo-reply'}, 
                u'udp': {111: {'state': u'open|filtered', 'reason': u'no-response', 'name': u'rpcbind'}}, 
                'hostname': '', 
                u'tcp': {912: {'state': u'filtered', 'reason': u'no-response', 'name': u'apex-mesh'}}, 
                'scanstatus': 'success'}, 
            u'192.168.34.102': {'status': {'state': u'up', 'reason': u'reset'}, 
                'hostname': '', 
                u'tcp': {912: {'state': u'filtered', 'reason': u'no-response', 'name': u'apex-mesh'}}, 
                'scanstatus': 'success'}}
    # test_result = python2json(testd, '/usr/lib/python2.7/dist-packages/nmap/abcd.json')
    output_json = 'port_scan_output.json_%s' %(time.strftime("%Y%m%d_%H:%M:%S"))
    print output_json
    test_result = python2json(testd, output_json)
    print test_result
    if test_result == 0:
        testf = open(output_json, 'r')
        print testf.readline()



def test_portscan():
    hostlist = []
    for i in range(10):
        if i == 0:
            continue
        hostlist.append('192.168.34.%s'%(i))
    p = multiprocessing.Pool(processes=5)
    results = []
    for host in hostlist:
        scanprogress = p.apply_async(portscan, (host, ))
        scanresult = scanprogress.get()
        if type(scanresult) == int or scanresult[0] == 0:
            #results.append()
            continue
        else:
            # print scanresult[1]
            results.append(scanresult[1])
    p.close()
    for host in results:
        print host

def test_multiportscan():
    # scan_plan = json2python('testscan.json')[2]
    scan_plan = {'163.177.242.54':'tcp','163.177.65.160':'tcp','61.135.169.125':'tcp'}
    results = multiportscan(scan_plan)
    print results

if __name__ == "__main__":
    # pool = multiprocessing.Pool(processes=15)
    # for i in xrange(50):
        # msg = "hello %d" %(i)
        # pool.apply_async(func, (msg, ))
    # pool.close()
    # pool.join()
    # print "Sub-process(es) done."
    #func('127.0.0.1', '1,2,3,4,5')
    
    
    # testportscan()
    # test_json2python()
    test_multiportscan()
    # test_python2json()
    sys.exit()
