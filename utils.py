import nmap3
import json
from scapy.all import *

def execute():
    print("Executing the program...")
    choose_opt()

def analyze_web(web_url): 
    nmap = nmap3.Nmap()
    results = nmap.nmap_version_detection(web_url, args="-v")
    save_in_file(results, "nmap_version_detection")
    return format_json(results)

def tcp_scan(scan_target):
    nmap = nmap3.NmapScanTechniques()
    results = nmap.nmap_tcp_scan(scan_target, args="-v")
    save_in_file(results, "nmap_tcp_scan")
    return format_json(results)

def heavy_scan(scan_target):
    nmap = nmap3.NmapScanTechniques()
    results = nmap.nmap_tcp_scan(scan_target, args="-A -T4")
    save_in_file(results, "nmap_tcp_scan")
    return format_json(results)

def host_discovery_no_portscan(scan_target):
    nmap = nmap3.NmapHostDiscovery()
    results = nmap.nmap_no_portscan(scan_target, args="-v")
    save_in_file(results, "nmap_no_portscan")
    return format_json(results)

def choose_opt():
    target = ask_user_target()
    while(True):
        opt = ask_user()
        if(opt==1): print(analyze_web(target)); print("Analyzing web page -> ", target)
        if(opt==2): print(tcp_scan(target)); print("Analyzing IP by TCP -> ", target)
        if(opt==3): print(heavy_scan(target)); print("Analyzing IP in a heavy way -> ", target)
        if(opt==4): print(host_discovery_no_portscan(target)); print("Analyzing IP without port scan -> ", target)
        if(opt==0): break


def ask_user():
    opt = 0
    while True:
        opt = int(input("Select an option:\n 1-Analyze a webpage\n 2-TCP Scan\n 3-Heavy scan\n 4-Host Discovery(No portscan)\n 0-Leave\n"))
        if(opt>5 or opt<0):
            print("Wrong number...")
        else:
            break
    return opt

def ask_user_target():
    target = input("Introduce the target:")
    return target
    
def format_json(result):
    return json.dumps(result, indent=4)

def save_in_file(results, scan_type):
    result_text = scan_type, results
    file = open("scan_results.txt", "a")
    written_chars = file.write(str(result_text))
    if(written_chars <= 0): # I think this can't be less than 0, but just in case
        print("Error writing the file")
        return
        
    print("File wrote successfully, check it!!")