import nmap3

def analyze_web(web_url): 
    nmap = nmap3.Nmap()
    result = nmap.nmap_version_detection(web_url)
    return result

def tcp_scan(scan_target):
    nmap = nmap3.NmapScanTechniques()
    results = nmap.nmap_tcp_scan(scan_target)
    return results

def ping_scan(scan_target):
    nmap = nmap3.NmapScanTechniques()
    results = nmap.nmap_ping_scan(scan_target)
    return results

def host_discovery_no_portscan(scan_target):
    nmap = nmap.NmapHostDiscovery()
    results = nmap.nmap_no_portscan()
    return results

def choose_opt():
    opt = ask_user()
    target = ask_user_target()
    if(opt.__eq__(1)): analyze_web(target)
    if(opt.__eq__(2)): tcp_scan(target)
    if(opt.__eq__(3)): ping_scan(target)
    if(opt.__eq__(4)): host_discovery_no_portscan(target)

def ask_user():
    opt = 0
    while True:
        opt = int(input("Select an option 1-Analyze a webpage 2-TCP Scan 3-Ping scan 4-Host Discovery(No portscan)"))
        if(opt>4 or opt<1):
            print("Wrong number...")
        break
    return opt

def ask_user_target():
    target = input("Introduce the target:")
    return target

def execute():
    choose_opt()