from scapy.all import *
import logging
import netaddr

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

network = "192.168.0.1/24"

addresses = netaddr.IPNetwork(network)
liveCounter = 0

for host in addresses:
    if (host == addresses.network or host == addresses.broadcast):
        continue
    resp = sr1(IP(dst=str(host))/ICMP(), inter=0.1, timeout=1, verbose=0)
    if (str(type(resp)) == "<type 'NoneType'>"):
        print str(host) + "is down or not responding. "
    elif (int(resp.getLayer(ICMP).type)==3 and int(resp.getLayer(ICMP).code) in [1,2,3,9,10,13]):
        print str(host) + "is blocking ICMP."
    else:
        print str(host) + "is responding"
        liveCounter +=1
print "Out of " + str(addresses.size) + "hosts, " + str(liveCounter) + " are online"