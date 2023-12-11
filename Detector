from scapy.all import IP, TCP, sniff
import argparse
from collections import deque
import time

#parse command-line arguments from chatgpt
parser = argparse.ArgumentParser(description="TCP SYN Flood Attack Detector")
parser.add_argument("-t", "--target", required=True, help="Target IP address")
args = parser.parse_args()

targetIP = args.target
#this part is written by hadi------------------------------------------------
#parameters for TCP SYN flood detection
ipqueueLength = 1000 
rateLimit = 10 #max allowed number of SYN packets per ip address per second
recentIPs = deque(maxlen=ipqueueLength) #the max number of packets in the dequeue ~Hadi
#two empty dictionaries to store the state of incoming connections
connectionStates = {}
portStates = {}

BETA = 0.01#percentage of packets that can be allowed greater
            #than the adaptive threshold value
            #before classifying it as anomalous traffic ~Hadi
initialThreshold = 100  #Initial threshold for SYN packets
meanRate = initialThreshold #meanRate is initialized to 100

def adaptive_threshold(ip_Count): 
    global meanRate
    meanRate = (1 - BETA) * meanRate + BETA * ip_Count
    threshold = (BETA + 1) * meanRate #adaptive threshold formula from https://doi.org/10.1051/itmconf/20213701016 ~Hadi
    return threshold
#this part is written by both Ibrahim and Hadi--------------------------------------------------------------------------------------------
def packet_callback(pkt): #will call for each sniffed packet ~Both
    if IP in pkt and TCP in pkt:
        sourceIP = pkt[IP].src #extracting src ip of packet
        destPort = pkt[TCP].dport #similarly for the port
#end of part written by both----------------------------------------------------------------------------------------------
#this part is written by hadi------------------------------------------------------------------------------------------------
        if pkt[TCP].flags & 0x02:  #checks if it's a SYN packet
            alert1 = False
            alert2 = False
            alert3 = False
            ipCount = recentIPs.count(sourceIP) #counts number of packets recieved ~Hadi
            current_threshold = adaptive_threshold(ipCount)
            recentIPs.append(sourceIP) #appends the sniffed IPs to the recentIPs dictionary
            currentTime = time.time() #gets time from the time library
            if abs(currentTime - pkt.time) <= 10 and ipCount >= current_threshold: #idea is to limit the number of SYN packets to an adaptive threshold 
                alert1 = True                                                       #within a time window such that if they exceed the threshold in that
            if alert1:                                                              #time frame it sends an alert ~Hadi
                print(f"Possible SYN flood detected from {sourceIP} ({ipCount} SYN packets)")
#end of part written by hadi------------------------------------------------------------------------------------------------
#this part is written by ibrahm---------------------------------------------------------------------------------------------
            if sourceIP in connectionStates: #~Ibrahim
                connectionStates[sourceIP] += 1 #increments the count of SYN packets from the source IP in the connection states dictionary
            else:
                connectionStates[sourceIP] = 1 #if source IP is not in connection states dictionary, initializes count to 1

            if connectionStates[sourceIP] > rateLimit: #if limit exceeded prints error
                alert2 = True
            if alert2:
                print(f"Rate limit exceeded for {sourceIP}, potential SYN flood") #print the source ip and potential syn flood msg
            

            if destPort in portStates: #~Ibrahim
                portStates[destPort] += 1 #increments the count of SYN packets from the destination Port in the port states dictionary
            else:
                portStates[destPort] = 1 #if destinantion port is not in port states dictionary, initializes count to 1

            if portStates[destPort] > rateLimit: #if limit exceeded prints error
                alert3 = True
            if alert3:
                print(f"Rate limit exceeded for source port {destPort}, potential SYN flood") #print the destination port and potential syn flood msg
#end of part written by ibrahim-------------------------------------------------------------------------------------------------------
#sniff packets on the specified network interface
sniff(filter=f"dst host {targetIP}", prn=packet_callback)

