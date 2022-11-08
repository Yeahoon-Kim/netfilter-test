# netfilter-test
## Objective
* Block malicious site using netfilter
## Component
* ip : IP struct
* ipv4hdr : IPv4 Header Struct
* tcphdr : TCP Header Struct
* netfilter-test : role of main, check packet and decide accept/drop
## Requirements
* jump all packet to netfilter queue using `iptables` command
* find the start point and the length of packet and parse it by the type of IP, TCP, HTTP
* extract Host field from HTTP request and judge if that site is malicious by comparing Host to parameter
* call `nfq_set_verdict` by changing third parameter `NF_DROP` if it is malicious site