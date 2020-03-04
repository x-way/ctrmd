# ctrmd - conntrack entry removal daemon
[![CircleCI](https://circleci.com/gh/x-way/ctrmd.svg?style=svg)](https://circleci.com/gh/x-way/ctrmd)
[![Go Report Card](https://goreportcard.com/badge/github.com/x-way/ctrmd)](https://goreportcard.com/report/github.com/x-way/ctrmd)

ctrmd provides a mechanism to delete conntrack entries with iptables rules.

As there is no native support for deleting conntrack entries in iptables, the following approach is used:
-   packets are sent to a dedicated NFLOG group in iptables
-   ctrmd listens on this NFLOG group and issues conntrack delete instructions for each received packet

## Usage
Create iptables rule
```
# iptables -I FORWARDING -s 1.2.3.4 -d 5.6.7.8 -j NFLOG --nflog-group 666
```
Start ctrmd
```
# ctrmd -g 666
```
Observe how conntrack entries are deleted (destroyed in conntrack speak)
```
# conntrack -E -e DESTROY
[DESTROY] udp      17 src=1.2.3.4 dst=5.6.7.8 sport=49481 dport=53 src=5.6.7.8 dst=1.2.3.4 sport=53 dport=49481
[DESTROY] udp      17 src=1.2.3.4 dst=5.6.7.8 sport=40945 dport=53 src=5.6.7.8 dst=1.2.3.4 sport=53 dport=40945
[DESTROY] udp      17 src=1.2.3.4 dst=5.6.7.8 sport=49522 dport=53 src=5.6.7.8 dst=1.2.3.4 sport=53 dport=49522
```
