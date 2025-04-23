# RTT-Geo-Location-Anomaly-Detector
RTT GAD is a Wireshark plugin written in Lua that analyzes the Round-Trip Time of TCP and ICMP packets. The goal is to determine whether the host is actually located in the region corresponding to its registered IP address ( or if it is masking its true location using technologies such as VPNs, Tor, intermediate caches/CDNs, etc... )
