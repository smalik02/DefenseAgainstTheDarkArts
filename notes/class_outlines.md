#Tuesday, September 6th
* It feels like I've been gone for a long time...
* A little exercise:
  - When you hear the term information security, list some topics, issues, or things that come to mind.
  - List some information security events that have occurred this calendar year.
* Terminology: Is it Computer Security?  Is it Information Security (infosec)?  Is it Cyber Security?
* The schtick is very different in this course, and this may be arguably the most "different" course you will take in the CS curriculum
* By definition, what is security?
* So how far have we come? (or lack thereof)
* One outcome of this course: question everything
* What's my ultimate goal for you in this course?  We'll revisit this on the last day of class.
* Virtual Machine

#Thursday, September 8th: Social Engineering
* PSA
* Social Engineering
* But, if most Security problems are human-based, then why do we need to focus on exploits, vulnerabilities, the tech stuff?
* Watch: Tacoma Narrows Bridge Fail
* What's the point?

#Tuesday, September 13th: Networking 101
* Last class: social engineering, the achilles heal known as software.  Two very hard problems.
* Read "Trusting Trust".  For most of this course, we will talk about the hard problem of software security.
* The "Trinity of Trouble" by Gary McGraw
	- Complexity
	- Extensibility
	- Connectivity
* Why study networking?
	- The "Connectivity" issue
	- Where the "cool stuff" happens
	- The cyber attribution problem => https://twitter.com/thegrugq/status/706545282645757952
* Recall the telephone conversation analogy for basic networking stuff
* Take it a step further: the OSI model and the seven layers
* Analogy for the OSI model: the US Postal Service => http://bpastudio.csudh.edu/fac/lpress/471/hout/netech/postofficelayers.htm
* Get comfortable reading Request For Proposals (RFPs):
	- Internet Protocol (IP): RFC 791 => http://www.ietf.org/rfc/rfc791.txt
	- Transfer Control Protocol (TCP): RFC 793 => http://www.ietf.org/rfc/rfc793.txt
* A packet: contains implementations of all the protocol layers; encapsulation model
* A PCAP: a file of packet captures from a network
* The Wall of Sheep
* tcpdump, Wireshark, ettercap
* The next lab

#Thursday, September 15th: Sniffing
* So you may be curious: how did we capture all those packets?
* tcpdump, ifconfig
* Two types of networks:
  1. Switched - packets flow through specific devices on network
  2. Unswitched - packets flow through all devices on network but you look at only the packets addressed to you......
* Promiscuous mode
* Preventing sniffing:
  1. Use encryption and encrypted network protocols
  2. VPN
  3. Use switched network......?
* Address Resolution Protocol
  * IP address to MAC address on a network'
  * Recall OSI model and packets
  * `arp -a`
  * ARP cache on machine for 20 minutes
  * No authentication
* ARP spoofing or ARP poisoning