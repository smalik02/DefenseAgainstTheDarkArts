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
  1. Unswitched - packets flow through all devices on network but you look at only the packets addressed to you......
    - Welp... http://superuser.com/questions/191191/where-can-i-find-an-unswitched-ethernet-hub
  2. Switched - packets flow through specific devices on network
* Promiscuous mode
* Preventing sniffing:
  1. Use encryption and encrypted network protocols
  2. VPN
  3. Use switched network......?
* LAN Tap: http://hakshop.myshopify.com/products/throwing-star-lan-tap-pro
* Address Resolution Protocol
  - IP address to MAC address on a network
  - Recall OSI model and packets
  - `arp -a`
  - ARP cache on machine for 20 minutes
  - No authentication
* ARP spoofing or ARP poisoning

#Tuesday, September 20th: Scanning
* Last class: sniffing unswitched and switched networks
* Is sniffing still relevant today?
* Preventing sniffing on switched network:
  - anti-arpspoof
  - ArpON
  - Antidote
  - Arpwatch
* About that problem on the PCAPs lab
  - A goal of this class: recognition and mindset
  - Base64: binary-to-text encoding scheme.  That is: binary data to ASCII
  - http://stackoverflow.com/questions/6916805/why-does-a-base64-encoded-string-have-an-sign-at-the-end
  - Why? Dangers in printing payload: https://unix.stackexchange.com/questions/73713/how-safe-is-it-to-cat-an-arbitrary-file
  - Why? Basic authentication on web. Example: https://github.com/LiamRandall/BsidesDC-Training/blob/master/http-auth/http-basic-auth-multiple-failures.pcap
* Scanning
  - Why? Network reconnaissance.  Warfare 101
  - What devices and computers are up?
  - What ports are open on a computer?
  - What services are running
  - Determine possible vulnerabilities
* Is scanning still relevant today?
* Basic method: ping sweep
* Problems with ping?
* Netcat
* Nmap

#Tuesday, September 22nd: Scanning, Part II
* Recall scanning:
  - Think poking holes, "ask questions"
* Poking holes => finding interesting and unwanted stuff on networks
  - Shodan: https://www.shodan.io/
* What could possibly go wrong?
* Want to be stealthy!
* RFC 793: if ports are closed and you send "junk" to it, RST packet will be sent! (page 65)
  - FIN scan: `sudo nmap -sF ...`
  - NULL scan: `sudo nmap -sN ...`
  - XMAS scan: `sudo nmap -sX ...' # FIN, PSH, URG flags in packet]
* Decoy:
  - `sudo nmap -D...`
  - spoofed connections
  - Must use real + alive IP address, else SYN flood

#Tuesday, September 27th: Distributed Denial of Service (DDoS) Attacks
* Last class: the stealthy scans, using decoys
* Defending against scanners
  - No certain way
  - Firewalls?
  - Close services
  - Packet filtering
* The first "D" (Distributed) in DDoS: attack source is more than one, often thousands of, unique IP addresses
* SYN flood
  - The idea: exhaust states in the TCP/IP stack
  - Recall TCP/IP handshaking
  - Attacker sends SYN packets with a spoofed source address, the victim, (that goes nowhere)
  - Victim sends SYN/ACK packet but attacker stays slient
  - Half-open connections must time out which may take a while
  - Alas, good SYN packets will not be able to go through
  - Reference 1: https://www.cert.org/historical/advisories/CA-1996-21.cfm?
  - Reference 2, RFC 4987: https://tools.ietf.org/html/rfc4987
  - Reference 3: https://www.juniper.net/documentation/en_US/junos12.1x44/topics/concept/denial-of-service-network-syn-flood-attack-understanding.html
* Defending against SYN flood
  - Increase queue
  - Filtering
  - SYN cookies
  - Reduce timer for SYN packets
* Teardrop (old)
  - The idea: "involves sending fragmented packets to a target machine. Since the machine receiving such packets cannot reassemble them due to a bug in TCP/IP fragmentation reassembly, the packets overlap one another, crashing the target network device." https://security.radware.com/ddos-knowledge-center/ddospedia/teardrop-attack/
  - Recall RFC 791 (IP), the IP packet fields in question: Fragment Offset, Flag (namely "Don't fragment" and "More fragments")
  - Result: "Since the machine receiving such packets cannot reassemble them due to a bug in TCP/IP fragmentation reassembly, the packets overlap one another, crashing the target network device."
  - Reference: https://www.juniper.net/techpubs/software/junos-es/junos-es92/junos-es-swconfig-security/understanding-teardrop-attacks.html
* Ping of Death (old)
  - The idea: violate the IP contract
  - In RFC 791, the maximum size of an IP packet is 65,535 bytes --including the packet header, which is typically 20 bytes long.
  - An ICMP echo request is an IP packet with a pseudo header, which is 8 bytes long. Therefore, the maximum allowable size of the data area of an ICMP echo request is 65,507 bytes (65,535 - 20 - 8 = 65,507)
  - Result: "However, many ping implementations allow the user to specify a packet size larger than 65,507 bytes. A grossly oversized ICMP packet can trigger a range of adverse system reactions such as denial of service (DoS), crashing, freezing, and rebooting."
* ICMP Flood Attack => Overload victim with a huge number of ICMP echo requests with spoofed source IP addresses.
* UDP Flood Attack => Same idea of ICMP flood attack but using UDP packets
* Smurf Attack (old, 1990s) => An example of abusing `ping` and *amplification*
* Defending against ICMP flood and Smurf attacks => Disable `ping`
* DNS Amplification:
  - The idea: "relies on the use of publically accessible open DNS servers to overwhelm a victim system with DNS response traffic."
  - DNS server port number: 53
  - Reference 1: https://www.us-cert.gov/ncas/alerts/TA13-088A
  - Reference 2: https://blog.cloudflare.com/deep-inside-a-dns-amplification-ddos-attack/
  - Case study from last week: Brian Krebs http://krebsonsecurity.com/2016/09/krebsonsecurity-hit-with-record-ddos/
* How easy it is to spoof packets? I want to introduce you to Scapy......
* Example, to make a DNS query: https://gist.github.com/thepacketgeek/6928674

#Thursday, September 29th: Vulnerabilities
* Loose ends:
  - set2.pcap in the PCAPs lab. Motivation: 2015 SANS Holiday Hack Challenge: https://holidayhackchallenge.com/
  - The scapy lab: a larger PCAP that looks very similar to that of set2.pcap
  - So how do you defend against scanning?
  - So how do you defend against DDoS?
  - So is attribution impossible?
  - So about that box that you scanned for the lab......
    - https://threatpost.com/honeypot-snares-two-bots-exploiting-bash-vulnerability/108578/
    - Legal and ethical issues?
* Verizon's 2016 Data Breach Investigations Report (DBIR)
* Recall: vocabulary (Course Introduction)
* Why talk about this now?
  - The next topics have a lot to do about vulnerabilities
  - Vocabulary
  - Understand why software development is very difficult. A painful example......
  - Misconceptions
  - The difficulty of disclosure
* Common Vulnerabilities and Exposures (CVE) https://cve.mitre.org/
  - SushiDude a.k.a., Steve Christey Coley
  - The ugly: http://www.csoonline.com/article/3122460/techology-business/over-6000-vulnerabilities-went-unassigned-by-mitres-cve-project-in-2015.html
* Common Weakness Enumeration (CWE)
* The differences: https://www.veracode.com/blog/2016/08/language-appsec
* Open Sourced Vulnerability Database (OSVDB) http://osvdb.org/
  - attrition.org
  - H.D. Moore
  - Rain Forest Puppy
  - Chris Sullo
  - DEAD, looking for someone to pick it back up
* National Vulnerability Database https://nvd.nist.gov/home.cfm
* Exploit DB https://www.exploit-db.com/
* Scanning for vulns:
  - Nikto https://github.com/sullo/nikto
  - OpenVAS
  - Nessus
  - w3af
  - Metasploit (Rapid7) https://github.com/rapid7/metasploit-framework
* If you do a scan or a penetration test of a system and no vulnerabilities are reported, is that a good thing?
  - The badness-ometer

#Tuesday, October 4th: Crypto, Part I
* This week: crypto, the foundation of Computer Security
* The golden rule: "Never Roll Your Own Crypto"
* Crypto algorithms: symmetric, hash functions, asymmetric
* Tradeoffs to consider:
  * Cost of breaking a cipher
  * Value of the information that is encrypted
  * Time required to break info
  * Lifetime of information?
* The only secure crypto algorithm: One-Time Pad
* Symmetric algorithms: DES, AES, RC4. What do they provide in terms of security? What do they not provide?
* One way hash functions: MD5, SHA-1.  What do they provide in terms of security? What do they not provide?
* Crypto and connection with vulnerabilities? See https://cve.mitre.org/about/terminology.html
* Case study: crap login code
* https://crackstation.net/hashing-security.htm
* Cracking user accounts on Linux systems:
  * Use /etc/passwd and /etc/shadow files from Linux-based systems
  * $algorithm$salt$hash
  * $1$ = MD5
  * $2$ = Blowfish
  * $5$ = SHA-256
  * $6$ = SHA-512

#Thursday, October 6th: Crypto, Part II
* Today: asymmetric crypto, public and private keys: RSA
* Example: SSH, GitHub
* What does asymmetric crypto does not provide?
* Digital certificates - assert the online identities of individuals, computers, and other entities on a network
* They are issued by certification authorities (CAs) that must validate the identity of the certificate-holder both before the certificate is issued and when the certificate is used.
* Specification: https://technet.microsoft.com/en-us/library/cc776447(v=ws.10).aspx
* More: https://security.stackexchange.com/questions/20803/how-does-ssl-tls-work, https://stackoverflow.com/questions/788808/how-do-digital-certificates-work-when-used-for-securing-websites-using-ssl