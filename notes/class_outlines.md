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

#Thursday, October 6th: Crypto, Part II
* Last class: the golden rules of crypto, symmetric algorithms, one-way hash functions
* Applications: checksums, Git hash (SHA-1)
* Cracking user accounts on Linux systems:
  - Use /etc/passwd and /etc/shadow files from Linux-based systems
  - $algorithm$salt$hash
  - $1$ = MD5
  - $2$ = Blowfish
  - $5$ = SHA-256
  - $6$ = SHA-512
* Today: asymmetric crypto, public and private keys: RSA
* Example: SSH, GitHub
* What does asymmetric crypto does not provide?

#Tuesday, October 11th: Crypto, Part III
* So how does Transport Layer Security (TLS) (also commonly known as Secure Socket Layer or SSL work)?
  - Why? HTTPS is HTTP inside of a TLS session
  - Uses BOTH symmetric and asymmetric crypto
  - Secure communications between two parties over a network
  - On top of TCP
  - Different port numbers used for TLS connection.  Port 443 for HTTPS
  - Part 1: Data between two parties encrypted via symmetric crypto.  Why?
  - Part 2: Identity of communicating parties identified via asymmetric crypto
  - Connection integrity via message integrity check using a message authentication code 
  - Digital certificates - assert the online identities of individuals, computers, and other entities on a network
    - They are issued by certification authorities (CAs) that must validate the identity of the certificate-holder both before the certificate is issued and when the certificate is used.
    - Specification: https://technet.microsoft.com/en-us/library/cc776447(v=ws.10).aspx
* TLS process:
  1. Client connects to TLS-enabled server. Client requesting a secure connection and presents a list of supported cipher suites (ciphers and hash functions).
  2. The server checks what the highest SSL/TLS version is that is supported by them both, picks a ciphersuite from one of the client's options (if it supports one), and optionally picks a compression method.
  3. The server sends back its identification via digital certificate (THIS MAY NOT HAPPEN)
  4. Client confirms validity of certificate --or NOT!
  5. Both the server and the client can now compute the session key (or shared secret) for the symmetric encryption and decryption of the data.  This computation of the session key is known as Diffie-Hellman key exchange.
  6. "The client tells the server that from now on, all communication will be encrypted, and sends an encrypted and authenticated message to the server."
* References:
  - https://security.stackexchange.com/questions/20803/how-does-ssl-tls-work
  - https://stackoverflow.com/questions/788808/how-do-digital-certificates-work-when-used-for-securing-websites-using-ssl
  - http://security.stackexchange.com/questions/45963/diffie-hellman-key-exchange-in-plain-english
  - https://blogs.akamai.com/2016/03/enterprise-security---ssltls-primer-part-1---data-encryption.html
  - https://blogs.akamai.com/2016/03/enterprise-security---ssltls-primer-part-2---public-key-certificates.html
* Creating self-signed certificates:
  - For Apache web servers: https://www.digitalocean.com/community/tutorials/how-to-create-a-self-signed-ssl-certificate-for-apache-in-ubuntu-16-04
  - For nginx web servers: https://www.digitalocean.com/community/tutorials/how-to-create-a-self-signed-ssl-certificate-for-nginx-in-ubuntu-16-04

#Tuesday, October 18th: Web Security
* Last class: Christine's talk => OWASP Top 10, Heartbleed, XSRF
* Loose end 1: bug vs flaw
* Loose end 2: vulnerabilities:
  * Common Vulnerabilities and Exposures (CVE) https://cve.mitre.org/
  - SushiDude a.k.a., Steve Christey Coley
  - The ugly: http://www.csoonline.com/article/3122460/techology-business/over-6000-vulnerabilities-went-unassigned-by-mitres-cve-project-in-2015.html
  - Common Weakness Enumeration (CWE)
  - Crypto and connection with vulnerabilities? See https://cve.mitre.org/about/terminology.html
  - The differences: https://danielmiessler.com/blog/difference-cve-cwe/#gs.03_NSOU, https://www.veracode.com/blog/2016/08/language-appsec
  * National Vulnerability Database https://nvd.nist.gov/home.cfm
  * Exploit DB https://www.exploit-db.com/
* Loose end 1: Cross-Site Scripting (XSS)
  - http://www.veracode.com/blog/2012/07/what-is-cross-site-scripting
* Our attack playground: http://www.cs.tufts.edu/comp/20/hackme.php
* Proxy
* Burp Suite
* SQL injection
  - The idea: twist SQL queries via input data => access or modify data you should not have access to
  - Where to attack: web applications with a database; attack form fields or URL parameters
  - The culprit: the single quote
  - How to determine SQL injection: errors displayed on page
  - Blind SQL injection: asks the database true or false questions and determines the answer based on the applications response
  - Prevention:
    - Filter out special characters
    - Limit data and privileges that a database has access to => least privilege
    - Use prepared statements
* In-class lab: DVWA

#Thursday, October 20th: Web Security
* How I designed the Scapy lab
* Last class: XSS, SQLi, proxy
* Today: XSRF, command execution, file uploads, directory traversal
* hackme.php

#Thursday, November 10th: Static and Dynamic Analysis
* Congratulations!
* CTF recap
* Special CTF recognitions:
  - Most clever hack
  - The lunch pail
* Static analysis:
  * No execution of program
  * Rule based
  * Full coverage
  * Binary: black box
  * Code: white box
  * Examples: lint, Coverity, Fortify, grep
* Dynamic analysis:
  * System execution
  * Trial and error
  * Detect dependencies
  * Deal with real runtime variables
  * Based on automated tests, user interactions
  * No guarantee of full coverage of source
  * Example: Valgrind
* Techniques:
  * Data flow analysis
    * Collect runtime info about data while in a static state
    * Basic block (the code), control flow, control path
  * Control graph
    * Node => block
    * Edges => jumps / paths
  * Taint analysis (also DFA)
    * Identify variables that have been tainted; used vuln fns known as sink
  * Lexical analysis
    * code => tokens  (e.g., /* gets */)
* Strengths and weaknesses
  * Find vulnerabilities with high confidence
  * False positives, false negatives
  * Can't find configuration issues
  * Can you prove findings are vulnerabilities?

#Tuesday, November 15th: Malware
* Virus
  - Think of a biological virus: propagation and piggybacking
  - A malicious piece of executable code
  - Propagates by attaching itself to a host file
  - A virus can be: an executable (i.e., .exe as seen in e-mail attachment), a script, document containing macros
  - A boot sector of a disk partition
  - Note: when propagating, the virus does not have to be an exact copy of itself!
  - If you send infected file to someone else and that person executes the file, it will infect the person's system as well
  - Viruses do not re-infect already infected files
* Worm
  - Does not need to attach itself to another file (i.e., self-contained)
  - Send copies of itself over a network
  - Another difference: a virus infects a machine while a worm infects a network (e.g., consuming bandwidth)
  - How does a worm hop from machine to machine on a network? Using remote commands such as rsh, password cracking, using sockets
  - Techniques
    - Scanning; select random IPv4 addresses
    - Send small packets to reduce suspicion
    - Connect to vulnerable network services, exploit vulnerability
    - Perhaps even open up a shell
* Backdoor
  - Bypasses authentication
  - Grants attacker access to remote machine
  - Connecting to a remote machine: used netcat or a malware kit (e.g., MPack)
  - Example 2: tini.exe
* VirusTotal: https://www.virustotal.com/

#Thursday, November 17th: Malware (continued), Forensics and Incident Handling
* What is forensics?
  - Preservation (of computer media)
  - Identification (of computer media)
  - Extraction (of computer media)
  - Interpretation
  - Documentation
* Process
  - Assess the situation
  - Acquire data
  - Analyze data
  - Report
* Terminology
  - Volatile
  - Non-volatile
  - Physical acquisition - bit-by-bit copy of entire physical store
  - Logical acquisition - bit-by-bit copy of directories and files on a file system partition
  - Write blockers: "devices that allow acquisition of information on a drive without creating the possibility of accidentally damaging the drive contents. They do this by allowing read commands to pass but by blocking write commands" (http://forensicswiki.org/wiki/Write_Blockers)
  - Chain-of-custody - chronological documentation from "crade-to-grave" (i.e., seizre, custody, control, transfer, analysis, disposal)
* Tools
  - strings
  - dd (convert-and-copy)
  - FTK
  - Encase
  - Microsoft COFEE (for law enforcement only)
  - stegdetect
  - Sleuthkit and Autopsy
* Incident Handling. Or Why Incident Handling?
  - Chaos
  - Barking up the wrong trees
  - Dead-end investigations
  - Hard to accumulate knowledge, experience
  - Legal issues
  - Cost overruns
  - Organization (i.e., do not know who to contact)
* Forensics vs. Incident Handling
  - There are overlaps
  - Forensics: "finding and documenting the actions of a person or persons in relation to other people or places or activities. Must have a strong understanding of where and how data is stored, how data is created, how to recover that data in a forensically sound manner and how to analyze the recovered data.""
  - Incident Handling: generally speaking, must be well versed with many facets of IT and information security.
  - Source: http://exforensis.blogspot.com/2009/09/how-is-computer-forensics-different.html

#Tuesday, November 29th: Anti-Forensics, Privacy
* Last class: malware, forensics
* Last class: the USB stick...
* The last lab: disk image --physical or logical acquisition?  Write blocker used?
* Question: countermeasures to forensics?
* Question: what is privacy?
* Why talk privacy?
  1. Misconceptions
  2. Misunderstandings
  3. Legal implications
* True privacy: permits a person to be effectively invisible
* Impossible.  Reasons:
  * ISP logs
  * Poorly written software
  * Technology itself
* The good: Notepad, Paint
* The bad: World of Warcraft, Quickens, Facebook, Microsoft Word
* What to do now in the age of Facebook:
  * Control: comply with person's desire when it comes to handling personal information, data collection
  * Disclosure: failure to explicitly consider privacy => bad press. Examples: Windows Media Player, HP printers
* Mantras:
  * Provide prominent disclosure
  * Put users in charge of their data
  * Seek anonymity
  * _Less is more_
  * Customers come first
* Privacy Enhancing Technologies (PETs): crowds, Tor, Hushmail, prepaid credit cards
* Privacy Aware Technologies (PATs): Unsubscribe, password, encryption
* Goals of PATs and PETs:
  * Unlinkability
  * Anonymity
  * Pseudonymity
  * Unobservability
* Legislation
  * U.S. Safe Harbor Privacy Principles
  * HIPAA (1996)
  * GLBA (1998)
* Current Issues
  * Deploying new technology naively
  * Violating location-based technologies
  * RFID
  * Moble

#What's The Point?
* Course evaluations
* Debate questions:
  * Is it okay to strike back at attackers?
  * Should tools like nmap, Metasploit, Tamper Data be outlawed?
  * Should encryption be outlawed?
  * Edward Snowden: sinner or saint?
  * Should companies spend money on security awareness training for their employees?
  * How long should ISP logs be retained for?
  * True or false: Java is safer to use than C/C++
* Many topics we did not talk about this semester
* We learned a little about a lot this semester. You know enough to be dangerous.
* The morals of the story...
* What's the ultimate point of this class?  Be a good citizen.  Understand tradeoffs.  Talk to those who are curious. Reach out to the non-tech.  Engage and encourage constructive debates.  We have done a lot of that this semester: see privacy discussion.  Stay informed.
* A look back at 2004 when I first proposed a course on security, privacy, and politics
* Looking ahead...
* Your work is not done.

#Future
* Case study: crap login code
* https://crackstation.net/hashing-security.htm