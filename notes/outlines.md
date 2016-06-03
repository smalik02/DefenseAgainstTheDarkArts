#Thursday, September 17th: Sniffing
* So you may be curious: how did we capture all those packets?
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


#Tuesday, September 22nd: Scanning
* Last class: sniffing unswitched and switched networks
* Preventing sniffing, redux:
  * anti-arpspoof
  * ArpON
  * Antidote
  * Arpwatch
* Side-note: you can also sniff radio, bluetooth
* Day 2: we talked about the importance of recon
* Scanning
  * Network recon
  * What devices and computers are up?
  * What ports are open on a computer?
  * What services are running
  * Determine possible vulnerabilities
* Basic method: ping sweep
* Problems with ping?
* Netcat
* Nmap

#Tuesday, September 29th: Scanning, Part II
* Recall scanning:
* What could possibly go wrong?
* Want to be stealthy!
* RFC 793: if ports are closed and you send "junk" to it, RST packet will be sent!
  * FIN scan: `sudo nmap -sF ...`
  * NULL scan: `sudo nmape -sN ...`
  * XMAS scan: `sudo nmap -sX ...' # FIN, PSH, URG flags in packet
  * Decoy:
    * `sudo nmap -D...`
    * spoofed connections
    * Must use real + alive IP address, else SYN flood
* SYN flood
    * The idea: exhaust states in the TCP/IP stack
    * Recall TCP/IP handshaking
    * Attacker sends SYN packets with a spoofed source address, the victim, (that goes nowhere)
    * Victim sends SYN/ACK packet but attacker stays slient
    * Half-open connections must time out which may take a while
    * Alas, good SYN packets will not be able to go through
* Defending against scanners
  * No certain way
  * Firewalls?
  * Close services
  * Packet filtering
* Defending against SYN flood
  * Increase queue
  * Filtering
  * SYN cookies
  * Reduce timer for SYN packets

#Thursday, October 1st: Vulnerabilities
* So far, we have covered scanning. Why scan? What are we scanning for?
* Recall: vocabulary (Course Introduction)
* Common Vulnerabilities and Exposures (CVE) https://cve.mitre.org/
  * SushiDude a.k.a., Steve Christey Coley
* Open Sourced Vulnerability Database (OSVDB) http://osvdb.org/
  * attrition.org
  * H.D. Moore
  * Rain Forest Puppy
  * Chris Sullo
* National Vulnerability Database https://nvd.nist.gov/home.cfm
* Exploit DB https://www.exploit-db.com/
* Scanning for vulns:
  * Nikto https://github.com/sullo/nikto
  * OpenVAS
  * Nessus
  * w3af
  * Metasploit (Rapid7) https://github.com/rapid7/metasploit-framework
* About that box that we scanned in class last week......
* So about that box that you scanned for the lab that was due on Tuesday......
  * https://threatpost.com/honeypot-snares-two-bots-exploiting-bash-vulnerability/108578/
  * Legal and ethical issues?

#Tuesday, October 6th: Crypto, Part I
* Last class: vulnerabilities, Herb Lin's lecture
* Final project
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

#Thursday, October 8th: Crypto, Part II
* Last class: basic crypto
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

#Tuesday, October 13th: Crypto, Part III
* Last class: doing authentication correctly, password cracking
* Today: asymmetric crypto, public and private keys: RSA
* Example: SSH, GitHub
* What does asymmetric crypto does not provide?
* Digital certificates - assert the online identities of individuals, computers, and other entities on a network
* They are issued by certification authorities (CAs) that must validate the identity of the certificate-holder both before the certificate is issued and when the certificate is used.
* Specification: https://technet.microsoft.com/en-us/library/cc776447(v=ws.10).aspx
* More: https://security.stackexchange.com/questions/20803/how-does-ssl-tls-work, https://stackoverflow.com/questions/788808/how-do-digital-certificates-work-when-used-for-securing-websites-using-ssl

#Thursday, October 15th: Web Security, Part I
* Web security. Why?
* About the web stack
* The cardinal sin: input validation
* Introductions:
  * OWASP Top 10
  * CWE / OWASP Top 25
  * "76% of .gov applications fail the OWASP top ten vulnerabilities" - https://twitter.com/jrappasaurus/status/654656360588574720
* Our attack playground: http://www.cs.tufts.edu/comp/20/hackme.php
* Proxy
* Burp Suite
* Cross-Site Scripting

#Thursday, October 15th: Web Security, Part II
* Last class: proxies and Cross-Site Scripting
* Preventing XSS
* Auditing mobile apps using a proxy
* AdiOS and Veracode
* SQL injection
  * The idea: twist SQL queries via input data => access or modify data you should not have access to
  * Where to attack: web applications with a database; attack form fields or URL parameters
  * The culprit: the single quote
  * How to determine SQL injection: errors displayed on page
  * Blind SQL injection: asks the database true or false questions and determines the answer based on the applications response
  * Prevention:
    * Filter out special characters
    * Limit data and privileges that a database has access to => least privilege
    * Use prepared statements

#Thursday, November 12th: Static and Dynamic Analysis
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

#Tuesday, December 1st: Anti-Forensics, Privacy
* Put away computers, laptops
* Recent incident (email)
* Last class: forensics, copyrights, trade secrets, patents
* Assignment 5: disk image --physical or logical acquisition?  Write blocker used?
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
* Return Quiz 2

#Thursday, December 10th: What's The Point?
* Debate questions:
  * Is it okay to strike back at attackers?
  * Should tools like nmap, Metasploit, Tamper Data be outlawed?
  * Should encryption be outlawed?
  * Edward Snowden: sinner or saint?
  * Should companies spend money on security awareness training for their employees?
  * How long should ISP logs be retained for?
  * True or false: Java is safer to use than C/C++
* Many topics we did not talk about this semester: exploiting buffer overflows, Distributed Rights Management (DRM), Electronic Voting, cyberwarfare, cryptocurrency, cyber policy, cloud security
* We learned a little about a lot this semester. You know enough to be dangerous.
* But what's the point of this class?  Be a good citizen.  Understand tradeoffs.  Talk to those who are curious. Reach out to the non-tech.  Engage and encourage constructive debates.  We have done a lot of that this semester: see privacy discussion.  Stay informed.
* A look back at 2004 when I first proposed a course on security, privacy, and politics
* Looking ahead, coming spring 2017?
* Your work is not done.