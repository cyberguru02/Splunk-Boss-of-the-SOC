# Splunk-Boss-of-the-SOC

## Objective
The Boss of the SOC (BOTS) simulation series offers hands-on security training using Splunk, designed in a jeopardy-style capture-the-flag format focused on analyzing and investigating ransomware attacks. In the scenario, we take on the role of Alice Bluebird, a SOC analyst at Wayne Enterprises, tasked with defending against cyber threats. The simulation involve real-world scenarios such as investigating website defacements and tracing attacker activities. This training enhances skills in threat detection, incident response, and using Splunk for detailed analysis and defense strategies, crucial for safeguarding organizations from cyber threats.

### Skills Learned
Gain advanced understanding of Active Directory setup and administration.

Develop proficiency in configuring and utilizing Splunk for log ingestion and analysis.

Acquire the ability to simulate and identify cyber attack signatures and patterns.

Enhance knowledge of network protocols and security vulnerabilities.

Cultivate critical thinking and problem-solving skills in cybersecurity.

### Tools Used
Active Directory: Windows Server 2022 for managing resources.

Splunk: Security Information and Event Management (SIEM) for log and telemetry analysis.

Kali Linux: Platform for simulating various cyber attacks.

Atomic Red Team: Toolset for generating realistic attack scenarios and telemetry.

## Steps
This is a created series of simulations that provides hands-on security practices through Splunk which are mainly considered as blue-team jeopardy-style capture-the-flag-esque (CTF) for analyzing and investigation for Ransomware. In one of the following scenarios of the module, I will do a walkthrough on how I investigated and analyzed on how a website was defaced.

​​

Scenario:

In this scenario, reports of the below graphic come in from your user community when they visit the Wayne Enterprises website, and some of the reports reference “P01s0n1vy.” In case you are unaware, P01s0n1vy is an APT group that has targeted Wayne Enterprises. Your goal, as Alice, is to investigate the defacement, with an eye towards reconstructing the attack via the Lockheed Martin Kill Chain.

​

As Incident Handlers or SOC Analysts, it is essential to understand attackers' tactics, techniques, and procedures to effectively defend against threats. We must look through the lenses of how an attacker might try to deploy and execute malware. Basing off the cyber kill chain, a framework including 7 stages of a cyber threat, can help give us insight on what to look for.

​
![image](https://github.com/user-attachments/assets/38c86fbe-ca02-4c7c-bc86-442a46f5c8a8)

​

​

​

​

​

​

​

​

​

​

​

​

​

​

​

​

​

​

​

​

​

​​​

In this walkthrough I will gather some created questions that highlight parts of the kill chain from various sources that will help give better insight into the logs such as TryHackMe and bots.splunk.com.


Part 1: Reconnaissance

In this phase, the attacker is gathering information about Wayne Enterprises to plan their attack. As Alice Bluebird, the task is to identify and analyze the data that can help one understand what the attacker was looking for and how they might have discovered vulnerabilities in the website. The attacker is likely to collect information from open sources such as social media or perform a network scan to search of open ports, services, and potential vulnerabilities. Let’s go ahead and start tracing down the attacker’s footprints. 

​

Question 1: What is the likely IPv4 address of someone from the Po1s0n1vy group scanning imreallynotbatman.com for web application vulnerabilities?

​

This query allowed us to filter the logs specifically for HTTP traffic related to the imreallynotbatman.com website. This query allowed us to filter the logs specifically for HTTP traffic related to the imreallynotbatman.com website. This query allowed us to filter the logs specifically for HTTP traffic related to the imreallynotbatman.com website. This query allowed us to filter the logs specifically for HTTP traffic related to the imreallynotbatman.com website.

​

​
![image](https://github.com/user-attachments/assets/cdd89330-2e7b-400c-88ab-23371e07a19a)

​

​

​

​

​

​

​

​

​

​

​

​

​

​

​​​

By looking up the search query: “index=botsv1 imreallynotbatman.com sourcetype=stream:http” This query allowed us to filter the logs specifically for HTTP traffic related to the imreallynotbatman.com website.

​

We can examine the “src” field that 40.80.148.42 is the likely ip since it indicates there’s a high volume of communication with the imreallynotbatman.com web server. This high level of activity suggests that the IP address 40.80.148.42 is likely involved in scanning the website for vulnerabilities, as it stands out due to the volume and nature of the traffic. Thus, we can conclude that the likely IPV4 address from the P01s0n1vy group that is scanning for web application vulnerabilities is 40.80.148.42

​

Question 2: One suricata alert highlighted the CVE value associated with the attack attempt. What is the CVE value?

​

Suricata is an intrusion detection system that generates alerts based on network traffic patterns and known vulnerabilities. By examining the Suricata alerts for the specified IP address, we identified an alert that specifically mentioned the Common Vulnerabilities and Exposures (CVE) value associated with the attack attempt. The CVE system provides a reference method for publicly known information-security vulnerabilities and exposures. 



To determine the CVE value associated with the attack attempt on imreallynotbatman.com, we used the following Splunk search query: index=botsv1 imreallynotbatman.com src_ip="40.80.148.42" sourcetype=suricata. This query focused on the Suricata alerts generated from the IP address 40.80.148.42, which we previously identified as likely involved in the attack.


![image](https://github.com/user-attachments/assets/5339f461-ba2e-41f8-8e5a-fb6036518001)



![image](https://github.com/user-attachments/assets/13a0758e-50cf-4d96-97e8-f654aa2bea1d)


















​

​

​​

​

​

​

​

​

​

​

​

​​​​​​

​

Sifting through the alert events and fields, we can conclude that the associated CVE value for the attack attempt is CVE-2014-6271. The presence of this CVE in the alert indicates that the attacker was attempting to exploit this specific vulnerability.



Question 3: What is the content management system (CMS) our web server is using?

​

To determine the content management system (CMS) used by our web server, we examined the HTTP traffic logs. Specifically, we looked at the `http.http_refer` and `http.url` fields for any references that might indicate the CMS being used.

​

Upon investigation, we found multiple references to the term "joomla" in these fields. Joomla is a widely used open-source content management system known for its flexibility and extensive range of features.

​

By cross-referencing these findings with external research, we confirmed that "joomla" is indeed a CMS. The presence of Joomla-related references in the `http.http_refer` and `http.url` fields strongly suggests that our web server is using Joomla as its content management system.

​

Therefore, based on the data from the HTTP traffic logs and subsequent research, we can conclude that the CMS our web server is using is Joomla.





![image](https://github.com/user-attachments/assets/135c3b66-b483-4c9b-95fa-4c68c7f0b742)
























​

​

Question 4: What company created the web vulnerability scanner used by Po1s0n1vy?

​

To identify the company that created the web vulnerability scanner used by the Po1s0n1vy group, we conducted a search using Suricata as the source type. We focused on the keywords “imreallynotbatman.com” and “scan” to locate relevant alerts. The following Splunk search query was used: `index=botsv1 sourcetype=suricata imreallynotbatman.com scan`.



From the results, we examined the `alert.signature` field, which often contains detailed information about the nature of the alert, including the tools or methods used. In this case, the `alert.signature` field indicated that the web vulnerability scanner used in the attack was created by Acunetix, a well-known company in the cybersecurity industry that specializes in web vulnerability scanning solutions.

​

​
![image](https://github.com/user-attachments/assets/7228e137-72c1-4a71-9c7c-a9588c0bf3cb)

​

​

​

​

​

​

​

​

​​

​

​

​​​

​

Additionally, we verified this information by looking at the HTTP stream headers. Using the following query: `index=botsv1 sourcetype=stream:http dest_ip="192.168.250.70" src_ip="40.80.148.42" | table src_headers`, we found further references to Acunetix in the `src_headers` field. This reinforced our initial finding from the Suricata alerts.

​

​![image](https://github.com/user-attachments/assets/0ab99b35-57a5-43f8-9aab-732373c56104)


​

​

​

​​​

Therefore, based on the analysis of Suricata alerts and HTTP stream headers, we can conclude that the web vulnerability scanner used by the Po1s0n1vy group was created by Acunetix.

​

Question 6: What is the IP address of the server imreallynotbatman.com?

​

To determine the IP address of the server hosting imreallynotbatman.com, we analyzed the destination IP addresses recorded in the logs. By focusing on the destination IP (dest_ip) with the highest count of 17,483 occurrences, we can deduce that the IP is likely “imreallynotbatman.com”.



![image](https://github.com/user-attachments/assets/c631c282-cf9d-45d5-9946-2452a53b6cb6)


















Part 2: Exploitation 

In the exploitation phase of a cyber-attack, attackers capitalize on vulnerabilities identified during earlier reconnaissance and scanning stages. This phase marks the transition from passive reconnaissance to active intrusion, where attackers use various tools and methods to exploit specific weaknesses in the target system or network. Their primary objectives include gaining unauthorized access, disrupting services, and potentially exfiltrating sensitive data. Cybersecurity personnels must act swiftly against these exploitations by detecting, patching, or updating configurations to defend from it. As a SOC analyst, Alice in this situation, let’s try to see what sort-of exploitation the attacker used.

​

What was the URI which got multiple brute force attempts? We can see that based on the picutyre the URI, Joomla has multiple brute force attempts made.  

​

​![image](https://github.com/user-attachments/assets/47ddddfc-5ceb-4738-8ec7-fc693d473788)


​

​​

​

​

​

​

​

​

​

​

​

​

​

​

​

​

​

​

​​​​

​

Against which username was the brute force attempt made?​​

​

This query will generate a table ordered by time, displaying attributes such as time and form data. As depicted in the image below, the form_data field contains the username targeted during the brute force attack. This username is ‘admin’ throughout the table. 

​

​![image](https://github.com/user-attachments/assets/796af3a3-b3e3-4cee-9cba-4420c61bbc9a)


​

​

​

​

​

​

​

​

​

​

​

​

​​

​

​

​

​

​

What was the correct password for admin access to the content management system running imreallynotbatman.com?

​
![image](https://github.com/user-attachments/assets/eff02c90-07b2-4961-b6fc-80bfd22a97a9)

​

​

​

​

​

​

​

​​​​​

​

Upon analyzing the logs from the brute force attack on imreallynotbatman.com, it became evident that one of the attacking IP addresses made a single successful attempt to gain admin access. This attempt was indicated by a log entry with a 303 internet status code, typically associated with successful redirection after authentication.

​

I decided to run the query:



index=botsv1 sourcetype=stream:http dest_ip="192.168.250.70" http_method=POST form_data=*username*passwd* | rex field=form_data "passwd=(?<creds>\w+)" |table _time src_ip uri http_user_agent creds src_headers. 

​

Running the query provided a clear indication of the passwords used before the successful login attempt. Based on the analysis of these logs, the correct password for admin access to the content management system running imreallynotbatman.com was determined to be "batman". This password was successfully guessed by the attacker, granting them unauthorized access to the administrative account.



This discovery highlights the critical importance of robust password management practices and continuous monitoring of authentication attempts. Detecting and responding to such unauthorized access incidents promptly is essential for maintaining the security and integrity of web applications and content management systems.



How many unique passwords were attempted in the brute force attempt?

​Using the query:



index=botsv1 sourcetype=stream:http dest_ip="192.168.250.70" http_method=POST form_data=*username*passwd* | rex field=form_data "passwd=(?<creds>\w+)" |stats count(creds) as UniquePassword by src_ip



Adding the count() function with the previous query allows us to find the distinct passwords throughout the logs

​

​

​

​![image](https://github.com/user-attachments/assets/b3a1d28b-5d80-4706-b3fa-d46fdfe98a79)


​

​



​

​​​​

The answer is 412

​

What IP address is likely attempting a brute force password attack against imreallynotbatman.com?



To pinpoint the IP address behind a suspected brute force password attack, on imreallynotbatman.com I took an approach centered around web application attacks that involve HTTP traffic. Brute force attacks usually result in HTTP traffic flow between the attacker and the web server.



In line with methods I started by extracting all HTTP traffic logs using the query: index="botsv1" sourcetype=stream:http
Initially most of the traffic was traced back to IP address 40.80.148.42 linked to the Po1s0n1vy group. While this IP address was a starting point I narrowed down my search for a force attack by employing a regex pattern search within the HTTP traffic logs. By filtering logs with index=botsv1 sourcetype="stream:http" | regex (passw) I honed in on entries containing "passw" which hinted at password related activity. This refined search revealed that 93.62% of entries were tied to IP address 23.22.63.114.

​
![image](https://github.com/user-attachments/assets/0ad1ecbb-95de-40a9-9cc2-4319f3799ccb)

​

​​

​

​

​

​

​

​

​

​

​

​

​​​

​



Installation Part:

This is the phase where attackers prepare the infrastructure and tools necessary to execute their cyber operations effectively. From the attacker's perspective, installation involves setting up command and control (C2) servers, deploying malware onto compromised systems, and establishing persistence mechanisms to maintain access.



As a SOC analyst, like Alice in this scenario, this sets the stage for subsequent threat detection and response actions, allowing for timely identification of vulnerabilities and proactive defense strategies to protect sensitive assets and maintain operational continuity. By comprehending the tactics employed during installation, SOC analysts can enhance their ability to detect and mitigate potential threats early in the attack lifecycle, thereby minimizing the impact of cyber incidents and safeguarding organizational assets against persistent adversaries. Let’s see how the attackers installed the malware on the web server.



Sysmon also collects the Hash value of the processes being created. What is the MD5 HASH of the program 3791.exe?



In this scenario, to find the MD5 hash of the program `3791.exe`, we can use the following Splunk query:



index=botsv1 "3791.exe"index=botsv1 "3791.exe" sourcetype="XmlWinEventLog" EventCode=1 CommandLine="3791.exe" 

​

This query searches for events related to the execution of `3791.exe`, specifically filtering for logs that match the event code indicating process creation (EventCode=1) and the command line containing `3791.exe`.

​

​
![image](https://github.com/user-attachments/assets/79478232-e22a-4bfb-8bd6-72a48ea0d75e)



The event code `EventCode=1` is from Sysmon logs which represents process creation. This event is logged whenever a new process is started on the system, capturing critical details such as the process name, its hash values, the command line used to execute it, and other attributes. This information is invaluable for security analysts as it helps in tracking the execution of programs and identifying potentially malicious activities.



From the search results, we find that the MD5 hash value for the program `3791.exe` is  AAE3F5A29935E6ABCC2C2754D12A9AF0. The MD5 (Message Digest Algorithm 5) hash provides a unique fingerprint for the file based on its content. We can take the hash into virustotal to see if the hash matches anything malicious which has been flagged. 

​

​![image](https://github.com/user-attachments/assets/af04db15-0957-4695-97cf-8615ea69fe65)


By capturing and analyzing these hash values, SOC analysts can quickly identify and respond to potential threats, ensuring that any unauthorized or malicious software is detected and mitigated promptly. In this case, identifying the MD5 hash of `3791.exe` helps in tracking the specific instance of the program and assessing its potential impact on the system.


Looking at the logs, which user executed the program 3791.exe on the server?​

​

We can check on one of the event logs pulled from one of the previous queries regarding the “3791.exe” and devlve deeper into one of them. In the picture below, I find the user who exevuted the program, “NT AUTHORITY\USR”.

​​
![image](https://github.com/user-attachments/assets/1582c592-b732-420d-9b43-46fd266d1b09)

​
​​​​

Search hash on the virustotal. What other name is associated with this file 3791.exe?

​

By using the hash of the file, AAE3F5A29935E6ABCC2C2754D12A9AF0, into virus total, we can see that the file itself is malicious. We can also see the names in the pictures below that are associated with the hash. 



![image](https://github.com/user-attachments/assets/05394cbc-949e-4c1e-921d-a3e7c87f91cc)



![image](https://github.com/user-attachments/assets/00d19340-ccfb-4e08-ba39-0022e75a9aa1)


Actions on Objective:

This is where attackers move towards achieving their ultimate goals after gaining initial access and conducting necessary exploitation. In this phase, attackers focus on executing specific actions aligned with their objectives, which typically involve further infiltration, data exfiltration, or disruption of services within the compromised environment. 

As a SOC analyst, Alice in this situation, understanding the actions on objective phase is crucial. It represents the culmination of an attacker's efforts, where they aim to maximize the impact of their intrusion. Analysts must diligently monitor for indicators of compromise (IOCs) and anomalous behaviors indicative of unauthorized activities. Rapid detection and response are essential to mitigating potential damage and preventing further escalation of the attack.

During this phase, security teams deploy advanced threat detection mechanisms, leverage threat intelligence, and collaborate closely with incident response teams to contain and neutralize the threat effectively. This proactive approach involves updating defenses, applying patches, and reconfiguring security controls to fortify against ongoing attacks and future threats.



Ultimately, the actions on objective phase underscores the critical importance of continuous monitoring, rapid response capabilities, and proactive defense strategies in safeguarding organizational assets and maintaining operational resilience against sophisticated cyber threats.


What is the name of the file that defaced the imreallynotbatman.com website?


To identify this malicious file, we focused on the HTTP traffic, as it likely involved a download via the web. Using the stream:http source type and the victim’s IP address (192.168.250.70), we looked for suspicious activity in the src_headers field. Using the query: index=botsv1 src=192.168.250.70 sourcetype=suricata dest_ip=23.22.63.114, we can uncover a suspicious filename. To look into the file name more in-depth, I went and queried, "index=botsv1 url="/poisonivy-is-coming-for-you-batman.jpeg" dest_ip="192.168.250.70" | table _time src dest_ip http.hostname url" to display relevant field(s) within a table format. I was able to confirm that the file is “poisonivy-is-coming-for-you-batman.jpeg". With the information provided I am also able to confirm the details about the file of where it came from and sent to.


​
![image](https://github.com/user-attachments/assets/01c91a09-f964-40c0-a9fb-6469219e71d5)




Fortigate Firewall 'fortigate_utm' detected SQL attempt from the attacker's IP 40.80.148.42. What is the name of the rule that was triggered during the SQL Injection attempt?



By searching up the query: index=botsv1 src=40.80.148.42 sourcetype=suricata



I am able to see what alert event logs from suritcata in regards to the attacker’s ip, and check the attack or alert.signature field to see if a rule triggered. In the picture it’s shown that the attacker has triggered the HTTP.URI.SQL.Injection, which we were seeking for.


![image](https://github.com/user-attachments/assets/691fbf8b-0209-4995-a0a1-c7ec2708e29a)


                                        Answer: HTTP.URI.SQL.Injection
Command & Control (C2):

This is where attackers establish a covert communication infrastructure to maintain control over compromised systems or networks. During this phase, after successfully infiltrating a target environment, attackers deploy command and control (C2) mechanisms to remotely manage and orchestrate malicious activities. This includes communicating with compromised endpoints, transmitting stolen data, and executing further instructions to advance their objectives.



In the context of a cyber-attack lifecycle, the Command & Control phase follows the initial stages of reconnaissance, scanning, and exploitation. It represents a critical juncture where attackers leverage their foothold to ensure persistence and operational continuity within the compromised infrastructure. By setting up C2 channels through encrypted protocols or covert communication methods, attackers evade detection and maintain a persistent presence, enabling ongoing malicious operations.

For cybersecurity personnel, rapid detection and response during the C2 phase are paramount. Security analysts like Alice in the SOC must monitor network traffic for suspicious patterns indicative of C2 communications. By analyzing network logs and behavior anomalies, SOC teams can identify unauthorized data transmissions, unusual command executions, or attempts to evade detection measures.



Ultimately, understanding the tactics employed in the C2 phase allows cybersecurity professionals to implement proactive defense measures. This includes blocking malicious domains, disabling unauthorized network protocols, and continuously updating security controls to thwart ongoing C2 activities. By disrupting command and control mechanisms, organizations can mitigate the impact of cyber-attacks, protect sensitive data, and restore operational integrity swiftly.



This attack used dynamic DNS to resolve to the malicious IP. What fully qualified domain name (FQDN) is associated with this attack?


To find the IP address the attacker used, we can examine network-centric log sources based on using the Fortigate firewall logs, despite confirming the answer in a different question. Use the search query: index=botsv1 sourcetype=fortigate_utm "poisonivy-is-coming-for-you-batman.jpeg". By searching it we can check the logs to confirm what the FQDN is and it’s showing the identified host as prankglassinebracket.jumpingcrab.com in the packet that made the GET request for the JPEG image used to deface the website.

![image](https://github.com/user-attachments/assets/70a1cf26-0a29-4044-a672-ab988c635228)



Weaponization:

This is where attackers convert identified vulnerabilities into actual cyber weapons capable of exploiting target systems or networks. During this phase, attackers harness the weaknesses uncovered during reconnaissance and scanning to develop and deploy malicious payloads or exploits. This marks a critical shift from passive information gathering to active attack execution, where the goal is to achieve unauthorized access, disrupt services, or extract sensitive data.

​

As attackers weaponize vulnerabilities, they often employ sophisticated techniques such as crafting malware, creating malicious documents, or exploiting software flaws to deliver payloads that can compromise targeted systems. These malicious tools and methods are designed to evade detection and exploit specific weaknesses in the target environment.



Cybersecurity personnel must respond swiftly during this phase by actively monitoring for indicators of compromise (IOCs), analyzing suspicious behaviors, and implementing defensive measures. This includes patching vulnerabilities, updating security configurations, and deploying intrusion detection systems (IDS) or endpoint protection to detect and block malicious activities.



As a SOC analyst like Alice in this scenario, understanding the methods of exploitation used by attackers is crucial. By analyzing attack vectors and the specific techniques employed during weaponization, SOC teams can effectively mitigate risks, protect organizational assets, and maintain operational resilience against evolving cyber threats.


​

What IP address has P01s0n1vy tied to domains that are pre-staged to attack Wayne Enterprises?



Based on the data gathered from this attack and common open-source intelligence (OSINT) sources for domain names, what is the email address that is most likely associated with the P01s0n1vy APT group?

​

Since we are able to utilize any OSINT sources, I decided to perform an IP search on 23.22.63.114 on Crowd Strike, an cyber attack response service company, which reveals the likely associated email address: 

​

​​![image](https://github.com/user-attachments/assets/35be868d-83d4-4df2-a711-cdff3e61eeb5)


Delivery:

This is where attackers initiate the deployment of malicious components to the target environment. It represents a critical phase in the cyber-attack lifecycle where adversaries attempt to deliver payloads, such as malware or exploit kits, through various vectors. Attackers leverage tactics like phishing emails, malicious attachments, or compromised websites to deliver their payloads to unsuspecting users or systems.



During this phase, attackers exploit vulnerabilities identified in earlier reconnaissance stages to gain initial access or compromise trusted channels. Their primary goal is to establish a foothold within the target environment, enabling further exploitation and potential data exfiltration.



As a SOC analyst, Alice in this situation, understanding the delivery phase involves analyzing indicators such as suspicious email attachments, unusual network traffic patterns, or unexpected file downloads. By detecting and mitigating these delivery mechanisms swiftly, cybersecurity personnel can prevent the initial compromise and minimize the risk of subsequent exploitation. Implementing robust email filtering, endpoint protection, and user awareness training are crucial defenses against delivery-based attacks, ensuring proactive defense measures to safeguard organizational assets and data.

​

This following questions outlines the significance of the Delivery phase in cyber-attacks, emphasizing the role of SOC analysts in detecting and mitigating potential threats during this critical stage of the attack lifecycle.

​

What is the HASH of the Malware associated with the APT group?

​

I went to the Hybrid Analysis, a malware analysis website, and looked up the APT group to see the asociated hash.


![image](https://github.com/user-attachments/assets/c6584b38-12ce-4b2d-94f0-f9d1ccf77984)





It reveals the MD5 hash: c99131e0169171935c5ac32615ed6261, as the associated hash with the APT group.



What is the name of the Malware associated with the Poison Ivy Infrastructure?



I ran the hash to determine what the malware was on virustotal, and saw it was associated with the name - MirandaTateScreensaver.scr.exe



​
![image](https://github.com/user-attachments/assets/cf0921e9-72d7-4ed3-937b-3edd92ebf80d)



​

Went to Hybrid Analysis as well to get more info about it as well:

![image](https://github.com/user-attachments/assets/973dfdf8-652a-4b42-b063-5e8d46fc980a)
