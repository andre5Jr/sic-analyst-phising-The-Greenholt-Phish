# soc-analyst-phising-The-Greenholt-Phish

📝 Project Title:
TryHackMe – Phishing Emails: Investigating a Suspicious Email and Its Malicious Attachment

🎯 Objective:
Analyze a suspicious phishing email by examining its metadata, origin, and attachment to extract key indicators of compromise (IOCs). The goal is to identify the spoofed sender, investigate DNS records (SPF/DMARC), and evaluate the malicious file embedded in the email to assess the threat.

🛠️ Tools Used:

Email Header Analysis
VirusTotal
MXToolbox (DNS record lookup)
Hex Editor / File Signature Analysis
TryHackMe Lab Environment
WHOIS Lookup Tools

❌ Skills Demonstrated:

Email forensics and header parsing
DNS SPF/DMARC verification
File hash analysis (SHA256)
Threat intelligence enrichment
Phishing campaign detection and attachment inspection

Project Overview: 
This lab simulates a real-world phishing investigation scenario. The exercise begins with a suspicious email received by a user. The objective is to analyze the email header, origin, and attachment to answer targeted investigative questions. Through this hands-on lab, the goal is to build a foundational understanding of phishing indicators and forensic processes related to email-based threats.

Task Breakdown

✏️ Task 1: Identify the Transfer Reference Number
Objective: What is the Transfer Reference Number listed in the email's Subject?

Method: Review the email subject line in the provided header or email interface. The reference number is often in a structured format (e.g., numeric or alphanumeric).

✏️ Task 2: Determine the Sender's Name
Objective: Who is the email from?

Method: Locate the "From" field in the email header or email client view. This field may be spoofed, so validate via header details.

✏️ Task 3: Extract the Sender’s Email Address
Objective: What is his email address?

Method: Parse the header’s “From” field for the email address. Confirm consistency with the display name.

✏️ Task 4: Identify the Reply-To Address
Objective: What email address will receive a reply to this email?

Method: Check the “Reply-To” header field. This often differs from the “From” address in phishing campaigns.

✏️ Task 5: Trace the Originating IP Address
Objective: What is the Originating IP?

Method: Look for the first Received: header (bottom-most) in the email header. Extract the IP from the "by" or "from" line.

✏️ Task 6: Investigate the IP Owner
Objective: Who is the owner of the Originating IP? (Do not include the "." in your answer.)

Method: Use WHOIS lookup tools (e.g., ARIN, RIPE) to determine the registered owner of the originating IP.

✏️ Task 7: Retrieve the SPF Record
Objective: What is the SPF record for the Return-Path domain?

Method: Use MXToolbox or dig/nslookup to retrieve the SPF TXT record for the Return-Path domain.

✏️ Task 8: Retrieve the DMARC Record
Objective: What is the DMARC record for the Return-Path domain?

Method: Query for _dmarc.domain.com using DNS tools to extract DMARC TXT records.

✏️ Task 9: Identify the Attachment Name
Objective: What is the name of the attachment?

Method: Open the email or header to view MIME sections. The filename= field typically reveals the attachment name.

✏️ Task 10: Get the SHA256 Hash of the Attachment
Objective: What is the SHA256 hash of the file attachment?

Method: Upload the file to VirusTotal or use a hash tool (sha256sum) to calculate its hash locally.

✏️ Task 11: Determine the File Size
Objective: What is the attachment’s file size? (Don't forget to add "KB" to your answer, NUM KB)

Method: Check VirusTotal analysis or local file properties to extract the file size in kilobytes.

✏️ Task 12: Identify the True File Extension
Objective: What is the actual file extension of the attachment?

Method: Inspect file magic bytes with a hex editor or use file command to determine its true file type (not just by name).

🔍 Analysis and Reflection

💡 Challenges Faced:

Detecting forged email headers in layered MIME formatting
Interpreting DNS records across SPF, DKIM, and DMARC
Identifying true file extensions despite misleading names

💡 Lessons Learned:

Reply-to mismatches are common phishing red flags
SPF/DMARC validations help identify domain spoofing
File analysis requires more than extension checking

💡 Relevance to SOC Analyst Roles:

Enhances phishing email triage skills
Builds understanding of email metadata and sender verification
Reinforces importance of IOCs in early detection

💡 Relevance to Penetration Testing / Red Teaming:

Demonstrates common phishing vectors used for initial access
Reinforces use of social engineering through email
Validates how simple attachments can bypass basic filters

✅ Conclusion

💡 Summary: Through header inspection and DNS record analysis, the email’s spoofed origin, reply-to mismatch, and malicious attachment were revealed. The analysis provided a SHA256 hash, true file extension, and file size of the weaponized payload. This lab modeled the step-by-step investigative process for SOC analysts and threat hunters.

💡 Skills Gained:

Email header forensics
SPF/DMARC analysis
File integrity and malware detection
DNS record and WHOIS interpretation

💡 Next Steps:

Build detection rules for SPF/DMARC failures
Incorporate YARA or Sigma rules to catch similar phishing attempts
Test email gateway filters using simulated phishing scenarios

![image alt](https://github.com/andre5Jr/soc-analyst-phising-The-Greenholt-Phish/blob/27c2a666742dc5b0caa6d1cca0dd5ecfbd1174ba/1-1.png)   

![image alt]https://github.com/andre5Jr/soc-analyst-phising-The-Greenholt-Phish/blob/27c2a666742dc5b0caa6d1cca0dd5ecfbd1174ba/2-1.png)   

![image alt](https://github.com/andre5Jr/soc-analyst-phising-The-Greenholt-Phish/blob/27c2a666742dc5b0caa6d1cca0dd5ecfbd1174ba/3-1.png)   

![image alt](https://github.com/andre5Jr/soc-analyst-phising-The-Greenholt-Phish/blob/27c2a666742dc5b0caa6d1cca0dd5ecfbd1174ba/4-1.png)   

![image alt](https://github.com/andre5Jr/soc-analyst-phising-The-Greenholt-Phish/blob/27c2a666742dc5b0caa6d1cca0dd5ecfbd1174ba/5-1.png)   

![image alt](https://github.com/andre5Jr/soc-analyst-phising-The-Greenholt-Phish/blob/27c2a666742dc5b0caa6d1cca0dd5ecfbd1174ba/6-1.png)   

![image alt](https://github.com/andre5Jr/soc-analyst-phising-The-Greenholt-Phish/blob/27c2a666742dc5b0caa6d1cca0dd5ecfbd1174ba/7-1.png)   

![image alt](https://github.com/andre5Jr/soc-analyst-phising-The-Greenholt-Phish/blob/27c2a666742dc5b0caa6d1cca0dd5ecfbd1174ba/7-2.png)   

![image alt](https://github.com/andre5Jr/soc-analyst-phising-The-Greenholt-Phish/blob/27c2a666742dc5b0caa6d1cca0dd5ecfbd1174ba/8-1.png)   

![image alt](https://github.com/andre5Jr/soc-analyst-phising-The-Greenholt-Phish/blob/27c2a666742dc5b0caa6d1cca0dd5ecfbd1174ba/8-2.png)   

![image alt](https://github.com/andre5Jr/soc-analyst-phising-The-Greenholt-Phish/blob/27c2a666742dc5b0caa6d1cca0dd5ecfbd1174ba/9-1.png)   

![image alt](https://github.com/andre5Jr/soc-analyst-phising-The-Greenholt-Phish/blob/27c2a666742dc5b0caa6d1cca0dd5ecfbd1174ba/10-1.png)   

![image alt](https://github.com/andre5Jr/soc-analyst-phising-The-Greenholt-Phish/blob/27c2a666742dc5b0caa6d1cca0dd5ecfbd1174ba/11-1.png)   

![image alt](https://github.com/andre5Jr/soc-analyst-phising-The-Greenholt-Phish/blob/27c2a666742dc5b0caa6d1cca0dd5ecfbd1174ba/11-2.png)   

![image alt](https://github.com/andre5Jr/soc-analyst-phising-The-Greenholt-Phish/blob/27c2a666742dc5b0caa6d1cca0dd5ecfbd1174ba/12-1.png)  


