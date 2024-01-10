# Description of project:

Understanding and analyzing a recent Cyber Security breach. The goal is to find a solution through a tool, protocol/policy, and to discuss vulnerability protection behaviors that can be demonstrated to prevent these attacks.

# The breach of choice:

The type of breach I chose was SQL injection and this breach occurred on a common managed file transfer software product called MOVEit. This product which is produced by Ipswitch, Inc., encrypts files and uses secure File Transfer Protocols to transfer data, as well as providing automation services, analytics and failover options.

# Analysis of breach:

The following information was presented to the public by Progress Software which is the company responsible for finding and patching parts of this recent vulnerability. Although Progress Software is responsible for the mitigation of the breach the Cybersecurity firm Huntress has been credited with discovering and reporting the vulnerabilities as part of a code review recently. Progress Software released patches to address new SQL injection vulnerabilities in the MOVEit Transfer application, which could lead to the theft of sensitive information. The vulnerabilities allow unauthenticated attackers to gain unauthorized access to the MOVEit Transfer database by submitting a crafted payload. The flaws impact all versions of the service, but specific versions of MOVEit Transfer have been patched. The activity has been attributed to the notorious Cl0p ransomware gang, which has a track record of orchestrating data theft campaigns and exploiting zero-day bugs in various managed file transfer platforms since December 2020. Progress Software released the following statement, "It appears that the Clop threat actors had the MOVEit Transfer exploit completed at the time of the GoAnywhere event and chose to execute the attacks sequentially instead of in parallel," the company said. "These findings highlight the significant planning and preparation that likely precede mass exploitation events." They also mentioned that the Cl0p actors have also issued an extortion notice to affected companies, urging them to contact the group by June 14, 2023, or have their stolen information published on the data leak site. This development comes after the previously reported MOVEit Transfer vulnerability (CVE-2023-34362) has come under heavy exploitation to drop web shells on targeted systems, with penetration testing firm Horizon3.ai publishing a proof-of-concept (PoC) exploit for the flaw.

# Vulnerability Assessment:

- Scope and Objective: Clearly define the scope of the vulnerability assessment, including the systems and networks to be assessed. The objective is to identify and assess the vulnerabilities in the MOVEit Transfer software and its associated components.
- Vulnerability Identification: CVE-2023-34362: A webshell named 'human2.aspx' located in the 'C:\MOVEitTransfer\wwwroot' folder is being exploited. This allows unauthorized access and execution of commands on the MOVEit Transfer server. CVE-2023-35708: A SQL injection vulnerability that could result in elevated privileges and unauthorized access to the MOVEit Transfer database.
- Vulnerability Scanning: Perform vulnerability scanning using appropriate tools to identify the presence of the vulnerabilities mentioned above. Scan all affected systems and versions of MOVEit Transfer software.
- Patch Assessment: Verify if the latest patch provided by Progress Software Corporation has been applied to the affected systems. Use the provided link (https://community.progress.com/s/article/MOVEit-Transfer-Critical-Vulnerability-31May2023) to access the patch and ensure its installation.
- Network Configuration Review: Review the firewall rules to ensure that external traffic to ports 80 and 443 is blocked for MOVEit Transfer servers. This will help prevent unauthorized access to the software.
- File and Folder Analysis: Inspect the 'C:\MOVEitTransfer\wwwroot' directory on the MOVEit Transfer server for the presence of the 'human2.aspx' file. Additionally, search for any newly created files in this directory. Delete any instances of the 'human2.aspx' and 'cmdline' script files.
- User Account and Password Review: Reset the passwords for all service accounts associated with the affected systems, including the MOVEit Service Account. Ensure that any unauthorized user profiles are removed.
- Log Analysis: Review the logs for any indications of unauthorized file downloads from unrecognized IP addresses or a large quantity of files downloaded. Look for any suspicious activities related to the vulnerabilities mentioned.
- Indicators of Compromise (IoC) Analysis: Check the provided IoCs (IP addresses, file paths, POST requests, user account names) to identify any potential signs of compromise in the environment. Use appropriate tools and techniques to analyze the logs and system data for the presence of these IoCs.
- Security Patch Management: Establish a process for ongoing security patch management to ensure that future vulnerabilities in the MOVEit Transfer software are addressed promptly. Regularly check for vendor patches and apply them as soon as they become available.
- Reporting: Prepare a detailed report documenting the findings of the vulnerability assessment, including identified vulnerabilities, patch status, recommended remediation steps, and any potential signs of compromise found. Provide clear recommendations for mitigating the identified vulnerabilities and securing the MOVEit Transfer environment.
- Remediation: Implement the recommended remediation steps, including applying the latest patch, updating firewall rules, deleting unauthorized files, resetting passwords, and addressing any other identified issues. Regularly monitor and maintain the security of the MOVEit Transfer environment to prevent future vulnerabilities and ensure ongoing protection.

# SQL Injection Specific Defenses

- Defensive Coding Practices: This involves secure coding techniques to prevent SQL injection attacks. Strategies include:
- Parameterized Queries or Stored Procedures: Replacing dynamic queries with parameterized queries or stored procedures to separate SQL code from user input.
- Escaping: Properly encoding user-supplied parameters to prevent them from being interpreted as SQL code.
- Data Type Validation: Validating user input data types to reject mismatched inputs and ensuring only expected data types are used in queries.
- Whitelist Filtering: Accepting only inputs that match predefined legitimate patterns, effectively filtering out malicious input.
- SQL Injection Attack Detection: Methods to detect vulnerabilities:
- Code-Based Vulnerability Testing: Generating a test suite to identify SQL injection vulnerabilities. Static analysis tools track user inputs and generate reports on attack patterns.
- Concrete Attack Generation: Using symbolic execution to generate test inputs that expose SQL injection vulnerabilities.
- Taint-Based Vulnerability Detection: Applying static analysis techniques to track tainted data and validate input validation and sanitization.
- SQL Injection Attack Prevention: Methods to prevent vulnerabilities:
- Runtime SQL Injection Attack Prevention: Performing runtime checks on queries to prevent unauthorized SQL code execution, but this can impact performance and require code instrumentation.
- Randomization: Introducing randomness in SQL keywords to prevent injection attacks. A proxy filter de-randomizes queries based on a secret key.
- Learning-Based Prevention: Deploying a runtime monitoring system to intercept queries and validate their legitimacy based on intended programming logic.

# Operational Security Measures:

- Incident Response: This category emphasizes the critical role of incident response in maintaining strong operational security. Incident response teams are crucial to swiftly address and mitigate the impact of security incidents. These teams can operate reactively, responding to incidents after detection, or proactively by seeking out vulnerabilities to prevent incidents. They also contribute to employee education on information security matters.
- Employee/User Education and Awareness: The second category focuses on educating and raising awareness among employees and users. While technical countermeasures are important, human behavior and errors are significant contributors to security incidents. Ensuring Information Security Awareness (ISA) among employees is essential to prevent mishandling of sensitive information and reducing data breaches caused by human errors.
- Encryption: Encryption is highlighted in this category as a fundamental technique for operational security. It transforms data into unreadable ciphertext using cryptographic algorithms and keys, ensuring confidentiality and integrity. Encryption is applied for data protection, secure communication, and safeguarding intellectual property. Various frameworks, including those from NIST, advocate the use of encryption to enhance security.
- Software Updates and Patch Management: The final category stresses the importance of regularly updating software and managing patches to address vulnerabilities. This complex process involves identifying, testing, installing, and verifying patches. Organizations often struggle with timely patching due to various challenges, indicating a need for improved patching processes to enhance software security.

# Summary:

The escalating cyber security breaches in today's interconnected digital landscape highlight the urgent need for robust measures to protect organizations from unauthorized access and data compromise. This research delved into the specifics of a SQL injection breach, its impact on the MOVEit managed file transfer software, and short-term solutions through a vulnerability assessment. Furthermore, the study explored SQL injection specific defenses, including defensive coding practices, SQL injection attack detection, and runtime SQL injection attack prevention. Additionally, operational security solutions, such as incident response, employee/user education and awareness, encryption, and regular software updates and patch management, were presented to bolster overall security postures. By understanding, implementing, and combining these comprehensive strategies, organizations can strengthen their defense mechanisms, mitigate the risks of cyber attacks, and safeguard sensitive information from malicious threats.
