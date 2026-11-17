rule Suspicious_PowerShell_Download_Exec
{
    meta:
        description = "PowerShell downloading and executing remote content"
        severity = "High"
        mitre = "T1059.001 PowerShell"
    strings:
        $ps = "powershell" nocase
        $d1 = "DownloadString" nocase
        $d2 = "DownloadFile" nocase
        $d3 = "Invoke-WebRequest" nocase
        $x1 = "IEX" nocase
        $x2 = "Invoke-Expression" nocase
    condition:
        $ps and (1 of ($d*)) and (1 of ($x*))
}

rule Suspicious_PowerShell_Encoded_Command
{
    meta:
        description = "PowerShell started with an encoded command or hidden window"
        severity = "High"
        mitre = "T1027 Obfuscated Files or Information"
    strings:
        $ps = "powershell" nocase
        $enc = /\s-e(nc|ncodedcommand)?\s+[A-Za-z0-9+\/=]{20,}/ nocase
        $hid = /-w(indowstyle)?\s+hidden/ nocase
        $nop = /-nop(rofile)?\s/ nocase
        $b64 = "FromBase64String" nocase
    condition:
        $ps and ($enc or $b64 or ($hid and $nop))
}

rule Reverse_Shell_Commands
{
    meta:
        description = "Command lines typical of reverse shells"
        severity = "Critical"
        mitre = "T1059 Command and Scripting Interpreter"
    strings:
        $r1 = "bash -i >& /dev/tcp/" nocase
        $r2 = /nc(\.exe)?\s+(-e|-c)\s+(\/bin\/(ba)?sh|cmd)/ nocase
        $r3 = "import socket,subprocess,os" nocase
        $r4 = "socket.socket(socket.AF_INET" nocase
        $r5 = "/bin/sh -i" nocase
    condition:
        any of ($r1, $r2, $r3, $r5) or ($r4 and $r5)
}

rule LOLBin_Remote_Fetch
{
    meta:
        description = "Windows built-in tools used to fetch or run remote payloads"
        severity = "Medium"
        mitre = "T1218 System Binary Proxy Execution"
    strings:
        $c1 = /certutil(\.exe)?\s+.*-urlcache/ nocase
        $c2 = /bitsadmin(\.exe)?\s+.*\/transfer/ nocase
        $c3 = /mshta(\.exe)?\s+https?:/ nocase
        $c4 = /regsvr32(\.exe)?\s+.*\/i:https?:/ nocase
    condition:
        any of them
}
