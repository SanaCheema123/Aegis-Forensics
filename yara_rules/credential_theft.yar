rule Credential_Dumping_Tools
{
    meta:
        description = "Mimikatz-style commands or LSASS dumping"
        severity = "Critical"
        mitre = "T1003 OS Credential Dumping"
    strings:
        $m1 = "sekurlsa::logonpasswords" nocase
        $m2 = "lsadump::sam" nocase
        $m3 = "mimikatz" nocase
        $p1 = "procdump" nocase
        $p2 = "lsass" nocase
        $c1 = "comsvcs.dll" nocase
        $c2 = "MiniDump" nocase
    condition:
        any of ($m*) or ($p1 and $p2) or ($c1 and $c2)
}

rule Auth_Log_Brute_Force_Tools
{
    meta:
        description = "Names of password-guessing tools in logs or user agents"
        severity = "Medium"
        mitre = "T1110 Brute Force"
    strings:
        $t1 = "hydra" nocase
        $t2 = "medusa" nocase
        $t3 = "ncrack" nocase
        $t4 = "crackmapexec" nocase
        $t5 = "patator" nocase
    condition:
        any of them
}
