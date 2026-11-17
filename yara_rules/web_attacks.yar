rule Web_SQL_Injection_Attempt
{
    meta:
        description = "SQL injection patterns in web requests"
        severity = "High"
        mitre = "T1190 Exploit Public-Facing Application"
    strings:
        $s1 = /union(\s|\+|%20)+(all(\s|\+|%20)+)?select/ nocase
        $s2 = "information_schema" nocase
        $s3 = /('|%27)(\s|\+|%20)*or(\s|\+|%20)*('|%27)?1('|%27)?=('|%27)?1/ nocase
        $s4 = /sleep\(\d+\)/ nocase
    condition:
        any of them
}

rule Web_Path_Traversal_Attempt
{
    meta:
        description = "Directory traversal sequences reaching system files"
        severity = "High"
        mitre = "T1190 Exploit Public-Facing Application"
    strings:
        $p1 = /(\.\.\/){3,}/
        $p2 = /(%2e%2e%2f){2,}/ nocase
    condition:
        $p1 or $p2
}

rule Log4Shell_JNDI_Lookup
{
    meta:
        description = "Log4Shell exploitation string"
        severity = "Critical"
        mitre = "T1190 Exploit Public-Facing Application"
    strings:
        $j = /\$\{jndi:(ldap|ldaps|rmi|dns)/ nocase
    condition:
        $j
}

rule Scanner_User_Agents
{
    meta:
        description = "User agents of vulnerability scanners"
        severity = "Low"
        mitre = "T1595 Active Scanning"
    strings:
        $u1 = "sqlmap" nocase
        $u2 = "nikto" nocase
        $u3 = "masscan" nocase
        $u4 = "Nmap Scripting Engine" nocase
        $u5 = "dirbuster" nocase
    condition:
        any of them
}
