rule Webshell_PHP_Generic
{
    meta:
        description = "PHP code that executes input taken from the request"
        severity = "Critical"
        mitre = "T1505.003 Web Shell"
    strings:
        $php = "<?php" nocase
        $e1 = /eval\s*\(\s*(base64_decode|gzinflate|str_rot13)\s*\(/ nocase
        $e2 = /(system|shell_exec|passthru|exec)\s*\(\s*\$_(GET|POST|REQUEST|COOKIE)/ nocase
        $e3 = /assert\s*\(\s*\$_(GET|POST|REQUEST)/ nocase
    condition:
        $php and any of ($e*)
}

rule Webshell_JSP_ASP_Generic
{
    meta:
        description = "JSP/ASP code that runs commands from request parameters"
        severity = "Critical"
        mitre = "T1505.003 Web Shell"
    strings:
        $j1 = "Runtime.getRuntime().exec(" nocase
        $j2 = "request.getParameter(" nocase
        $a1 = "eval(Request" nocase
        $a2 = "WScript.Shell" nocase
        $a3 = "Request.Form" nocase
    condition:
        ($j1 and $j2) or ($a1) or ($a2 and $a3)
}

rule Web_Log_Webshell_Access
{
    meta:
        description = "Web log lines requesting known webshell names or passing shell commands in the URL"
        severity = "High"
        mitre = "T1505.003 Web Shell"
    strings:
        $n1 = /(c99|r57|b374k|wso|china ?chopper)\.(php|asp|aspx|jsp)/ nocase
        $n2 = /shell\.(php|asp|aspx|jsp)\?/ nocase
        $c1 = /[?&](cmd|exec|command)=(whoami|id|ls|dir|cat|wget|curl|powershell)/ nocase
    condition:
        any of them
}
