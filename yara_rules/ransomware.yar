rule Ransomware_Note_Text
{
    meta:
        description = "Text commonly found in ransom notes"
        severity = "Critical"
        mitre = "T1486 Data Encrypted for Impact"
    strings:
        $a = "your files have been encrypted" nocase
        $b = "all your files are encrypted" nocase
        $c = "bitcoin" nocase
        $d = "decrypt" nocase
        $e = "private key" nocase
    condition:
        ($a or $b) and ($c or $d or $e)
}

rule Backup_Destruction_Commands
{
    meta:
        description = "Commands that delete shadow copies or disable recovery"
        severity = "Critical"
        mitre = "T1490 Inhibit System Recovery"
    strings:
        $v1 = "vssadmin delete shadows" nocase
        $v2 = "vssadmin.exe delete shadows" nocase
        $w1 = "wbadmin delete catalog" nocase
        $b1 = "recoveryenabled no" nocase
        $s1 = "wmic shadowcopy delete" nocase
    condition:
        any of them
}
