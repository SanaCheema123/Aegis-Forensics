rule Aegis_Harmless_Test_Marker
{
    meta:
        description = "Harmless marker for validating YARA alert flow"
        severity = "Low"
    strings:
        $marker = "AEGIS_YARA_TEST_MARKER_2026"
    condition:
        $marker
}
