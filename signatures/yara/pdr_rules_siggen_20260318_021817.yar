/* PDR Generated YARA Rules */
/* Generated: 2026-03-18T02:18:17.396079 */
/* Analysis ID: siggen_20260318_021817 */
/* ================================================== */


rule PDR_DNS_Tunneling {
    meta:
        description = "Detects potential DNS tunneling activity"
        author = "PDR"
        date = "2026-03-18"
        severity = "high"
        reference = "internal_analysis_siggen_20260318_021817"
    
    strings:
        $dns_pattern_0 = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.evil.com" nocase
    
    condition:
        any of them
}


rule PDR_C2_Servers {
    meta:
        description = "Detects communication with known C2 servers"
        author = "PDR"
        date = "2026-03-18"
        severity = "high"
        reference = "internal_analysis_siggen_20260318_021817"
    
    strings:
        $c2_ip_0 = "45.33.22.11" ascii
        $c2_ip_1 = "45.33.22.11" ascii
    
    condition:
        any of them
}

