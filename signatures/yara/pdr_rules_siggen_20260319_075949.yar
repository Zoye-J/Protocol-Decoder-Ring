/* PDR Generated YARA Rules */
/* Generated: 2026-03-19T07:59:49.264929 */
/* Analysis ID: siggen_20260319_075949 */
/* ================================================== */


rule PDR_DNS_Tunneling {
    meta:
        description = "Detects potential DNS tunneling activity"
        author = "PDR"
        date = "2026-03-19"
        severity = "high"
        reference = "internal_analysis_siggen_20260319_075949"
    
    strings:
        $dns_pattern_0 = "mobile.events.data.microsoft.com." nocase
        $dns_pattern_1 = "mobile.events.data.microsoft.com." nocase
        $dns_pattern_2 = "mobile.events.data.microsoft.com." nocase
        $dns_pattern_3 = "mobile.events.data.microsoft.com." nocase
    
    condition:
        any of them
}


rule PDR_Malicious_Patterns {
    meta:
        description = "Detects known malicious byte sequences"
        author = "PDR"
        date = "2026-03-19"
        severity = "medium"
        reference = "internal_analysis_siggen_20260319_075949"
    
    strings:
        $byte_pattern_0 = {1703030a6f000000000000000793eea51f25048ec16c54162820b3ef97}
        $byte_pattern_1 = {17030304c60000000000000008439a1a3a214b4ec95b05aba94a774a3a}
        $byte_pattern_2 = {000b13e5667d4a9b558000000000000b300d06092a864886f70d01010c0500305131}
        $byte_pattern_3 = {0400011a00008ca00114000000005c40ed903e2db9439ebdc7d2c71e8ce2806b5b11}
        $byte_pattern_4 = {1703030a740000000000000001ed7eff2755d2c3e09c6744c3a3aba334}
        $byte_pattern_5 = {17030308d60000000000000002814447ddbc2c79bdde4b62ab7d99644e}
        $byte_pattern_6 = {0400011a00008ca00114000000005c40ed903e2db9439ebdc7d2c71e8ce2f009edf0}
        $byte_pattern_7 = {1703030a7400000000000000011004eec7cafc88ff356b1cd5d858d246}
        $byte_pattern_8 = {170303078d0000000000000002437282fb0da854d8d0be03160df77c23}
        $byte_pattern_9 = {1703030b5b000000000000000429b0f41c9f54bf5d9376529d8a66cd76}
    
    condition:
        any of them
}

