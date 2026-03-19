/* PDR Generated YARA Rules */
/* Generated: 2026-03-19T10:25:38.435788 */
/* Analysis ID: siggen_20260319_102538 */
/* ================================================== */


rule PDR_DNS_Tunneling {
    meta:
        description = "Detects potential DNS tunneling activity"
        author = "PDR"
        date = "2026-03-19"
        severity = "high"
        reference = "internal_analysis_siggen_20260319_102538"
    
    strings:
        $dns_pattern_0 = "mobile.events.data.microsoft.com." nocase
        $dns_pattern_1 = "mobile.events.data.microsoft.com." nocase
        $dns_pattern_2 = "mobile.events.data.microsoft.com." nocase
        $dns_pattern_3 = "mobile.events.data.microsoft.com." nocase
        $dns_pattern_4 = "mobile.events.data.microsoft.com." nocase
    
    condition:
        any of them
}


rule PDR_Malicious_Patterns {
    meta:
        description = "Detects known malicious byte sequences"
        author = "PDR"
        date = "2026-03-19"
        severity = "medium"
        reference = "internal_analysis_siggen_20260319_102538"
    
    strings:
        $byte_pattern_0 = {1703030a6f000000000000000599df8d5f28ed7a8d38fe119eb309667b}
        $byte_pattern_1 = {1703030f5700000000000000061807f476e2b90de3ad8976e3fd5f0df4}
        $byte_pattern_2 = {000b13e5667d4a9b558000000000000b300d06092a864886f70d01010c0500305131}
        $byte_pattern_3 = {0400011a00008ca0011400000000f41364df58065f4c8a33a6197afb40e1b162f9d2}
        $byte_pattern_4 = {1703030a7400000000000000017f5b5712f4f3576d0ee3c8cef6d4fce7}
        $byte_pattern_5 = {17030309d300000000000000022bbfa07193303a5c12be5cf7ad1e3c55}
        $byte_pattern_6 = {0400011a00008ca0011400000000f41364df58065f4c8a33a6197afb40e1dbb69bc7}
        $byte_pattern_7 = {1703030a740000000000000001043f5991f2c35d3d0d687790c76c6925}
        $byte_pattern_8 = {170303078d00000000000000024f0afb6061dfce7cc6e6eb1ac330b7cf}
        $byte_pattern_9 = {1703030b5900000000000000032c4fef13d339362408cc2a63a37c0bc4}
    
    condition:
        any of them
}

