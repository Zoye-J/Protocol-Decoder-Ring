/* PDR Generated YARA Rules */
/* Generated: 2026-03-19T07:46:12.292831 */
/* Analysis ID: siggen_20260319_074612 */
/* ================================================== */


rule PDR_DNS_Tunneling {
    meta:
        description = "Detects potential DNS tunneling activity"
        author = "PDR"
        date = "2026-03-19"
        severity = "high"
        reference = "internal_analysis_siggen_20260319_074612"
    
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
        reference = "internal_analysis_siggen_20260319_074612"
    
    strings:
        $byte_pattern_0 = {1703030a6f0000000000000012cdc40c10d41361793f44b5294daf820a}
        $byte_pattern_1 = {17030304c60000000000000013a5d4cdea629997018d0a7299ca64f469}
        $byte_pattern_2 = {000b13e5667d4a9b558000000000000b300d06092a864886f70d01010c0500305131}
        $byte_pattern_3 = {0400011a00008ca0011400000000e595204d59a59b4c9405828fc96df0adee1ccc50}
        $byte_pattern_4 = {1703030a7400000000000000019958af3790410a999d1e793c3d879401}
        $byte_pattern_5 = {17030308d700000000000000029eb6cc578851b2578548d6a04a26fb3e}
        $byte_pattern_6 = {0400011a00008ca0011400000000e595204d59a59b4c9405828fc96df0add784ada5}
        $byte_pattern_7 = {1703030a7400000000000000015e79ace055cab8204bc1de8a6da3fa32}
        $byte_pattern_8 = {170303078d0000000000000002ac930f80d9747c072840e7ebe0f06397}
        $byte_pattern_9 = {1703030b60000000000000000553217eacd191c523291fff4441e6fe19}
    
    condition:
        any of them
}

