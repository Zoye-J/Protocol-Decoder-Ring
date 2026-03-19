/* PDR Generated YARA Rules */
/* Generated: 2026-03-19T10:20:54.003885 */
/* Analysis ID: siggen_20260319_102053 */
/* ================================================== */


rule PDR_DNS_Tunneling {
    meta:
        description = "Detects potential DNS tunneling activity"
        author = "PDR"
        date = "2026-03-19"
        severity = "high"
        reference = "internal_analysis_siggen_20260319_102053"
    
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
        reference = "internal_analysis_siggen_20260319_102053"
    
    strings:
        $byte_pattern_0 = {1703030a6f0000000000000003e9cc0130d2b4c843ad1b79bac56f2eda}
        $byte_pattern_1 = {170303047f00000000000000047b594c1acdf541fe37f9ad629650e53d}
        $byte_pattern_2 = {1703030a74000000000000000315aabb29fae4c9a9b921f602319ef012}
        $byte_pattern_3 = {170303078d0000000000000004596b2a17219e3f7335b4428297a10786}
        $byte_pattern_4 = {1703030b5e0000000000000002a86ece094a97f359c137168b769b7e86}
        $byte_pattern_5 = {170303046b00000000000000055c962dadb09b5a7fdaf1fd1324f20f91}
        $byte_pattern_6 = {17030306b8000000000000000644f025909bfa3afa71dff628578af087}
        $byte_pattern_7 = {1703030a770000000000000007a3b4fd743155d00469001a52ad8036d4}
        $byte_pattern_8 = {17030309d2000000000000000865aa02d50ab4753877b2b08b41f86313}
        $byte_pattern_9 = {1703030b6300000000000000027184f38caf21db31a4defcfb53c76ba2}
    
    condition:
        any of them
}

