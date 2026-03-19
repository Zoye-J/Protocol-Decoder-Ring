/* PDR Generated YARA Rules */
/* Generated: 2026-03-19T10:39:12.622266 */
/* Analysis ID: siggen_20260319_103912 */
/* ================================================== */


rule PDR_DNS_Tunneling {
    meta:
        description = "Detects potential DNS tunneling activity"
        author = "PDR"
        date = "2026-03-19"
        severity = "high"
        reference = "internal_analysis_siggen_20260319_103912"
    
    strings:
        $dns_pattern_0 = "telemetry.individual.githubcopilot.com." nocase
        $dns_pattern_1 = "telemetry.individual.githubcopilot.com." nocase
    
    condition:
        any of them
}


rule PDR_Malicious_Patterns {
    meta:
        description = "Detects known malicious byte sequences"
        author = "PDR"
        date = "2026-03-19"
        severity = "medium"
        reference = "internal_analysis_siggen_20260319_103912"
    
    strings:
        $byte_pattern_0 = {1703030a6f000000000000000bac55aa1962710a10cb3bfe87a6f4da47}
        $byte_pattern_1 = {17030306c1000000000000000c2fcc0c14ad85d2b8ba56e27e0f6d1538}
        $byte_pattern_2 = {000b13e5667d4a9b558000000000000b300d06092a864886f70d01010c0500305131}
        $byte_pattern_3 = {0400011a00008ca0011400000000f41364df58065f4c8a33a6197afb40e128a94f26}
        $byte_pattern_4 = {1703030a74000000000000000146caceb8448d530d07a528766d367cc9}
        $byte_pattern_5 = {170303078d00000000000000027ff6019e6f16194a8e1dc8c460dcd610}
        $byte_pattern_6 = {1703030b660000000000000008d8046ff4846c77837a82b5893f96c4eb}
        $byte_pattern_7 = {1703030b660000000000000001c3d44f0b35ce7b09121dccf16bb8c3a2}
        $byte_pattern_8 = {1703030a8f0000000000000006e74f6677cfc9f3fe5ee0418083829023}
        $byte_pattern_9 = {1703031adb000000000000000607b1317f216edfef5bf9b71fbc5d0862}
    
    condition:
        any of them
}

