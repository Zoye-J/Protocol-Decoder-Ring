/* PDR Generated YARA Rules */
/* Generated: 2026-03-19T10:18:11.709830 */
/* Analysis ID: siggen_20260319_101811 */
/* ================================================== */


rule PDR_DNS_Tunneling {
    meta:
        description = "Detects potential DNS tunneling activity"
        author = "PDR"
        date = "2026-03-19"
        severity = "high"
        reference = "internal_analysis_siggen_20260319_101811"
    
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
        reference = "internal_analysis_siggen_20260319_101811"
    
    strings:
        $byte_pattern_0 = {1100eeff00000000}
        $byte_pattern_1 = {1703030a6f0000000000000007cea4f584bf46181726f7de87704f4e50}
        $byte_pattern_2 = {170303047f0000000000000008f4b7a621b6f5bbf133a21750db71ccc6}
        $byte_pattern_3 = {1703030a74000000000000000747377a392b1d7f7f066c761592eeda85}
        $byte_pattern_4 = {170303090a000000000000000865b3f615b80fef5fa3c68c2ef5a43717}
        $byte_pattern_5 = {000b13e5667d4a9b558000000000000b300d06092a864886f70d01010c0500305131}
        $byte_pattern_6 = {0400011a00008ca0011400000000563a77b5a5bf6c4f86ccb06b40fc8f41bcd1bd49}
        $byte_pattern_7 = {1703030a740000000000000001c921ddc7034a6125ce0d7d5b48683af6}
        $byte_pattern_8 = {170303078d0000000000000002c801ab240ee84e1f7777a5d69a2de3f7}
        $byte_pattern_9 = {1703030b520000000000000004cb20cee1880b74ed55e344d40c0ab8f1}
    
    condition:
        any of them
}

