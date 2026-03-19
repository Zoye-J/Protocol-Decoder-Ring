/* PDR Generated YARA Rules */
/* Generated: 2026-03-19T10:45:42.595593 */
/* Analysis ID: siggen_20260319_104542 */
/* ================================================== */


rule PDR_DNS_Tunneling {
    meta:
        description = "Detects potential DNS tunneling activity"
        author = "PDR"
        date = "2026-03-19"
        severity = "high"
        reference = "internal_analysis_siggen_20260319_104542"
    
    strings:
        $dns_pattern_0 = "mobile.events.data.microsoft.com." nocase
        $dns_pattern_1 = "mobile.events.data.microsoft.com." nocase
    
    condition:
        any of them
}


rule PDR_Malicious_Patterns {
    meta:
        description = "Detects known malicious byte sequences"
        author = "PDR"
        date = "2026-03-19"
        severity = "medium"
        reference = "internal_analysis_siggen_20260319_104542"
    
    strings:
        $byte_pattern_0 = {0303000101160303002800000000000000008ef78ead5486afc9022c8491e853934d}
        $byte_pattern_1 = {170303046b0000000000000001d7df1b9ae36f896964c2ee00aef6a5fa}
        $byte_pattern_2 = {1703030a170000000000000002ebc750e7f1f839a05931696764de5aba}
        $byte_pattern_3 = {17030301c00000000000000001b41b955d28d1da46dd84f38bbd99266c}
        $byte_pattern_4 = {170303046b0000000000000003d8bd62fcb5cab4be2e2868ac67f3f632}
        $byte_pattern_5 = {170303060d00000000000000043e6af6fd482d08bf837710ab50f68576}
        $byte_pattern_6 = {1703030a6f0000000000000005985e495c535166ebb7d9c6536f3f5f7b}
        $byte_pattern_7 = {1703031ca300000000000000060a0506426c0b3800874a75b12063a8e9}
        $byte_pattern_8 = {000b13e5667d4a9b558000000000000b300d06092a864886f70d01010c0500305131}
        $byte_pattern_9 = {0400011a00008ca0011400000000563a77b5a5bf6c4f86ccb06b40fc8f41ed4c5bf9}
    
    condition:
        any of them
}

