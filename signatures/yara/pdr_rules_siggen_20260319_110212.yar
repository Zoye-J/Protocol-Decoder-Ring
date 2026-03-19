/* PDR Generated YARA Rules */
/* Generated: 2026-03-19T11:02:12.653670 */
/* Analysis ID: siggen_20260319_110212 */
/* ================================================== */


rule PDR_DNS_Tunneling {
    meta:
        description = "Detects potential DNS tunneling activity"
        author = "PDR"
        date = "2026-03-19"
        severity = "high"
        reference = "internal_analysis_siggen_20260319_110212"
    
    strings:
        $dns_pattern_0 = "mobile.events.data.microsoft.com." nocase
        $dns_pattern_1 = "mobile.events.data.microsoft.com." nocase
        $dns_pattern_2 = "mobile.events.data.microsoft.com." nocase
        $dns_pattern_3 = "mobile.events.data.microsoft.com." nocase
        $dns_pattern_4 = "tsfe.trafficshaping.dsp.mp.microsoft.com." nocase
    
    condition:
        any of them
}


rule PDR_Malicious_Patterns {
    meta:
        description = "Detects known malicious byte sequences"
        author = "PDR"
        date = "2026-03-19"
        severity = "medium"
        reference = "internal_analysis_siggen_20260319_110212"
    
    strings:
        $byte_pattern_0 = {000d00170000ff0100010000000000140303000101}
        $byte_pattern_1 = {030300010116030300280000000000000000ff98a2af6bf02f57eacb00af96503b4e}
        $byte_pattern_2 = {1703030a720000000000000001317597a46228f5120d8de92f506f9a69}
        $byte_pattern_3 = {17030309b400000000000000022bf1db443734474b8b5c00dd7a49868e}
        $byte_pattern_4 = {000b13e5667d4a9b558000000000000b300d06092a864886f70d01010c0500305131}
        $byte_pattern_5 = {0400011a00008ca0011400000000f41364df58065f4c8a33a6197afb40e155145c77}
        $byte_pattern_6 = {1703030a7700000000000000014585eb433c070e9de841e134226efb83}
        $byte_pattern_7 = {170303078d0000000000000002a8abdc2342a4999599deab74ea01f440}
        $byte_pattern_8 = {1703030b57000000000000000117ec0ca609885225c4c234a2dad5536c}
        $byte_pattern_9 = {1703030a770000000000000003406f0f606518be25caa44ec5d63c6f2d}
    
    condition:
        any of them
}

