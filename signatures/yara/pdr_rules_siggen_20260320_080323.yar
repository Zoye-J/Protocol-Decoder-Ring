/* PDR Generated YARA Rules */
/* Generated: 2026-03-20T08:03:23.959896 */
/* Analysis ID: siggen_20260320_080323 */
/* ================================================== */


rule PDR_DNS_Tunneling {
    meta:
        description = "Detects potential DNS tunneling activity"
        author = "PDR"
        date = "2026-03-20"
        severity = "high"
        reference = "internal_analysis_siggen_20260320_080323"
    
    strings:
        $dns_pattern_0 = "194291-ipv4mte.gr.global.aa-rt.sharepoint.com." nocase
        $dns_pattern_1 = "194291-ipv4mte.gr.global.aa-rt.sharepoint.com." nocase
        $dns_pattern_2 = "194291-ipv4mte.gr.global.aa-rt.sharepoint.com." nocase
        $dns_pattern_3 = "194291-ipv4mte.gr.global.aa-rt.sharepoint.com." nocase
        $dns_pattern_4 = "194291-ipv4fdsmte.gr.global.aa-rt.sharepoint.com." nocase
    
    condition:
        any of them
}


rule PDR_Malicious_Patterns {
    meta:
        description = "Detects known malicious byte sequences"
        author = "PDR"
        date = "2026-03-20"
        severity = "medium"
        reference = "internal_analysis_siggen_20260320_080323"
    
    strings:
        $byte_pattern_0 = {000b13e5667d4a9b558000000000000b300d06092a864886f70d01010c0500305131}
        $byte_pattern_1 = {0400011a00008ca0011400000000b96df6eead749343b0197cea5ef017f5645373c5}
        $byte_pattern_2 = {1703030a740000000000000001432af73c401a9c32098d9fc3e59da492}
        $byte_pattern_3 = {170303078d00000000000000024bf73b86d2fb9b4e84831eb4afec4bf5}
        $byte_pattern_4 = {0400011a00008ca0011400000000b07e5409c6e1cd45aea47f417419d1e5882ca57a}
        $byte_pattern_5 = {0400011a00008ca0011400000000950630d2a09516418d98960b2dcda3769ee73166}
        $byte_pattern_6 = {1703030a740000000000000001fc20100c18bd6b37ddd5e6fd1a6d385a}
        $byte_pattern_7 = {17030309d60000000000000002b8e4fe04be76b447effeab595d81722c}
        $byte_pattern_8 = {1703030a6f000000000000000133b94a8ed633e4ac3514fe11d040c728}
        $byte_pattern_9 = {17030304c60000000000000002b24e4c606d03913abf4b8ad65faf646b}
    
    condition:
        any of them
}

