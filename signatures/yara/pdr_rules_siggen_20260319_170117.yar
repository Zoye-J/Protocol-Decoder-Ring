/* PDR Generated YARA Rules */
/* Generated: 2026-03-19T17:01:17.528014 */
/* Analysis ID: siggen_20260319_170117 */
/* ================================================== */


rule PDR_DNS_Tunneling {
    meta:
        description = "Detects potential DNS tunneling activity"
        author = "PDR"
        date = "2026-03-19"
        severity = "high"
        reference = "internal_analysis_siggen_20260319_170117"
    
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
        date = "2026-03-19"
        severity = "medium"
        reference = "internal_analysis_siggen_20260319_170117"
    
    strings:
        $byte_pattern_0 = {000b13e5667d4a9b558000000000000b300d06092a864886f70d01010c0500305131}
        $byte_pattern_1 = {0400011a00008ca00114000000006606b42bad73e54d9ab3ca8bce9d676616eefabf}
        $byte_pattern_2 = {1703030a6f0000000000000001f3b55b0ecf36fc80a1cef128754d60a3}
        $byte_pattern_3 = {17030309b4000000000000000216f5604ba00de616fb8c55d1c2403701}
        $byte_pattern_4 = {0400011a00008ca0011400000000cc65f68e6d76d44e891fb6b2e63dea633067ba89}
        $byte_pattern_5 = {1703030a740000000000000001344ded232ac75ef664dd6768260464d5}
        $byte_pattern_6 = {17030309d10000000000000002189215319d813aa423ba2242d114bcc3}
        $byte_pattern_7 = {0400011a00008ca0011400000000c2cb156df6c2b642b70a7b0735f2398ee5c9e4e3}
        $byte_pattern_8 = {1703030a74000000000000000106450fe98ea200ac62351f074408a698}
        $byte_pattern_9 = {170303078d0000000000000002303e595ccd9cdd0c8385041e15c28007}
    
    condition:
        any of them
}

