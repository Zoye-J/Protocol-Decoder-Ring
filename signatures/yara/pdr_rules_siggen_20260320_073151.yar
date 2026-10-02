/* PDR Generated YARA Rules */
/* Generated: 2026-03-20T07:31:51.692530 */
/* Analysis ID: siggen_20260320_073151 */
/* ================================================== */


rule PDR_DNS_Tunneling {
    meta:
        description = "Detects potential DNS tunneling activity"
        author = "PDR"
        date = "2026-03-20"
        severity = "high"
        reference = "internal_analysis_siggen_20260320_073151"
    
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
        reference = "internal_analysis_siggen_20260320_073151"
    
    strings:
        $byte_pattern_0 = {1100eeff00000000}
        $byte_pattern_1 = {000b13e5667d4a9b558000000000000b300d06092a864886f70d01010c0500305131}
        $byte_pattern_2 = {0400011a00008ca0011400000000b07e5409c6e1cd45aea47f417419d1e5d657abdd}
        $byte_pattern_3 = {1703030a770000000000000001f396ea55cae10320f2de7139f2f0dfc0}
        $byte_pattern_4 = {17030309d6000000000000000268fb9a8b903df74f80fd265ff1ee6919}
        $byte_pattern_5 = {0400011a00008ca0011400000000b07e5409c6e1cd45aea47f417419d1e57c9b865c}
        $byte_pattern_6 = {1703030a7700000000000000011a3fb98e46e1f30cb82ac2f94822365a}
        $byte_pattern_7 = {170303078d0000000000000002104d509dec2224d6790012be590bffd4}
        $byte_pattern_8 = {0400011a00008ca0011400000000b96df6eead749343b0197cea5ef017f5390eed26}
        $byte_pattern_9 = {1703030a6f00000000000000011dd7cf030c508aa13d58b0db3609994b}
    
    condition:
        any of them
}

