/* PDR Generated YARA Rules */
/* Generated: 2026-03-21T02:11:14.482036 */
/* Analysis ID: siggen_20260321_021114 */
/* ================================================== */


rule PDR_DNS_Tunneling {
    meta:
        description = "Detects potential DNS tunneling activity"
        author = "PDR"
        date = "2026-03-21"
        severity = "high"
        reference = "internal_analysis_siggen_20260321_021114"
    
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
        date = "2026-03-21"
        severity = "medium"
        reference = "internal_analysis_siggen_20260321_021114"
    
    strings:
        $byte_pattern_0 = {000b13e5667d4a9b558000000000000b300d06092a864886f70d01010c0500305131}
        $byte_pattern_1 = {0400011a00008ca0011400000000ccce7be56f749b419e3383d07925a704357c825e}
        $byte_pattern_2 = {1703030a6f00000000000000017ade65b159f9ac7225686c761be761dc}
        $byte_pattern_3 = {17030304c600000000000000027017b295e63922d3c6f5d6d566ed3806}
        $byte_pattern_4 = {0400011a00008ca00114000000000c935c1ab3694444b80b4329ef17a113653eedf0}
        $byte_pattern_5 = {0400011a00008ca0011400000000fb9ae078c27bd74a9f1a234f071b7232b64d0e24}
        $byte_pattern_6 = {1703030a740000000000000001d1d6d62f1055596d1abb18f9cc5bdc9e}
        $byte_pattern_7 = {170303078d0000000000000002ab093c94108eaf84fb03dea77bfdeae2}
        $byte_pattern_8 = {1703030a740000000000000001aeb67908e6cbff561422e6195cdbe437}
        $byte_pattern_9 = {17030309d60000000000000002c1440894fd9a9c61483333019ff63fed}
    
    condition:
        any of them
}

