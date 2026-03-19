/* PDR Generated YARA Rules */
/* Generated: 2026-03-19T10:46:46.200432 */
/* Analysis ID: siggen_20260319_104646 */
/* ================================================== */


rule PDR_DNS_Tunneling {
    meta:
        description = "Detects potential DNS tunneling activity"
        author = "PDR"
        date = "2026-03-19"
        severity = "high"
        reference = "internal_analysis_siggen_20260319_104646"
    
    strings:
        $dns_pattern_0 = "api.individual.githubcopilot.com." nocase
        $dns_pattern_1 = "api.individual.githubcopilot.com." nocase
        $dns_pattern_2 = "api.individual.githubcopilot.com." nocase
        $dns_pattern_3 = "api.individual.githubcopilot.com." nocase
    
    condition:
        any of them
}


rule PDR_Malicious_Patterns {
    meta:
        description = "Detects known malicious byte sequences"
        author = "PDR"
        date = "2026-03-19"
        severity = "medium"
        reference = "internal_analysis_siggen_20260319_104646"
    
    strings:
        $byte_pattern_0 = {1703030a720000000000000008d47ac88ad512a7cc04f6a9096d83a594}
        $byte_pattern_1 = {1703031ca30000000000000009372ce34fbecb00e1a795a0b08e20d6b8}
        $byte_pattern_2 = {1703030a7700000000000000098bb321668fbd90c1df274a7df560257b}
        $byte_pattern_3 = {170303078d000000000000000ac9474a6e5bbc01280f59b55420ae5cb7}
        $byte_pattern_4 = {1703030b690000000000000005b0606dc3efe54f317f185b5bce46390e}
        $byte_pattern_5 = {1703030a770000000000000008dd6c72f48d82614c8bb2dc962c88256c}
        $byte_pattern_6 = {17030309e100000000000000090734bba52a68426673145d637f1a5735}
        $byte_pattern_7 = {1703030b6c0000000000000005fed30da88cb9c8847bf27a9b8c53f4f2}
        $byte_pattern_8 = {1703030b620000000000000004c34a47ccf95fa538be4330c5a86500a8}
        $byte_pattern_9 = {170303046b000000000000000958da7835dbd851852c55df7c41eadac8}
    
    condition:
        any of them
}

