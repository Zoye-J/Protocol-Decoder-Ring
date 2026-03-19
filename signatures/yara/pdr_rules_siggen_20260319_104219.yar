/* PDR Generated YARA Rules */
/* Generated: 2026-03-19T10:42:19.376588 */
/* Analysis ID: siggen_20260319_104219 */
/* ================================================== */


rule PDR_Malicious_Patterns {
    meta:
        description = "Detects known malicious byte sequences"
        author = "PDR"
        date = "2026-03-19"
        severity = "medium"
        reference = "internal_analysis_siggen_20260319_104219"
    
    strings:
        $byte_pattern_0 = {150303001a000000000000000319ca2e48641bef13c0796f09d7c7fed9}
        $byte_pattern_1 = {1703030a6f0000000000000005bd2d7f7d45e8f22763a66a0d23f11997}
        $byte_pattern_2 = {17030306fa0000000000000006bae981414e913ad7aad79c434b8aadc4}
        $byte_pattern_3 = {000b13e5667d4a9b558000000000000b300d06092a864886f70d01010c0500305131}
        $byte_pattern_4 = {0400011a00008ca00114000000004d602b224c46004792f322275bdf09e9898ebdb8}
        $byte_pattern_5 = {1703030a740000000000000001758ed806bf9627bc1e6631ef143caf08}
        $byte_pattern_6 = {17030309e1000000000000000201a7f6ec372f525ba16f0249a7b9d331}
        $byte_pattern_7 = {0400011a00008ca0011400000000563a77b5a5bf6c4f86ccb06b40fc8f414c09440b}
        $byte_pattern_8 = {1703030a740000000000000001cbf703dece6b5683f4bdbd5cfd4e8e35}
        $byte_pattern_9 = {170303080400000000000000023db72d699da232145bf6d0636ec3fdf1}
    
    condition:
        any of them
}

