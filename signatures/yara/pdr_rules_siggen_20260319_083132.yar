/* PDR Generated YARA Rules */
/* Generated: 2026-03-19T08:31:32.804424 */
/* Analysis ID: siggen_20260319_083132 */
/* ================================================== */


rule PDR_Malicious_Patterns {
    meta:
        description = "Detects known malicious byte sequences"
        author = "PDR"
        date = "2026-03-19"
        severity = "medium"
        reference = "internal_analysis_siggen_20260319_083132"
    
    strings:
        $byte_pattern_0 = {1703030a6f0000000000000021aadc0dddcfbeb3b04da7b7751982332c}
        $byte_pattern_1 = {17030304c600000000000000221918faee9f169727d05717f98899d0c0}
        $byte_pattern_2 = {000b13e5667d4a9b558000000000000b300d06092a864886f70d01010c0500305131}
        $byte_pattern_3 = {0400011a00008ca0011400000000563a77b5a5bf6c4f86ccb06b40fc8f4174200f55}
        $byte_pattern_4 = {1703030a74000000000000000181a3c677669b1a08a8fb489c40db8db2}
        $byte_pattern_5 = {170303078d00000000000000029cc459a4d4cdd346b8ac280958fc4079}
        $byte_pattern_6 = {1703030b5d000000000000002694b1c6f82f9cc124f2c1c3bd290fc16e}
        $byte_pattern_7 = {1703030a7400000000000000238134bc6d932696feadf79e6d37d0e026}
        $byte_pattern_8 = {17030309d600000000000000248eb79f87fdc6ed33e5e78a9aef8238c9}
        $byte_pattern_9 = {1703030b6800000000000000017879482ec220f688951aa58ed947d146}
    
    condition:
        any of them
}

