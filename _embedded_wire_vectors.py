"""Upstream wire-format-v1 values embedded in the test suite.

Reference list for scripts/check_wire_vectors.py. Keys are dotted paths into
flop-labs/yellowpaper evidence/wire-format-v1.json (list items addressed by
their "id" or "version", or by index); each value is (hex as embedded in the
tests, test file that embeds it). The tests do not import this module;
test_wire_vectors_source.py checks that every value still appears verbatim in
its test file.
"""

EMBEDDED_WIRE_VECTORS = {
    # test_task_hash.py::test_task_hash_v1_matches_canonical_wire_vector
    "direct_rail_v1.task_hash.hash_hex": (
        "8d06cbf826718cda29c2ec2aa363ea13cebc118947eed5fa5d4dbb364357920d",
        "test_task_hash.py",
    ),
    # test_task_hash.py::test_report_data_matches_canonical_wire_format_v1_vector
    "direct_rail_v1.report_data_hex": (
        (
            "3165c6d38fbf992485c8c8640476f9a7a5db94523a32387e838d205d178bfff7"
            "0000000000000000000000000000000000000000000000000000000000000000"
        ),
        "test_task_hash.py",
    ),
    # test_validator_api.py::test_decode_policy_v1_matches_public_canonical_vector
    "decode_policy_v1.sha256_hex": (
        "be572af01bd68df9c660da094b7796244dd29435d532c63c9f42efe6bdabd796",
        "test_validator_api.py",
    ),
    # test_validator_api.py::test_decode_policy_v1_matches_public_canonical_vector
    "decode_policy_v1.scale_bytes_hex": (
        (
            "0100000000000000000000000000000000000000000000000000000000000000"
            "0000000000000040420f000000000040420f0001000000000000000000000000"
            "0000000000000000000000000000000000000000000000000000000000000000"
            "000000000000000000000000000000000000000000000000000000000000"
        ),
        "test_validator_api.py",
    ),
    # test_task_hash.py::test_compute_channel_id_v1_matches_public_canonical_vector
    "compute_channel_v1.channel_id.hash_hex": (
        "3655fa5a95712c31f0bd2380aa8193b30c78bd955e4e966abb0d9f49d66e8d28",
        "test_task_hash.py",
    ),
    # test_compute_channel.py::_canonical_v3_turn_proof_kwargs
    "compute_channel_v1.leaf_inputs.h_ids_hex": (
        "368e6eca01b76a510619dc2778d46860a9070c4a6ad73ef52e81c31dab5a404f",
        "test_compute_channel.py",
    ),
    # test_task_hash.py::test_verified_turn_leaf_versions_match_public_canonical_vectors
    "compute_channel_v1.leaf_versions.V0.hash_hex": (
        "c94322dcec243f39ac92af04248f643ca2978f138c1f9bb4bb2d2720ee8f5ad9",
        "test_task_hash.py",
    ),
    # test_task_hash.py::test_verified_turn_leaf_versions_match_public_canonical_vectors
    "compute_channel_v1.leaf_versions.V1.hash_hex": (
        "218d9062a948e52066456ecb38cc28517423f427a925d1f57c2cd17cc60f1b97",
        "test_task_hash.py",
    ),
    # test_task_hash.py::test_verified_turn_leaf_versions_match_public_canonical_vectors
    "compute_channel_v1.leaf_versions.V2.hash_hex": (
        "4a3632de6913f0502c6313499b29d0976b085a4612e14e017c5eaf065b1c6c2d",
        "test_task_hash.py",
    ),
    # test_task_hash.py::test_verified_turn_leaf_versions_match_public_canonical_vectors
    "compute_channel_v1.leaf_versions.V3.hash_hex": (
        "8ca5d489cec0a255a48a2e3c2149d8028597e03ea78628d9a3672ddb80df2869",
        "test_task_hash.py",
    ),
    # test_task_hash.py::test_compute_channel_merkle_root_matches_public_canonical_vector
    "compute_channel_v1.merkle.root_hex": (
        "1020281304e2677e48c1093e7f5069fc8fbff1ea82daf2ac5b2b49d7cef756ed",
        "test_task_hash.py",
    ),
    # test_compute_channel.py::_canonical_v3_turn_proof_kwargs
    "compute_channel_v1.merkle.path_for_index_2.0.sibling_hex": (
        "8ca5d489cec0a255a48a2e3c2149d8028597e03ea78628d9a3672ddb80df2869",
        "test_compute_channel.py",
    ),
    # test_compute_channel.py::_canonical_v3_turn_proof_kwargs
    "compute_channel_v1.merkle.path_for_index_2.1.sibling_hex": (
        "482735fe0838313af87270c7fa678a8fb6c3cf9d9e3af35b8c73ea39f279a92a",
        "test_compute_channel.py",
    ),
    # test_compute_channel.py::test_verify_turn_proof_wrong_path_orientation_matches_negative_vector
    "compute_channel_v1.v3_leaf_signature.public_key_hex": (
        "207b3ee770b7213b7e76bdb32702e2e166a8fea8a125613d6e98c765f5a06d40",
        "test_compute_channel.py",
    ),
    # test_compute_channel.py::RECEIPT_PUBLIC_KEY
    "compute_channel_v1.receipt.public_key_hex": (
        "b41236c517514b30a4d6619f4b4354a2ce593cd4b64a7c29dd45e3de6972997a",
        "test_compute_channel.py",
    ),
    # test_compute_channel.py::RECEIPT_V1_SIGNATURE_HEX
    "compute_channel_v1.receipt.signature_hex": (
        (
            "7803f98d0297c23f5df90f4bce093492de9658045d3d2296717a1e718e8bc40d"
            "891e60e517fdc459f59140b289d9fcba90809493875b5d8e77325b0ec9572683"
        ),
        "test_compute_channel.py",
    ),
    # test_task_hash.py::DIRECT_RAIL_SIGNABLE_HEX
    "direct_rail_v1.validator_attestation_signable_hex": (
        (
            "8d06cbf826718cda29c2ec2aa363ea13cebc118947eed5fa5d4dbb364357920d"
            "2a00000000000000f40100000000000002020202020202020202020202020202"
            "0202020202020202020202020202020203030303030303030303030303030303"
            "03030303030303030303030303030303be572af01bd68df9c660da094b779624"
            "4dd29435d532c63c9f42efe6bdabd79600010104040404040404040404040404"
            "04040404040404040404040404040404040404"
        ),
        "test_task_hash.py",
    ),
    # test_task_hash.py::DIRECT_RAIL_VALIDATOR_ID_HEX
    "direct_rail_v1.validator_id_hex": (
        "28cc07a97ff218ae057724f5d860f1ac5bcb9a1e907d141b2d6c06116a7ecf5c",
        "test_task_hash.py",
    ),
    # test_task_hash.py::DIRECT_RAIL_VALIDATOR_SIGNATURE_HEX
    "direct_rail_v1.validator_signature_hex": (
        (
            "729d579cd385954df683730ce83bc81f18c30838d434b890ef05efb29b3ebf42"
            "1a93d4e01f57e0ecb4036b23b55c2c5b23bd84eaa912fbd724ceb3dde8533682"
        ),
        "test_task_hash.py",
    ),
    # test_task_hash.py::DIRECT_RAIL_SCALE_HEX
    "direct_rail_v1.validator_attestation_scale_hex": (
        (
            "8d06cbf826718cda29c2ec2aa363ea13cebc118947eed5fa5d4dbb364357920d"
            "2a00000000000000f40100000000000002020202020202020202020202020202"
            "0202020202020202020202020202020203030303030303030303030303030303"
            "03030303030303030303030303030303be572af01bd68df9c660da094b779624"
            "4dd29435d532c63c9f42efe6bdabd79600010104040404040404040404040404"
            "0404040404040404040404040404040404040428cc07a97ff218ae057724f5d8"
            "60f1ac5bcb9a1e907d141b2d6c06116a7ecf5c729d579cd385954df683730ce8"
            "3bc81f18c30838d434b890ef05efb29b3ebf421a93d4e01f57e0ecb4036b23b5"
            "5c2c5b23bd84eaa912fbd724ceb3dde8533682"
        ),
        "test_task_hash.py",
    ),
    # test_task_hash.py::test_compute_channel_id_v1_wrong_genesis_network_matches_negative_vector
    "negative_cases.wrong_genesis_network.bytes_hex": (
        "f7b859ec27672aa1bbe6dfc0b4c0fbeddf50dddc2d107a73a7dab0b5435e758b",
        "test_task_hash.py",
    ),
    # test_task_hash.py::test_compute_channel_id_v1_wrong_session_matches_negative_vector
    "negative_cases.wrong_session.bytes_hex": (
        "1dbc63e202e92143b6d8299f7da687b2a9d08d9554a1a8a3e9c3b0ce88247180",
        "test_task_hash.py",
    ),
    # test_compute_channel.py::test_verify_receipt_rejects_wrong_agent_signature
    "negative_cases.invalid_receipt_signature.bytes_hex": (
        (
            "7903f98d0297c23f5df90f4bce093492de9658045d3d2296717a1e718e8bc40d"
            "891e60e517fdc459f59140b289d9fcba90809493875b5d8e77325b0ec9572683"
        ),
        "test_compute_channel.py",
    ),
    # test_task_hash.py::INVALID_VALIDATOR_SIGNATURE_HEX
    "negative_cases.invalid_validator_signature.bytes_hex": (
        (
            "739d579cd385954df683730ce83bc81f18c30838d434b890ef05efb29b3ebf42"
            "1a93d4e01f57e0ecb4036b23b55c2c5b23bd84eaa912fbd724ceb3dde8533682"
        ),
        "test_task_hash.py",
    ),
    # test_compute_channel.py::LEGACY_LEAF_CURRENT_CHANNEL_HEX
    "negative_cases.legacy_leaf_current_channel.bytes_hex": (
        (
            "01ffffffff333333333333333333333333333333333333333333333333333333"
            "3333333333444444444444444444444444444444444444444444444444444444"
            "4444444444ffffffffffffffffffffffffffffffff0000000000000000000000"
            "0000000000000000000000000000000000000000000000000000000000000000"
            "0000000000000000000000000000000000000000000000000000000000000000"
            "000000000000000000000000000000000000000000fdfffffffffffffffeffff"
            "ffffffffff01000000000000001454f6cf53b85cd7a0665ef54785cb037bb046"
            "4270b42fc0760ba28482eee44eaa482284b51d7e23558bf5e844eca10b3c2b62"
            "f95504fccf2c4d57e86b910180084a3632de6913f0502c6313499b29d0976b08"
            "5a4612e14e017c5eaf065b1c6c2d005f0ff24a5b34ae51d68c9e76052c5aabc0"
            "b6715d0cf78b18383d56da2a6ff85200"
        ),
        "test_compute_channel.py",
    ),
    # test_compute_channel.py::WRONG_PATH_ORIENTATION_HEX
    "negative_cases.wrong_path_orientation.bytes_hex": (
        (
            "03ffffffff333333333333333333333333333333333333333333333333333333"
            "3333333333444444444444444444444444444444444444444444444444444444"
            "4444444444ffffffffffffffffffffffffffffffff6666666666666666666666"
            "666666666666666666666666666666666666666666368e6eca01b76a510619dc"
            "2778d46860a9070c4a6ad73ef52e81c31dab5a404f7777777777777777777777"
            "777777777777777777777777777777777777777777fdfffffffffffffffeffff"
            "ffffffffff01000000000000002e60e88466a203e1c106a6dfca39276cf97556"
            "c3af971f48c4da8845cc23e068cbbcaf63aa20672cd21a6f64b9513d086f2ade"
            "15c90979e870fc2162c07d2f8d088ca5d489cec0a255a48a2e3c2149d8028597"
            "e03ea78628d9a3672ddb80df286900482735fe0838313af87270c7fa678a8fb6"
            "c3cf9d9e3af35b8c73ea39f279a92a00"
        ),
        "test_compute_channel.py",
    ),
    # test_compute_channel.py::LEGACY_RECEIPT_CURRENT_CHANNEL_HEX
    "negative_cases.legacy_receipt_current_channel.bytes_hex": (
        (
            "1111111111111111111111111111111111111111111111111111111111111111"
            "2222222222222222222222222222222222222222222222222222222222222222"
            "2a000000000000000000000000000000e8030000000000000000000000000000"
            "a0f54ce7f97e6e8e76a4ddf6b8785ec5efd243b4a335b7954504a5c19faee620"
            "e881741ae3cfbb56cd503d17e91cd5406ffc1a8d7478108854cd781aade52687"
        ),
        "test_compute_channel.py",
    ),
    # test_compute_channel.py::_canonical_v3_turn_proof_kwargs
    "compute_channel_v1.v3_leaf_signature.signature_hex": (
        (
            "2e60e88466a203e1c106a6dfca39276cf97556c3af971f48c4da8845cc23e068"
            "cbbcaf63aa20672cd21a6f64b9513d086f2ade15c90979e870fc2162c07d2f8d"
        ),
        "test_compute_channel.py",
    ),
    # test_compute_channel.py::_canonical_fcc4_blob
    "compute_channel_v1.fcc4_transcript_blob_hex": (
        (
            "464343343655fa5a95712c31f0bd2380aa8193b30c78bd955e4e966abb0d9f49"
            "d66e8d280100000003ffffffff33333333333333333333333333333333333333"
            "3333333333333333333333333344444444444444444444444444444444444444"
            "44444444444444444444444444ffffffffffffffffffffffffffffffff016666"
            "666666666666666666666666666666666666666666666666666666666666368e"
            "6eca01b76a510619dc2778d46860a9070c4a6ad73ef52e81c31dab5a404f7777"
            "777777777777777777777777777777777777777777777777777777777777fdff"
            "fffffffffffffeffffffffffffff01000000000000002e60e88466a203e1c106"
            "a6dfca39276cf97556c3af971f48c4da8845cc23e068cbbcaf63aa20672cd21a"
            "6f64b9513d086f2ade15c90979e870fc2162c07d2f8d00"
        ),
        "test_compute_channel.py",
    ),
    # test_compute_channel.py::VERIFIED_TURN_V3_SCALE_HEX
    "compute_channel_v1.verified_turn_v3_scale_hex": (
        (
            "03ffffffff333333333333333333333333333333333333333333333333333333"
            "3333333333444444444444444444444444444444444444444444444444444444"
            "4444444444ffffffffffffffffffffffffffffffff6666666666666666666666"
            "666666666666666666666666666666666666666666368e6eca01b76a510619dc"
            "2778d46860a9070c4a6ad73ef52e81c31dab5a404f7777777777777777777777"
            "777777777777777777777777777777777777777777fdfffffffffffffffeffff"
            "ffffffffff01000000000000002e60e88466a203e1c106a6dfca39276cf97556"
            "c3af971f48c4da8845cc23e068cbbcaf63aa20672cd21a6f64b9513d086f2ade"
            "15c90979e870fc2162c07d2f8d088ca5d489cec0a255a48a2e3c2149d8028597"
            "e03ea78628d9a3672ddb80df286900482735fe0838313af87270c7fa678a8fb6"
            "c3cf9d9e3af35b8c73ea39f279a92a01"
        ),
        "test_compute_channel.py",
    ),
    # test_compute_channel.py::ACK_PREIMAGE_HEX
    "compute_channel_v1.fcc4_transcript_with_ack.ack_preimage_hex": (
        (
            "3655fa5a95712c31f0bd2380aa8193b30c78bd955e4e966abb0d9f49d66e8d28"
            "ffffffff8ca5d489cec0a255a48a2e3c2149d8028597e03ea78628d9a3672ddb"
            "80df2869fbffffffffffffffffffffffffffffff"
        ),
        "test_compute_channel.py",
    ),
    # test_compute_channel.py::ACK_AGENT_SIGNATURE_HEX
    "compute_channel_v1.fcc4_transcript_with_ack.agent_signature_hex": (
        (
            "4241d4420396f9478f3d9a7f302360665c56499d33b40f00866c6124faaa420d"
            "3ad22f9670c010c7b4008f489cfd017b28dcb931d9ceb3c9eb16ce32a806d88a"
        ),
        "test_compute_channel.py",
    ),
    # test_compute_channel.py::FCC4_TRANSCRIPT_WITH_ACK_HEX
    "compute_channel_v1.fcc4_transcript_with_ack.blob_hex": (
        (
            "464343343655fa5a95712c31f0bd2380aa8193b30c78bd955e4e966abb0d9f49"
            "d66e8d280100000003ffffffff33333333333333333333333333333333333333"
            "3333333333333333333333333344444444444444444444444444444444444444"
            "44444444444444444444444444ffffffffffffffffffffffffffffffff016666"
            "666666666666666666666666666666666666666666666666666666666666368e"
            "6eca01b76a510619dc2778d46860a9070c4a6ad73ef52e81c31dab5a404f7777"
            "777777777777777777777777777777777777777777777777777777777777fdff"
            "fffffffffffffeffffffffffffff01000000000000002e60e88466a203e1c106"
            "a6dfca39276cf97556c3af971f48c4da8845cc23e068cbbcaf63aa20672cd21a"
            "6f64b9513d086f2ade15c90979e870fc2162c07d2f8d01fbffffffffffffffff"
            "ffffffffffffff4241d4420396f9478f3d9a7f302360665c56499d33b40f0086"
            "6c6124faaa420d3ad22f9670c010c7b4008f489cfd017b28dcb931d9ceb3c9eb"
            "16ce32a806d88a"
        ),
        "test_compute_channel.py",
    ),
    # test_compute_channel.py::INVALID_AGENT_ACK_SIGNATURE_HEX
    "negative_cases.invalid_agent_ack_signature.bytes_hex": (
        (
            "464343343655fa5a95712c31f0bd2380aa8193b30c78bd955e4e966abb0d9f49"
            "d66e8d280100000003ffffffff33333333333333333333333333333333333333"
            "3333333333333333333333333344444444444444444444444444444444444444"
            "44444444444444444444444444ffffffffffffffffffffffffffffffff016666"
            "666666666666666666666666666666666666666666666666666666666666368e"
            "6eca01b76a510619dc2778d46860a9070c4a6ad73ef52e81c31dab5a404f7777"
            "777777777777777777777777777777777777777777777777777777777777fdff"
            "fffffffffffffeffffffffffffff01000000000000002e60e88466a203e1c106"
            "a6dfca39276cf97556c3af971f48c4da8845cc23e068cbbcaf63aa20672cd21a"
            "6f64b9513d086f2ade15c90979e870fc2162c07d2f8d01fbffffffffffffffff"
            "ffffffffffffff4341d4420396f9478f3d9a7f302360665c56499d33b40f0086"
            "6c6124faaa420d3ad22f9670c010c7b4008f489cfd017b28dcb931d9ceb3c9eb"
            "16ce32a806d88a"
        ),
        "test_compute_channel.py",
    ),
}

# Values that intentionally differ from the pinned upstream commit.
KNOWN_DIVERGENCES = {}
