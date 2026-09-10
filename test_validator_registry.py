from app.crypto import MockValidatorRegistry


def test_mock_validator_registry_satisfies_registry_contract():
    validator_id = bytes.fromhex("11" * 32)

    registry = MockValidatorRegistry([validator_id])

    assert registry.active_validator_ids() == (validator_id,)
    assert registry.active_validator_count() == 1
    assert registry.is_active(validator_id) is True


def test_mock_validator_registry_contract_works_with_quorum_verifier():
    validator_id = bytes.fromhex("22" * 32)

    registry = MockValidatorRegistry([validator_id])

    assert registry.active_validator_count() == 1
    assert registry.is_active(validator_id) is True
