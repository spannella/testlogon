from app.services.profile import PROFILE_FIELDS, PROFILE_FIELD_VISIBILITY, PROFILE_VISIBILITY_LEVELS


def test_profile_visibility_matrix_classifies_all_profile_fields() -> None:
    assert set(PROFILE_FIELD_VISIBILITY.keys()) == set(PROFILE_FIELDS)


def test_profile_visibility_matrix_uses_known_levels() -> None:
    allowed = set(PROFILE_VISIBILITY_LEVELS)
    assert all(level in allowed for level in PROFILE_FIELD_VISIBILITY.values())
