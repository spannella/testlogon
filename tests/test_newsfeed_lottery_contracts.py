from __future__ import annotations

from app.routers import newsfeed


def test_post_serializer_emits_lottery_contract_fields_when_present() -> None:
    post = {
        "post_id": "p1",
        "user_id": "author_1",
        "created_at": "2026-01-01T00:00:00+00:00",
        "body": "lottery body",
        "locked": True,
        "lock_type": "tip_lottery",
        "lottery_tip_cents": 150,
        "lottery_quiet_period_seconds": 120,
        "lottery_state": "open",
        "lottery_last_tip_at": "2026-01-01T00:00:00+00:00",
        "lottery_last_tipper_user_id": "u2",
        "lottery_winner_user_id": None,
        "lottery_won_at": None,
        "lottery_version": 3,
    }

    out = newsfeed._post_to_dict(post, viewer_id="u3")
    assert out["lock_type"] == "tip_lottery"
    assert out["lottery_tip_cents"] == 150
    assert out["lottery_quiet_period_seconds"] == 120
    assert out["lottery_state"] == "open"
    assert out["lottery_last_tip_at"] == "2026-01-01T00:00:00+00:00"
    assert out["lottery_last_tipper_user_id"] == "u2"
    assert out["lottery_winner_user_id"] is None
    assert out["lottery_won_at"] is None
    assert out["lottery_version"] == 3


def test_create_post_request_preserves_fixed_price_contract() -> None:
    req = newsfeed.CreatePostRequest(
        body="fixed-price post",
        unlock_price_cents=299,
    )
    assert req.unlock_price_cents == 299
    assert req.lock_type is None
    assert req.lottery_tip_cents is None
