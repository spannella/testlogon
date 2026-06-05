"""Regression tests for GAP-0002 / GAP-0007.

`serve_broadcast_ad` was a stub that always returned a hardcoded house creative.
It must now delegate to the real ad-serving engine (`ad_serving.serve_ad`) and
fall back to the house creative only when the engine raises or returns unfilled.

Offline only: `serve_ad` is mocked, so no DynamoDB / AWS access occurs.
"""

from unittest.mock import patch

from app.services.broadcast_ads import serve_broadcast_ad

_BROADCAST_CTX = {
    "surface": "broadcast",
    "creator_id": "creator_1",
    "content_id": "session_1",
    "slot_type": "broadcast_preroll",
    "user_id": "viewer_1",
}


def test_delegates_to_engine_and_returns_real_creative():
    """When the engine fills, serve_broadcast_ad returns the engine's creative."""
    engine_result = {
        "filled": True,
        "creative_id": "cmp_creative_abc123",
        "format": "video",
        "video_url": "https://cdn.example.com/creative_abc123.mp4",
        "image_url": None,
        "cta_url": "https://advertiser.example.com",
        "impression_url": "/track?event=impression",
        "click_url": "/track?event=click",
        "skip_url": "/track?event=skip",
    }
    with patch(
        "app.services.ad_serving.serve_ad", return_value=engine_result
    ) as mock_engine:
        result = serve_broadcast_ad(**_BROADCAST_CTX)

    # Broadcast context mapped onto serve_ad's params (content_type="broadcast").
    mock_engine.assert_called_once_with(
        surface="broadcast",
        content_type="broadcast",
        creator_id="creator_1",
        content_id="session_1",
        slot_type="broadcast_preroll",
        user_id="viewer_1",
    )
    assert result is engine_result
    assert result["creative_id"] == "cmp_creative_abc123"
    assert not result["creative_id"].startswith("bcast_house_")


def test_falls_back_to_house_creative_on_engine_exception():
    """Engine error must not surface to the caller -> house creative fallback."""
    with patch(
        "app.services.ad_serving.serve_ad", side_effect=RuntimeError("engine down")
    ) as mock_engine:
        result = serve_broadcast_ad(**_BROADCAST_CTX)

    mock_engine.assert_called_once()
    assert result["filled"] is True
    assert result["creative_id"] == "bcast_house_broadcast_preroll"
    assert result["video_url"].endswith("bcast_house_broadcast_preroll.mp4")


def test_falls_back_to_house_creative_when_engine_unfilled():
    """filled=False from the engine also triggers the house fallback."""
    with patch(
        "app.services.ad_serving.serve_ad", return_value={"filled": False}
    ) as mock_engine:
        result = serve_broadcast_ad(**_BROADCAST_CTX)

    mock_engine.assert_called_once()
    assert result["filled"] is True
    assert result["creative_id"].startswith("bcast_house_")
