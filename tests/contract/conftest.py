from __future__ import annotations

import pytest


@pytest.fixture(params=["local", "aws"])
def provider_mode(request):
    return request.param
