"""Discoverability alias for the ADS-016 ad scheduling test suite.

The design doc named this feature "Ad Scheduling", but the implementation
module is ``app/services/ad_dayparting.py`` and its offline tests live in
``tests/test_ad_dayparting.py``. This alias lets engineers who follow the
design-doc naming run ``pytest tests/test_ad_scheduling.py`` and discover
the same tests.
"""

from tests.test_ad_dayparting import *  # noqa: F401,F403
