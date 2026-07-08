import io, sys

def patch(path, edits):
    with io.open(path, 'r', encoding='utf-8') as f:
        s = f.read()
    orig = s
    for old, new, n in edits:
        c = s.count(old)
        assert c == n, 'FAIL %s expected %d got %d for: %r' % (path, n, c, old[:70])
        s = s.replace(old, new)
    if s != orig:
        with io.open(path, 'w', encoding='utf-8') as f:
            f.write(s)
        print('PATCHED', path)
    else:
        print('NOCHANGE', path)

base = sys.argv[1].rstrip('/')
M = base + '/app/models.py'
CAMP = base + '/app/services/ad_campaigns.py'

patch(M, [
('_BID_CPM_MIN = 50\n_BID_CPM_MAX = 20_000\n_BID_CPM_DEFAULT = 500  # $5.00 CPM default',
 '_BID_CPM_MIN = 50\n_BID_CPM_MAX = 20_000\n_BID_CPM_DEFAULT = 500  # $5.00 CPM default\n# ADV-301: CPC/CPA bid bounds (cents). CPC $0.01..$100 default $0.50;\n# CPA $0.01..$1000 default $5.00.\n_BID_CPC_MIN = 1\n_BID_CPC_MAX = 10_000\n_BID_CPC_DEFAULT = 50\n_BID_CPA_MIN = 1\n_BID_CPA_MAX = 100_000\n_BID_CPA_DEFAULT = 500', 1),
('    bid_cpm_cents: int = Field(\n        default=_BID_CPM_DEFAULT, ge=_BID_CPM_MIN, le=_BID_CPM_MAX\n    )\n    # Ad category for the campaign.',
 '    bid_cpm_cents: int = Field(\n        default=_BID_CPM_DEFAULT, ge=_BID_CPM_MIN, le=_BID_CPM_MAX\n    )\n    # ADV-301: advertiser-set CPC/CPA bids (traffic/conversion objectives + auction).\n    bid_cpc_cents: int = Field(\n        default=_BID_CPC_DEFAULT, ge=_BID_CPC_MIN, le=_BID_CPC_MAX\n    )\n    bid_cpa_cents: int = Field(\n        default=_BID_CPA_DEFAULT, ge=_BID_CPA_MIN, le=_BID_CPA_MAX\n    )\n    # Ad category for the campaign.', 1),
('    bid_cpm_cents: Optional[int] = Field(\n        default=None, ge=_BID_CPM_MIN, le=_BID_CPM_MAX\n    )\n\n\nclass CampaignReviewIn',
 '    bid_cpm_cents: Optional[int] = Field(\n        default=None, ge=_BID_CPM_MIN, le=_BID_CPM_MAX\n    )\n    # ADV-301: bound CPC/CPA on update to match creation validation.\n    bid_cpc_cents: Optional[int] = Field(\n        default=None, ge=_BID_CPC_MIN, le=_BID_CPC_MAX\n    )\n    bid_cpa_cents: Optional[int] = Field(\n        default=None, ge=_BID_CPA_MIN, le=_BID_CPA_MAX\n    )\n\n\nclass CampaignReviewIn', 1),
('    bid_cpm_cents: int = _BID_CPM_DEFAULT\n\n\n# -- Delegates (DELEGATE-001) --',
 '    bid_cpm_cents: int = _BID_CPM_DEFAULT\n    # ADV-301: surface CPC/CPA bids for advertiser audit.\n    bid_cpc_cents: int = _BID_CPC_DEFAULT\n    bid_cpa_cents: int = _BID_CPA_DEFAULT\n\n\n# -- Delegates (DELEGATE-001) --', 1),
('    view_time_ms: int = Field(default=0, ge=0)\n    user_agent: str = ""\n    geo_country: str = ""\n\n\nclass AdTrackEventOut',
 '    view_time_ms: int = Field(default=0, ge=0)\n    user_agent: str = ""\n    geo_country: str = ""\n    # ADV-303: per-serve ad_click_id minted by serve_ad; carries the cleared\n    # auction price + content owner so track can bill the impression/click.\n    ad_click_id: str = ""\n\n\nclass AdTrackEventOut', 1),
])

patch(CAMP, [
('        "bid_cpm_cents": data.bid_cpm_cents,\n        "created_at": ts,',
 '        "bid_cpm_cents": data.bid_cpm_cents,\n        "bid_cpc_cents": data.bid_cpc_cents,\n        "bid_cpa_cents": data.bid_cpa_cents,\n        "created_at": ts,', 1),
])
print('DONE1')
