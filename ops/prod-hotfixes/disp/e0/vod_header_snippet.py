# ─── DISP-004: low-level transact serializer for reverse_vod_purchase ────────
# reverse_vod_purchase writes its clawback+refund+marker in ONE TransactWriteItems
# (all-or-nothing, mirroring tips.reverse_tip), which requires the bare low-level
# client + DDB attribute-value maps. _vod_av serializes a plain dict into that map
# (floats -> Decimal first; the boto3 TypeSerializer rejects floats).
_VOD_SERIALIZER = _VodTypeSerializer()


def _vod_to_decimal(obj: Any) -> Any:
    if isinstance(obj, float):
        return Decimal(str(obj))
    if isinstance(obj, dict):
        return {k: _vod_to_decimal(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_vod_to_decimal(v) for v in obj]
    return obj


def _vod_av(item: Dict[str, Any]) -> Dict[str, Any]:
    return {k: _VOD_SERIALIZER.serialize(v) for k, v in _vod_to_decimal(item).items()}
