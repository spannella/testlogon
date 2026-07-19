# Delegate feed post list 500s on a legacy post with numeric created_at/updated_at

## Symptom
GET /ui/newsfeed/delegate/{creator_id}/posts returns 500
(pydantic ValidationError: DelegatedPostOut.updated_at 'Input should be a valid
string ... input_value=Decimal(...)'). A creator with even ONE post whose
created_at/updated_at was persisted as a numeric epoch cannot have their delegate
feed listed at all.

## Root cause
DelegatedPostOut types created_at/updated_at as str, but some post writers persist
those as numeric (DynamoDB Decimal) epochs. _to_post_out did DelegatedPostOut(**d)
directly, so a single legacy/numeric row raises ValidationError and (via
response_model=List[DelegatedPostOut]) 500s the whole list.

## Fix
Coerce created_at/updated_at to str in _to_post_out before constructing the model
(handles both str and numeric stored values). See
delegate_feed_timestamp_coercion.patch.

## Prod-mirror status: PROD: APPLIED 2026-07-19
> PROD: APPLIED 2026-07-19 (SSM). Pre-fix prod had bare `DelegatedPostOut(**d)` in _to_post_out, NOT divergent.
> Added str-coercion of created_at/updated_at. bak: `app/routers/delegate_feed.py.bak_fs_delegate_feed_timestamp_coercion_20260719045927`.
> Verify: _to_post_out with Decimal/int timestamps coerces to str (was ValidationError 500). dev==prod.

Any creator with a numeric-timestamp post row hits this 500 in prod. Apply via SSM
+ restart uvicorn; verify GET .../posts returns 200.

## e2e impact
delegates-newsfeed 495.2 'Post appears in creator's post list'.
