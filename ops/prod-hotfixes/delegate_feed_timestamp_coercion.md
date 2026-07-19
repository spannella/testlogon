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

## Prod-mirror status: PENDING (running-server-affecting)
Any creator with a numeric-timestamp post row hits this 500 in prod. Apply via SSM
+ restart uvicorn; verify GET .../posts returns 200.

## e2e impact
delegates-newsfeed 495.2 'Post appears in creator's post list'.
