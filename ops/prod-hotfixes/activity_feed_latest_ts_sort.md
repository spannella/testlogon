# Activity feed groups not sorted by latest_ts (out-of-order items)

## Symptom
GET /ui/alerts/activity returns grouped activity items that are NOT strictly
ordered by latest_ts descending — a newer group can appear after an older one.

## Root cause
get_activity_feed (app/routers/alerts.py) builds groups keyed by source and
emits them in group_order, which is the FIRST-SEEN order of each group key while
scanning raw alerts. It never re-sorts the collapsed groups by their final
latest_ts, so once events group, the emitted order no longer matches latest_ts.

## Fix
Sort the group keys by groups[key].latest_ts descending before slicing to limit
and building result_items. See activity_feed_latest_ts_sort.patch.

## Prod-mirror status: PENDING (running-server-affecting)
User-facing ordering bug on the live activity feed; apply on prod via SSM +
restart uvicorn.

## e2e impact
activity-feed 105.3 'grouped items sorted by latest_ts desc'.
