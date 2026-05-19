#!/bin/sh
set -eu

MINIO_ALIAS="${MINIO_ALIAS:-local}"
MINIO_ENDPOINT="${MINIO_ENDPOINT:-http://minio:9000}"
ARCHIVE_BUCKET="${BROADCAST_ARCHIVE_BUCKET:-broadcast-archive}"
ARCHIVE_PREFIX="${BROADCAST_ARCHIVE_PREFIX:-sessions}"

until mc alias set "${MINIO_ALIAS}" "${MINIO_ENDPOINT}" "${MINIO_ROOT_USER}" "${MINIO_ROOT_PASSWORD}" >/dev/null 2>&1; do
  echo "[archive-sync] waiting for minio endpoint ${MINIO_ENDPOINT}"
  sleep 2
done

TARGET_PATH="${MINIO_ALIAS}/${ARCHIVE_BUCKET}/${ARCHIVE_PREFIX}"
echo "[archive-sync] mirroring /data/archive -> ${TARGET_PATH}"
exec mc mirror --watch --overwrite /data/archive "${TARGET_PATH}"
