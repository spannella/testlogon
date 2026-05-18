#!/bin/sh
set -eu

MINIO_ALIAS="${MINIO_ALIAS:-local}"
MINIO_ENDPOINT="${MINIO_ENDPOINT:-http://minio:9000}"
ARCHIVE_BUCKET="${BROADCAST_ARCHIVE_BUCKET:-broadcast-archive}"

until mc alias set "${MINIO_ALIAS}" "${MINIO_ENDPOINT}" "${MINIO_ROOT_USER}" "${MINIO_ROOT_PASSWORD}" >/dev/null 2>&1; do
  echo "[minio-init] waiting for minio endpoint ${MINIO_ENDPOINT}"
  sleep 2
done

mc mb --ignore-existing "${MINIO_ALIAS}/${ARCHIVE_BUCKET}"
echo "[minio-init] ensured bucket ${ARCHIVE_BUCKET}"
