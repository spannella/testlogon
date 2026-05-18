# iCloud Mount Secrets Manager IAM Policy (ICLOUD-020)

This policy is intended for the backend service role that manages iCloud mount secrets.

## Scope

- Access is restricted to secret names under prefix:
  - `arn:aws:secretsmanager:*:*:secret:filemgr/mounts/*`
- KMS usage restricted to the configured mount secret KMS key.
- Runtime now enforces CMK in non-dev environments (`FILEMGR_MOUNT_SECRET_REQUIRE_CMK=1`).

## Example policy

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "AllowMountSecretLifecycle",
      "Effect": "Allow",
      "Action": [
        "secretsmanager:CreateSecret",
        "secretsmanager:PutSecretValue",
        "secretsmanager:GetSecretValue",
        "secretsmanager:DescribeSecret",
        "secretsmanager:DeleteSecret"
      ],
      "Resource": "arn:aws:secretsmanager:*:*:secret:filemgr/mounts/*",
      "Condition": {
        "StringEquals": {
          "aws:RequestTag/managed-by": "filemanager-mount-service"
        },
        "ForAllValues:StringLike": {
          "aws:TagKeys": [
            "filemgr_owner",
            "filemgr_provider",
            "filemgr_mount_id",
            "managed-by"
          ]
        }
      }
    },
    {
      "Sid": "AllowKmsForMountSecrets",
      "Effect": "Allow",
      "Action": [
        "kms:Encrypt",
        "kms:Decrypt",
        "kms:GenerateDataKey",
        "kms:DescribeKey"
      ],
      "Resource": "arn:aws:kms:*:*:key/<FILEMGR_MOUNT_SECRET_KMS_KEY_ID>"
    }
  ]
}
```

## Notes

- Separate read-only support tooling should have `DescribeSecret` only unless explicitly approved.
- CloudTrail + `filemgr_mount_secret_access_total` metrics should be monitored for unexpected read spikes or failures.
- Secret material is never written to mount records; only `secret_ref` is persisted.
