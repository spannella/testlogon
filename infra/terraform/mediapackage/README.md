# MediaPackage + SPEKE IaC Scaffold (VWD-012)

This module provisions a baseline non-prod packaging layer with DRM integration hooks:

- MediaPackage channel
- MediaPackage HLS endpoint (SPEKE encryption)
- MediaPackage DASH endpoint (SPEKE encryption)
- IAM role/policy for SPEKE API access

## Usage

```hcl
module "mediapackage" {
  source      = "./infra/terraform/mediapackage"
  name_prefix = "nonprod-video"
  speke_url   = "https://example-speke.execute-api.us-east-1.amazonaws.com/v1/speke"
  tags = {
    env     = "nonprod"
    service = "video"
  }
}
```

## Staging validation checklist

- Confirm HLS and DASH endpoints are reachable and manifests are encrypted.
- Confirm SPEKE key provider receives requests for both HLS and DASH resource IDs.
- Confirm playback license workflow succeeds with staged DRM provider for Widevine/FairPlay/PlayReady.
