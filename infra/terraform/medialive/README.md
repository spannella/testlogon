# MediaLive IaC Scaffold (VWD-011)

This Terraform scaffold provisions reusable non-prod MediaLive dependencies:

- MediaLive input security group
- MediaLive input
- IAM role + policy for channel execution
- Rendered channel template output with canonical ABR ladder (`1080p`, `720p`, `540p`, `360p`)

## Usage

```hcl
module "medialive" {
  source        = "./infra/terraform/medialive"
  name_prefix   = "nonprod-video"
  destination_url = "s3ssl://example-bucket/live/stream"
  tags = {
    env = "nonprod"
    service = "video"
  }
}
```

Then use `module.medialive.channel_template_rendered` as the channel template payload in your deployment pipeline.

## Notes

- This module intentionally externalizes full channel creation to pipeline orchestration so channel updates can be reviewed and promoted safely.
- The channel template includes canonical ABR outputs and naming modifiers aligned with local tooling.
