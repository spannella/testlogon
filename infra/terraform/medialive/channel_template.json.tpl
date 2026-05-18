{
  "Name": "${channel_name}",
  "RoleArn": "${role_arn}",
  "ChannelClass": "${channel_class}",
  "InputSpecification": {
    "Codec": "AVC",
    "MaximumBitrate": "MAX_20_MBPS",
    "Resolution": "HD"
  },
  "InputAttachments": [
    {
      "InputId": "${input_id}",
      "InputAttachmentName": "primary_input"
    }
  ],
  "Destinations": [
    {
      "Id": "destination1",
      "Settings": [
        {
          "Url": "${destination_url}"
        }
      ]
    }
  ],
  "EncoderSettings": {
    "OutputGroups": [
      {
        "Name": "HLS Group",
        "OutputGroupSettings": {
          "HlsGroupSettings": {
            "Destination": { "DestinationRefId": "destination1" },
            "SegmentLength": 2
          }
        },
        "Outputs": [
          {
            "OutputName": "1080p",
            "NameModifier": "_1080p",
            "VideoDescriptionName": "video_1080p",
            "AudioDescriptionNames": ["audio_aac"]
          },
          {
            "OutputName": "720p",
            "NameModifier": "_720p",
            "VideoDescriptionName": "video_720p",
            "AudioDescriptionNames": ["audio_aac"]
          },
          {
            "OutputName": "540p",
            "NameModifier": "_540p",
            "VideoDescriptionName": "video_540p",
            "AudioDescriptionNames": ["audio_aac"]
          },
          {
            "OutputName": "360p",
            "NameModifier": "_360p",
            "VideoDescriptionName": "video_360p",
            "AudioDescriptionNames": ["audio_aac"]
          }
        ]
      }
    ],
    "AudioDescriptions": [
      {
        "Name": "audio_aac",
        "CodecSettings": {
          "AacSettings": {
            "Bitrate": 128000,
            "CodingMode": "CODING_MODE_2_0",
            "InputType": "NORMAL",
            "RawFormat": "NONE",
            "SampleRate": 48000,
            "Spec": "MPEG4"
          }
        }
      }
    ],
    "VideoDescriptions": [
      {"Name": "video_1080p", "Width": 1920, "Height": 1080},
      {"Name": "video_720p", "Width": 1280, "Height": 720},
      {"Name": "video_540p", "Width": 960, "Height": 540},
      {"Name": "video_360p", "Width": 640, "Height": 360}
    ],
    "TimecodeConfig": {
      "Source": "SYSTEMCLOCK"
    }
  }
}
