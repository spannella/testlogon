AWSTemplateFormatVersion: '2010-09-09'
Description: MediaPackage channel/endpoints with SPEKE hooks (non-prod baseline)

Resources:
  MediaPackageChannel:
    Type: AWS::MediaPackage::Channel
    Properties:
      Id: ${channel_id}

  HlsEndpoint:
    Type: AWS::MediaPackage::OriginEndpoint
    Properties:
      ChannelId: !Ref MediaPackageChannel
      Id: !Sub '${channel_id}-hls'
      ManifestName: index
      HlsPackage:
        SegmentDurationSeconds: 6
        PlaylistType: EVENT
        Encryption:
          SpekeKeyProvider:
            RoleArn: ${speke_role_arn}
            Url: ${speke_url}
            ResourceId: !Sub '${channel_id}-hls'
            SystemIds:
%{ for id in speke_system_ids ~}
              - ${id}
%{ endfor ~}

  DashEndpoint:
    Type: AWS::MediaPackage::OriginEndpoint
    Properties:
      ChannelId: !Ref MediaPackageChannel
      Id: !Sub '${channel_id}-dash'
      ManifestName: manifest
      DashPackage:
        SegmentDurationSeconds: 6
        ManifestLayout: FULL
        Encryption:
          SpekeKeyProvider:
            RoleArn: ${speke_role_arn}
            Url: ${speke_url}
            ResourceId: !Sub '${channel_id}-dash'
            SystemIds:
%{ for id in speke_system_ids ~}
              - ${id}
%{ endfor ~}

Outputs:
  ChannelId:
    Value: !Ref MediaPackageChannel
  HlsEndpointUrl:
    Value: !GetAtt HlsEndpoint.Url
  DashEndpointUrl:
    Value: !GetAtt DashEndpoint.Url
