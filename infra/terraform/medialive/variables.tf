variable "name_prefix" {
  type        = string
  description = "Prefix for MediaLive resources (e.g. env-team-service)."
}

variable "input_cidr_allow_list" {
  type        = list(string)
  description = "CIDR ranges allowed to push contribution streams."
  default     = ["0.0.0.0/0"]
}

variable "input_type" {
  type        = string
  description = "MediaLive input type. Example: RTMP_PUSH, URL_PULL, RTP_PUSH."
  default     = "RTMP_PUSH"
}

variable "channel_class" {
  type        = string
  description = "MediaLive channel class."
  default     = "SINGLE_PIPELINE"
}

variable "destination_url" {
  type        = string
  description = "Primary destination URL for MediaLive channel output."
}

variable "tags" {
  type        = map(string)
  default     = {}
}
