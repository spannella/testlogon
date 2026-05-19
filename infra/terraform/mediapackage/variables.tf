variable "name_prefix" {
  type        = string
  description = "Prefix for MediaPackage resources."
}

variable "speke_url" {
  type        = string
  description = "SPEKE key provider endpoint URL."
}

variable "speke_system_ids" {
  type        = list(string)
  description = "DRM system IDs for SPEKE (Widevine/FairPlay/PlayReady)."
  default = [
    "edef8ba9-79d6-4ace-a3c8-27dcd51d21ed",
    "94ce86fb-07ff-4f43-adb8-93d2fa968ca2",
    "9a04f079-9840-4286-ab92-e65be0885f95"
  ]
}

variable "tags" {
  type    = map(string)
  default = {}
}
