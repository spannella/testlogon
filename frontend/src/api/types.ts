/**
 * TypeScript types mirroring backend Pydantic models (app/models.py)
 * and router response shapes.
 */

// ─── Auth / Session ──────────────────────────────────────────────

export interface SessionStartReq {
  challenge_context?: Record<string, unknown>;
}

export interface SessionStartResp {
  auth_required: boolean;
  challenge_id?: string;
  required_factors: string[];
  session_id?: string;
}

export interface SessionFinalizeReq {
  challenge_id: string;
  remember_device?: boolean;
}

export interface SessionFinalizeResp {
  status: "ok" | "pending";
  session_id?: string;
  required_factors: string[];
  passed: Record<string, boolean>;
}

export interface MeResp {
  user_sub: string;
  session_id: string;
  ip: string;
}

export interface SessionInfo {
  session_id: string;
  is_current: boolean;
  created_at: number;
  last_seen_at: number;
  ip: string;
  user_agent: string;
  revoked: boolean;
  revoked_at?: number;
}

export interface TokenRefreshReq {
  refresh_token: string;
}

export interface TokenRefreshResp {
  access_token: string;
  id_token?: string;
  expires_in?: number;
}

// ─── MFA Verification (login flow) ──────────────────────────────

export interface TotpVerifyReq {
  challenge_id: string;
  totp_code: string;
}

export interface SmsBeginReq {
  challenge_id: string;
}

export interface SmsVerifyReq {
  challenge_id: string;
  code: string;
}

export interface EmailBeginReq {
  challenge_id: string;
}

export interface EmailVerifyReq {
  challenge_id: string;
  code: string;
}

export interface RecoveryReq {
  challenge_id: string;
  recovery_code: string;
  factor?: string;
}

export interface MfaVerifyResp {
  status: string;
  session_id?: string;
  required_factors: string[];
  passed: Record<string, boolean>;
  remaining_factors: string[];
}

// ─── MFA Devices ─────────────────────────────────────────────────

export interface TotpDevice {
  device_id: string;
  label?: string;
  enabled: boolean;
  created_at: number;
  last_used_at?: number;
}

export interface TotpDeviceBeginReq {
  label?: string;
}

export interface TotpDeviceBeginResp {
  device_id: string;
  secret: string;
  qr_code_uri: string;
}

export interface TotpDeviceConfirmReq {
  device_id: string;
  totp_code: string;
  totp_code2?: string;
}

export interface SmsDevice {
  sms_device_id: string;
  phone_e164: string;
  label?: string;
  enabled: boolean;
  pending: boolean;
  created_at: number;
  last_used_at?: number;
}

export interface SmsDeviceBeginReq {
  phone_e164: string;
  label?: string;
}

export interface SmsDeviceBeginResp {
  challenge_id: string;
  sent_to: string[];
  sms_device_id: string;
}

export interface SmsDeviceConfirmReq {
  challenge_id: string;
  code: string;
}

export interface EmailDevice {
  email_device_id: string;
  email: string;
  label?: string;
  enabled: boolean;
  pending: boolean;
  created_at: number;
  last_used_at?: number;
}

export interface EmailDeviceBeginReq {
  email: string;
  label?: string;
}

export interface EmailDeviceBeginResp {
  challenge_id: string;
  sent_to: string[];
  email_device_id: string;
}

export interface EmailDeviceConfirmReq {
  challenge_id: string;
  code: string;
}

export interface DeviceRemoveConfirmReq {
  challenge_id: string;
  code: string;
}

// ─── Password Recovery ───────────────────────────────────────────

export interface PasswordRecoveryStartReq {
  username: string;
}

export interface PasswordRecoveryStartResp {
  status: string;
  delivery_medium?: string;
  delivery_destination?: string;
  challenge_id?: string;
  required_factors: string[];
}

export interface PasswordRecoveryConfirmReq {
  username: string;
  confirmation_code: string;
  new_password: string;
  challenge_id?: string;
}

// ─── WebAuthn ────────────────────────────────────────────────────

export interface WebAuthnRegisterBeginReq {
  label?: string;
}

export interface WebAuthnRegisterBeginResp {
  options: Record<string, unknown>;
}

export interface WebAuthnRegisterFinishReq {
  credential: Record<string, unknown>;
  label?: string;
}

export interface WebAuthnRegisterFinishResp {
  credential_id: string;
}

export interface WebAuthnAuthBeginReq {
  username: string;
}

export interface WebAuthnAuthBeginResp {
  options: Record<string, unknown>;
}

export interface WebAuthnAuthFinishReq {
  username: string;
  credential: Record<string, unknown>;
}

export interface WebAuthnAuthFinishResp {
  status: string;
  session_id?: string;
}

// ─── Register ──────────────────────────────────────────────────

export interface RegisterStartReq {
  full_name: string;
  email: string;
  password: string;
  confirm_password: string;
  delivery_method?: "email" | "sms";
  phone?: string | null;
  enable_sms_mfa?: boolean;
  enable_totp_mfa?: boolean;
}

export interface RegisterStartResp {
  status: string;
  verification_required: boolean;
  delivery_medium?: string | null;
  delivery_destination?: string | null;
  session_id?: string | null;
}

export interface RegisterConfirmReq {
  email: string;
  confirmation_code: string;
}

export interface RegisterConfirmResp {
  status: string;
  session_id?: string | null;
  mfa_setup?: string[];
  sms_phone?: string | null;
}

export interface RegisterResendReq {
  email: string;
  delivery_method?: "email" | "sms";
  phone?: string | null;
  enable_sms_mfa?: boolean;
  enable_totp_mfa?: boolean;
}

export interface RegisterResendResp {
  status: string;
  delivery_medium?: string | null;
  delivery_destination?: string | null;
}

export interface RegisterEmailCheckReq {
  email: string;
}

export interface RegisterEmailCheckResp {
  status: string;
  available: boolean;
}

// ─── Passwordless ────────────────────────────────────────────────

export interface PasswordlessStartReq {
  username: string;
}

export interface PasswordlessStartResp {
  status: string;
  sent_to: string[];
}

export interface PasswordlessVerifyReq {
  token: string;
}

export interface PasswordlessVerifyResp {
  status: string;
  session_id?: string;
  auth_required: boolean;
  challenge_id?: string;
  required_factors: string[];
}

// ─── Device Trust ────────────────────────────────────────────────

export interface DeviceTrust {
  device_id: string;
  user_agent: string;
  first_seen_at: number;
  last_seen_at: number;
  last_ip: string;
  trusted: boolean;
}

// ─── API Keys ────────────────────────────────────────────────────

export interface ApiKey {
  key_id: string;
  label?: string;
  created_at: number;
  expires_at?: number;
  last_used_at?: number;
  prefix?: string;
  allow_cidrs?: string[];
  deny_cidrs?: string[];
}

export interface ApiKeyCreated extends ApiKey {
  key_secret: string;
}

export interface CreateApiKeyReq {
  label?: string;
  expires_in_days?: number;
}

export interface RevokeApiKeyReq {
  key_id: string;
}

export interface ApiKeyIpRulesReq {
  key_id: string;
  allow_cidrs: string[];
  deny_cidrs: string[];
}

// ─── Alerts ──────────────────────────────────────────────────────

export interface Alert {
  alert_id: string;
  event: string;
  title: string;
  details?: Record<string, unknown>;
  delivered?: Record<string, boolean>;
  read_at?: number;
  ts: number;
  ttl_epoch?: number;
  priority?: "urgent" | "normal" | "low";
  action_url?: string | null;
  category?: string;
  source_type?: string;
  source_id?: string;
}

export interface AlertsResp {
  alerts: Alert[];
  next_cursor?: string;
}

export interface MarkReadReq {
  alert_ids: string[];
}

// ─── Activity Feed ───────────────────────────────────────────────

export interface ActivityGroupItem {
  source_type: string;
  source_id: string;
  action_url: string | null;
  aggregations: Record<string, {
    count: number;
    latest_actor: string | null;
    total_cents: number;
  }>;
  latest_ts: number;
  title: string;
  unread: boolean;
  alert_ids: string[];
}

export interface ActivityFeedResp {
  items: ActivityGroupItem[];
  next_cursor: string | null;
}

export interface TipsSummary {
  total_tips_cents: number;
  tip_count: number;
  top_tippers: Array<{
    user_id: string;
    display_name: string;
    total_cents: number;
  }>;
  by_type: {
    post_tip: { count: number; total_cents: number };
    message_tip: { count: number; total_cents: number };
  };
}

export interface AlertPreferences {
  email_event_types?: string[];
  emails?: string[];
  sms_event_types?: string[];
  sms_numbers?: string[];
  toast_event_types?: string[];
  push_event_types?: string[];
  webhook_urls?: string[];
  webhook_event_types?: string[];
}

// ─── Profile ─────────────────────────────────────────────────────

export interface MailingAddress {
  line1?: string;
  line2?: string;
  city?: string;
  state?: string;
  postal_code?: string;
  country?: string;
}

export interface Language {
  name: string;
  level: string;
}

export interface Profile {
  display_name?: string;
  first_name?: string;
  middle_name?: string;
  last_name?: string;
  title?: string;
  description?: string;
  birthday?: string;
  gender?: string;
  location?: string;
  displayed_email?: string;
  displayed_telephone_number?: string;
  mailing_address?: MailingAddress;
  languages?: Language[];
  profile_photo_url?: string;
  cover_photo_url?: string;
}

export type ProfileViewAudience = "owner" | "member" | "public";

export interface CrossUserProfileResp {
  identifier: string;
  canonical_identifier?: string;
  user_sub: string;
  audience: ProfileViewAudience;
  profile: Profile;
}

// ─── Public Profile (SOC-006 Storefront) ───────────────────────────

export interface PublicProfileData {
  user_id: string;
  identifier: string;
  canonical_identifier?: string | null;
  display_name: string;
  title?: string | null;
  description?: string | null;
  location?: string | null;
  profile_photo_url?: string | null;
  cover_photo_url?: string | null;
  follower_count: number;
  following_count: number;
  post_count: number;
  is_following: boolean;
  is_followed_by: boolean;
  is_mutual: boolean;
  has_subscription_plans: boolean;
  created_at?: number | null;
  discoverability?: string | null;
}

export interface ProfilePostItem {
  post_id: string;
  created_at: string;
  body_preview?: string | null;
  image_urls: string[];
  video_id?: string | null;
  has_video: boolean;
  locked: boolean;
  unlock_price_cents?: number | null;
  like_count: number;
  comment_count: number;
  tip_total_cents: number;
}

export interface ProfilePostsResponse {
  items: ProfilePostItem[];
  next_cursor?: string | null;
  total_count: number;
}

// ─── Addresses ───────────────────────────────────────────────────

export interface AddressIn {
  name?: string;
  line1?: string;
  line2?: string;
  city?: string;
  state?: string;
  postal_code?: string;
  country?: string;
  label?: string;
  notes?: string;
}

export interface Address extends AddressIn {
  address_id: string;
  is_primary_mailing: boolean;
  created_at: number;
  updated_at: number;
}

// ─── Address Validation ───────────────────────────────────────────

export interface AddressValidateReq {
  line1?: string;
  line2?: string;
  city?: string;
  state?: string;
  postal_code?: string;
  country?: string;
}

export interface ValidatedAddressOut {
  line1: string;
  line2?: string;
  city: string;
  state: string;
  postal_code: string;
  country: string;
}

export interface AddressValidateResp {
  valid: boolean;
  dpv_match_code?: string; // "Y"=exact, "S"=street match, "D"=+4 not confirmed, "A"=ambiguous
  candidates: ValidatedAddressOut[];
}

// ─── Account ─────────────────────────────────────────────────────

export interface AccountState {
  status: string;
  reason?: string;
  updated_at?: number;
  closed_at?: number;
}

export interface AccountStatusReq {
  reason?: string;
}

export interface AccountClosureFinalizeReq {
  challenge_id: string;
}

// ─── Billing ─────────────────────────────────────────────────────

export interface BillingConfig {
  publishable_key?: string;
  currency: string;
  [key: string]: unknown;
}

export interface BillingSettings {
  autopay_enabled: boolean;
  currency: string;
  default_payment_method_id?: string;
  default_payment_token_id?: string;
}

export interface BillingBalance {
  currency: string;
  owed_pending_cents: number;
  owed_settled_cents: number;
  payments_pending_cents: number;
  payments_settled_cents: number;
  due_pending_cents?: number;
  due_settled_cents?: number;
  updated_at?: number;
}

export interface PaymentMethod {
  payment_method_id: string;
  method_type: string;
  label?: string;
  brand?: string;
  last4?: string;
  exp_month?: number;
  exp_year?: number;
  priority: number;
  provider?: string;
  provider_method_id?: string;
  is_default: boolean;
}

export interface LedgerEntry {
  sk: string;
  type: string;
  amount_cents: number;
  state: string;
  reason?: string;
  ts: number;
  [key: string]: unknown;
}

export interface Subscription {
  subscription_id: string;
  plan_id: string;
  status: string;
  billing_cycle?: string;
  next_billing_date?: string;
  [key: string]: unknown;
}

export interface SetAutopayReq {
  enabled: boolean;
}

export interface PayBalanceReq {
  amount_cents?: number;
  idempotency_key?: string;
}

export interface StripeChargeReq {
  amount_cents: number;
  payment_method_id?: string;
  description?: string;
  idempotency_key?: string;
}

export interface StripeRefundReq {
  payment_intent_id: string;
  amount_cents?: number;
  reason?: string;
}

// ── Refund Requests (BILLING-001) ────────────────────────────────────────

export interface RefundRequestIn {
  transaction_entry_id: string;
  reason: string;
  amount_cents?: number;
}

export interface RefundRequestOut {
  refund_request_id: string;
  status: string;
  amount_cents: number;
  currency: string;
  reason: string;
  transaction_type?: string;
  transaction_entry_id?: string;
  created_at: number;
  admin_notes?: string | null;
  completed_at?: number | null;
  requester_user_id?: string;
}

export interface AdminRefundApproveIn {
  notes?: string;
  amount_cents?: number;
}

export interface AdminRefundDenyIn {
  notes: string;
}

export interface SetPriorityReq {
  payment_method_id: string;
  priority: number;
}

export interface SetDefaultReq {
  payment_method_id: string;
}

export interface BillingCheckoutReq {
  amount_cents: number;
  currency?: string;
  description?: string;
}

// ─── Messaging ───────────────────────────────────────────────────

export interface Conversation {
  conversation_id: string;
  type: "dm" | "group";
  title?: string;
  description?: string;
  icon?: string;
  topic?: string;
  retention_days?: number;
  created_at: number;
  created_by: string;
  participant_count: number;
  last_message_at?: number;
  last_message_preview?: string;
  status: string;
  muted_until: number;
  last_read_at: number;
  unread_count: number;
  // Helpdesk routing fields (populated for helpdesk agents only)
  routing_mode?: string;
  routing_group_id?: string;
  routing_state?: string;
  active_agent_user_id?: string;
  active_agent_claimed_at?: number;
  assignment_version?: number;
  // Latest active pin projection
  latest_pinned_message_id?: string;
  latest_pinned_by_user_id?: string;
  latest_pinned_at?: number;
  // UI convenience fields (derived client-side)
  participants: Participant[];
  last_message?: Message;
}

export interface RoutingEventOut {
  conversation_id: string;
  event_id: string;
  event_type: string;
  actor_user_id: string;
  from_state: string;
  to_state: string;
  created_at: number;
  assignment_version: number;
  routing_group_id: string;
  active_agent_user_id: string;
  metadata: Record<string, unknown>;
}

export interface HelpdeskClaimOut {
  ok: boolean;
  conversation_id: string;
  state: string;
  assigned_agent_user_id: string;
  assignment_version: number;
  idempotent: boolean;
}

export interface Participant {
  user_id: string;
  status?: string;
  role?: "admin" | "member";
  display_name?: string;
  muted_until?: number;
  last_read_at?: number;
  joined_at?: number;
  left_at?: number;
  profile_photo_url?: string;
}

export interface MessageImage {
  bucket?: string;
  key?: string;
  content_type?: string;
  width?: number;
  height?: number;
  url?: string;
  filename?: string;
  filesize?: number;
  file_created_at?: number;
  preview_url?: string;  // Blurred preview URL for locked images
}

export interface GalleryImageItem {
  bucket: string;
  key: string;
  content_type: string;
  width?: number;
  height?: number;
  filename?: string;
  filesize?: number;
  url?: string;
  preview_url?: string;  // For locked items: blurred preview
  preview_bucket?: string;
  preview_key?: string;
}

export interface FileShareAttachment {
  path: string;
  name: string;
  size?: number;
  content_type?: string;
  permission: "read" | "write";
  owner: string;
  is_encrypted?: boolean;
}

export interface MessageEncryptionEnvelope {
  version: 1;
  alg: "AES-256-GCM";
  kdf: "PBKDF2-SHA256";
  iterations: number;
  salt_b64: string;
  iv_b64: string;
  // For text messages: ciphertext stored inline. For media: absent (binary lives in S3).
  ciphertext_b64?: string;
}

export interface MessageFile {
  path?: string;
  name?: string;
  size?: number;
  content_type?: string;
  duration_seconds?: number;
  thumbnail?: string;
  url?: string;
  signature_packet_id?: string;
  signature_packet_role?: "sender" | "signer";
  signature_packet_status?: string;
  signature_packet_status_chip?: "awaiting_your_signature" | "waiting_on_others" | "completed";
  signature_packet_status_text?: string;
  signature_packet_completed_at?: string | null;
  signature_packet_final_pdf_url?: string;
}

export type MessageConsumptionPolicy = "none" | "view_once" | "listen_once";
export type MessageMediaKind = "image" | "video" | "audio";
export type MessageConsumptionState = "pending" | "consumed" | "expired" | "failed";

export interface CalendarShareAttachment {
  calendar_id: string;
  name: string;
  owner: string;
  permission: "read" | "write";
  booking_link_id?: string;
  booking_public_url?: string;
}

export interface CalendarEventAttachment {
  event_id: string;
  calendar_id: string;
  name: string;
  start_utc?: string;
  end_utc?: string;
  all_day: boolean;
  all_day_date?: string;
  timezone: string;
  description?: string;
  owner: string;
}

export interface MeetingPollSlot {
  slot_id: string;
  start_utc: string;
  end_utc: string;
  yes_count: number;
  maybe_count: number;
  no_count: number;
  my_vote: "yes" | "no" | "maybe" | null;
}

export interface MeetingPollAttachment {
  poll_id: string;
  creator_id: string;
  title: string;
  duration_minutes: number;
  status: "open" | "confirmed" | "cancelled";
  confirmed_slot_id: string | null;
}

export interface MeetingPollState {
  poll_id: string;
  title: string;
  duration_minutes: number;
  creator_id: string;
  status: "open" | "confirmed" | "cancelled";
  confirmed_slot_id: string | null;
  slots: MeetingPollSlot[];
}

export interface SendCalendarShareReq {
  calendar_id: string;
  permission: "read" | "write";
  include_booking_link: boolean;
  text?: string;
}

export interface SendCalendarEventReq {
  calendar_id: string;
  event_id: string;
  text?: string;
}

export interface SendMeetingPollReq {
  title: string;
  duration_minutes: number;
  slots: Array<{ start_utc: string; end_utc: string }>;
  text?: string;
}

export interface Message {
  message_id: string;
  conversation_id: string;
  sender_id: string;
  kind: "text" | "image" | "file" | "audio" | "video" | "gallery" | "file_share" | "calendar_share" | "calendar_event" | "meeting_poll" | "video_share" | "voice_message" | "voicemail";
  created_at: number;
  text?: string;
  image?: MessageImage;
  file?: MessageFile;
  // Gallery message fields
  free_images?: GalleryImageItem[];
  locked_images?: GalleryImageItem[] | null;  // null = hidden (not unlocked yet)
  locked_image_count?: number;
  file_share?: FileShareAttachment;
  calendar_share?: CalendarShareAttachment;
  calendar_event?: CalendarEventAttachment;
  meeting_poll?: MeetingPollAttachment;
  video_share?: {
    video_id: string;
    owner_user_id: string;
    title: string;
    thumbnail_url?: string;
    duration_seconds?: number;
    width?: number;
    height?: number;
    visibility: string;
    drm_enabled: boolean;
    hls_manifest_url?: string;
    playback_token?: string;
    playback_expires_at?: number;
  };
  voice_message?: {
    audio_url: string;
    audio_content_type: string;
    audio_size_bytes: number;
    duration_seconds: number;
    waveform_data: number[];
  };
  voicemail?: {
    call_id: string;
    mode: "audio" | "video";
    audio_url?: string | null;
    video_url?: string | null;
    content_type: string;
    size_bytes: number;
    duration_seconds: number;
    waveform_data: number[];
    call_state: string;
    caller_user_id: string;
    callee_user_id: string;
  };
  lottery?: {
    message_type: "lottery_dm";
    lock_state: "locked" | "unlocked";
    selected_outcome?: LotterySelectedOutcome & {
      media_metadata?: {
        bucket?: string;
        key?: string;
        content_type?: string;
        content_length?: number;
        etag?: string | null;
        last_modified?: number | null;
      };
    };
  };
  preview?: LinkPreview;
  reply_to_message_id?: string;
  parent_message_id?: string;
  thread_id?: string;
  thread_root_message_id?: string;
  has_thread?: boolean;
  thread_reply_count?: number;
  thread_last_reply_at?: number;
  forwarded_from?: Record<string, unknown>;
  forward_note?: string;
  edited_at?: number;
  edited_by?: string;
  revoked_at?: number;
  revoked_by?: string;
  delivered_to_count?: number;
  delivered_to_user_ids?: string[];
  read_by_count?: number;
  read_by_user_ids?: string[];
  reactions_counts?: Record<string, number>;
  my_reactions?: string[];
  is_encrypted?: boolean;
  encryption?: MessageEncryptionEnvelope;
  consumption_policy?: MessageConsumptionPolicy;
  media_kind?: MessageMediaKind;
  consumption_state?: MessageConsumptionState;
  consumed_at?: number;
  lock_price_cents?: number;
  lock_description?: string;
  is_unlocked?: boolean;
  locked?: boolean;
  tip_amount_cents?: number;
  tip_currency?: string;
  view_once?: boolean;
  expires_at?: number;
  expired?: boolean;
  scheduled?: boolean;
  deliver_at?: number;
  // UI convenience fields (derived client-side)
  edited?: boolean;
  revoked?: boolean;

  /** PWA-005: Offline queue metadata — only present for locally-queued messages */
  __offline?: {
    queueId: string;
    status: "pending" | "sending" | "failed";
    error?: string;
    enqueuedAt: number;
  };
}

export interface ThreadMessagesPage {
  items: Message[];
  next_cursor?: string | null;
  unread_count?: number;
}

export interface LinkPreview {
  url?: string;
  title?: string;
  description?: string;
  image_url?: string;
  site_name?: string;
}

export interface SendTextMessageReq {
  text?: string;
  encryption?: MessageEncryptionEnvelope;
  reply_to_message_id?: string;
  parent_message_id?: string;
  thread_id?: string;
  thread_root_message_id?: string;
  preview?: LinkPreview;
  lock_price_cents?: number;
  lock_description?: string;
  send_at?: number;
  view_once?: boolean;
  expires_in_seconds?: number;
  tip_amount_cents?: number;
  tip_payment_method_id?: string;
}

export interface SendImageMessageReq {
  bucket: string;
  key: string;
  content_type?: string;
  width?: number;
  height?: number;
  filename?: string;
  filesize?: number;
  file_created_at?: number;
  caption?: string;
  kind?: "image" | "file" | "video";
  reply_to_message_id?: string;
  consumption_policy?: Extract<MessageConsumptionPolicy, "none" | "view_once">;
  expires_in_seconds?: number;
  lock_price_cents?: number;
  lock_description?: string;
  tip_amount_cents?: number;
  tip_payment_method_id?: string;
  send_at?: number;
  encryption?: MessageEncryptionEnvelope;
}

export interface SendTipReq {
  amount_cents: number;
  currency?: string;
  note?: string;
  payment_method_id?: string;
}

export interface SendGalleryMessageReq {
  free_images: Array<{
    bucket: string;
    key: string;
    content_type: string;
    width?: number;
    height?: number;
    filename?: string;
    filesize?: number;
  }>;
  locked_images: Array<{
    bucket: string;
    key: string;
    content_type: string;
    width?: number;
    height?: number;
    filename?: string;
    filesize?: number;
    preview_bucket: string;
    preview_key: string;
  }>;
  text?: string;
  lock_price_cents?: number;
  lock_description?: string;
  expires_in_seconds?: number;
  send_at?: number;
  tip_amount_cents?: number;
  tip_payment_method_id?: string;
}

export interface SendFileMessageReq {
  path: string;
  kind?: "file" | "audio" | "video";
  duration_seconds?: number;
  reply_to_message_id?: string;
  consumption_policy?: MessageConsumptionPolicy;
  signature_packet_id?: string;
}

export interface SendFileShareReq {
  file_path: string;
  permission: "read" | "write";
  text?: string;
  send_at?: number;
}

export interface ConversationDraft {
  draft_id: string;
  conversation_id: string;
  owner_user_id: string;
  text: string;
  version: number;
  created_at: number;
  updated_at: number;
  client_updated_at?: number;
  tenant_id?: string;
}

export interface ConversationDraftListResp {
  items: ConversationDraft[];
  next_cursor?: string;
}

export interface CreateConversationDraftReq {
  text: string;
  client_updated_at?: number;
}

export interface UpdateConversationDraftReq {
  text: string;
  client_updated_at?: number;
}

export interface StartConversationReq {
  participant_ids: string[];
  type?: "dm" | "group";
}

export interface StartGroupConversationReq {
  title?: string;
  participant_ids: string[];
  description?: string;
  icon?: string;
  topic?: string;
  retention_days?: number;
}

export interface PresenceStatus {
  user_id: string;
  online: boolean;
  last_seen_at: number;
}

export interface TypingUser {
  user_id: string;
  updated_at: number;
}

export interface UserSearchResult {
  user_id: string;
  display_name: string;
}

export interface CreateAttachmentGrantResp {
  grant_token: string;
  expires_at: number;
  conversation_id: string;
  message_id: string;
}

export interface ConsumeAttachmentReq {
  consumption_attempt_id: string;
  trigger: "open" | "play";
  playback_seconds?: number;
}

export interface ConsumeAttachmentResp {
  ok: boolean;
  conversation_id: string;
  message_id: string;
  consumption_state: "consumed";
  consumed_at: number;
  consumption_attempt_id: string;
}

export interface MessageViewer {
  user_id: string;
  last_viewed_at: number;
  view_count: number;
}

export interface MessageControlsErrorResp {
  detail: string;
  error_code?: string;
}

export type MessageControlAction = "hidden" | "visible" | "pinned" | "unpinned";

export interface MessageControlActionResp {
  ok: boolean;
  conversation_id: string;
  message_id: string;
  action: MessageControlAction;
  updated_at: number;
}

export interface HiddenMessagesResp {
  items: Message[];
  next_cursor?: string;
}

export interface ConversationPin {
  conversation_id: string;
  message_id: string;
  pinned_by_user_id: string;
  pinned_at: number;
  is_active: boolean;
}

export interface ConversationPinsResp {
  items: ConversationPin[];
  next_cursor?: string;
}

export interface ReportMessageReq {
  reason_code: string;
  statement: string;
}

export interface ReportMessageResp {
  ok: boolean;
  report_id: string;
  conversation_id: string;
  message_id: string;
  reason_code: string;
  status: "submitted";
  created_at: number;
}


export type MessageGalleryType = "image" | "video" | "file" | "link";

export interface ConversationGalleryItem {
  message_id: string;
  conversation_id: string;
  sender_id: string;
  created_at: number;
  type: MessageGalleryType;
  url: string;
  thumbnail_url?: string;
  title?: string;
  file_name?: string;
  content_type?: string;
  size?: number;
}

export interface ConversationGalleryResp {
  items: ConversationGalleryItem[];
  next_cursor?: string;
}


export interface ConversationGalleryQuery {
  type: MessageGalleryType;
  cursor?: string;
  limit?: number;
}

export interface ForwardMessageReq {
  source_conversation_id: string;
  source_message_id: string;
  note?: string;
}

export interface AddParticipantsReq {
  participant_ids: string[];
}

export interface UpdateRoleReq {
  role: "admin" | "member";
}

// ─── Files ───────────────────────────────────────────────────────

export interface FileEncryptionMetadata {
  version?: number;
  alg?: string;
  kdf?: string;
  iterations?: number;
  salt_b64?: string;
  iv_b64?: string;
  orig_name?: string;
  orig_size?: number;
  mime?: string;
}

export type PreviewKind = "image" | "document" | "video" | "audio" | "none" | "pdf" | "word" | "csv" | "excel" | "parquet" | "text";
export type PreviewStatus = "pending" | "ready" | "failed" | "unsupported";

export interface FileEntry {
  name: string;
  path: string;
  type: "file" | "folder";
  size?: number;
  content_type?: string;
  updated_at?: string;
  created_at?: string;
  is_encrypted?: boolean;
  enc_metadata?: FileEncryptionMetadata | null;
  enc_version?: number;
  enc_alg?: string;
  enc_kdf?: string;
  enc_kdf_iterations?: number;
  enc_salt_b64?: string;
  enc_iv_b64?: string;
  enc_orig_name?: string;
  enc_orig_size?: number;
  enc_orig_content_type?: string;
  preview_kind?: PreviewKind;
  preview_status?: PreviewStatus;
  poster_url?: string | null;
  hover_preview_url?: string | null;
  waveform_url?: string | null;
  preview_supported?: boolean;
  preview_reason?: string | null;
}

export interface FileListResp {
  path: string;
  items: FileEntry[];
  cursor?: string;
}

export interface ShareFileReq {
  path: string;
  to_user: string;
  permission: "read" | "write";
  expires_at?: number;
  signature_packet_id?: string;
}


export interface UsageMetricSummary {
  used_bytes: number;
  limit_bytes: number;
  percent_used: number;
}

export interface UsageUnitMetricSummary {
  used_count: number;
  limit_count: number;
  percent_used: number;
}

export interface UsageTransferSplitSummary {
  upload_bytes_total: number;
  download_bytes_total: number;
}

export interface UsageSummaryResp {
  period_id: string;
  upload: UsageMetricSummary;
  download: UsageMetricSummary;
  storage: UsageMetricSummary;
  message_send?: UsageUnitMetricSummary;
  post_publish?: UsageUnitMetricSummary;
  messaging_transfer?: UsageTransferSplitSummary;
  newsfeed_transfer?: UsageTransferSplitSummary;
  messaging_upload_bytes_total?: number;
  messaging_download_bytes_total?: number;
  newsfeed_upload_bytes_total?: number;
  newsfeed_download_bytes_total?: number;
  updated_at?: string;
}

export interface UsageDailyItem {
  day_utc: string;
  upload_bytes_total: number;
  download_bytes_total: number;
  storage_bytes_end_of_day: number;
}

export interface UsageDailyResp {
  from: string;
  to: string;
  items: UsageDailyItem[];
}

export interface UsageStorageFileItem {
  path: string;
  size: number;
}

export interface UsageStorageResp {
  storage_bytes_current: number;
  top_files: UsageStorageFileItem[];
}


export interface SftpMountSummary {
  id: string;
  owner: string;
  protocol?: "sftp" | "scp" | "ftp";
  host: string;
  port: number;
  remote_root: string;
  read_only: boolean;
  status: string;
}

export interface MountMockFileItem {
  name: string;
  path: string;
  type: "file" | "folder";
  size: number;
  modified_at: number;
}

export interface MountMockFilesResp {
  mount_id: string;
  owner: string;
  backend: string;
  path: string;
  items: MountMockFileItem[];
  limit: number;
  cursor?: string | null;
  filesystem_path?: string | null;
}

export interface SharedItem {
  owner: string;
  path: string;
  shared_at: string;
  permission: "read" | "write";
  expires_at?: string | null;
  signature_packet_id?: string | null;
  signature_packet_role?: "sender" | "signer";
  signature_packet_status?: string;
  signature_packet_status_chip?: "awaiting_your_signature" | "waiting_on_others" | "completed";
  signature_packet_status_text?: string;
  signature_packet_completed_at?: string | null;
  signature_packet_final_pdf_url?: string;
  name?: string;
  type?: "file" | "folder";
  size?: number;
  content_type?: string;
  is_encrypted?: boolean;
  enc_metadata?: FileEncryptionMetadata | null;
  enc_version?: number;
  enc_alg?: string;
  enc_kdf?: string;
  enc_kdf_iterations?: number;
  enc_salt_b64?: string;
  enc_iv_b64?: string;
  enc_orig_name?: string;
  enc_orig_size?: number;
  enc_orig_content_type?: string;
  preview_kind?: PreviewKind;
  preview_status?: PreviewStatus;
  poster_url?: string | null;
  hover_preview_url?: string | null;
  waveform_url?: string | null;
  preview_supported?: boolean;
  preview_reason?: string | null;
}

// ─── Calendar ────────────────────────────────────────────────────

export interface WorkingHoursWindow {
  start: string;
  end: string;
}

export interface CalendarCreateIn {
  name: string;
  timezone?: string;
  conflict_detection?: boolean;
  working_hours?: Record<string, WorkingHoursWindow[]>;
  buffer_before_minutes?: number;
  buffer_after_minutes?: number;
}

export interface Calendar {
  calendar_id: string;
  name: string;
  timezone: string;
  conflict_detection: boolean;
  working_hours?: Record<string, WorkingHoursWindow[]>;
  buffer_before_minutes: number;
  buffer_after_minutes: number;
  owner_user_id: string;
  created_at_utc: string;
}

export interface RecurrenceRule {
  freq: "DAILY" | "WEEKLY" | "MONTHLY";
  interval?: number;
  until_utc?: string;
  count?: number;
  byday?: ("MO" | "TU" | "WE" | "TH" | "FR" | "SA" | "SU")[];
  bymonthday?: number[];
  bysetpos?: number[];
}

export interface EventCreateIn {
  name: string;
  description?: string;
  timezone?: string;
  start_utc?: string;
  end_utc?: string;
  all_day?: boolean;
  all_day_date?: string;
  attendees?: string[];
  booking_enabled?: boolean;
  approval_required?: boolean;
  status?: string;
  category?: string;
  recurrence_rule?: RecurrenceRule;
  exdates_utc?: string[];
}

export interface OccurrenceOverrideIn {
  name?: string;
  description?: string;
  timezone?: string;
  start_utc?: string;
  end_utc?: string;
  all_day?: boolean;
  all_day_date?: string;
  status?: string;
  category?: string;
}

export interface BookingReserveReq {
  name?: string;
  description?: string;
  start_utc: string;
  end_utc: string;
  timezone?: string;
  notify?: boolean;
}

export interface CalendarEvent {
  event_id: string;
  calendar_id: string;
  name: string;
  description: string;
  timezone: string;
  start_utc?: string;
  end_utc?: string;
  all_day: boolean;
  all_day_date?: string;
  attendees: string[];
  booking_enabled: boolean;
  approval_required: boolean;
  status: string;
  category?: string;
  recurrence_rule?: RecurrenceRule;
  exdates_utc?: string[];
  recurrence_overrides?: Record<string, OccurrenceOverrideIn>;
  created_at_utc: string;
  sync_state?: string;
  sync_conflict_reason?: string;
  sync_conflict_detected_at_utc?: string;
}

export interface EventsPage {
  events: CalendarEvent[];
  next_cursor?: string;
}

export interface BookingLinkCreateIn {
  name: string;
  duration_minutes: number;
  timezone?: string;
}

export interface BookingLink {
  link_id: string;
  calendar_id: string;
  name: string;
  duration_minutes: number;
  timezone: string;
  created_at_utc: string;
  public_url: string;
}

export interface Opening {
  start_utc: string;
  end_utc: string;
}

// ─── Calendar Sharing & Conflicts ────────────────────────────────

export interface CalendarShare {
  calendar_id: string;
  user_sub: string;
  permission: "read" | "write";
  created_at_utc: string;
}

export interface ShareCalendarReq {
  user_sub: string;
  permission: "read" | "write";
}

export interface ConflictPreviewReq extends EventCreateIn {
  event_id?: string;
}

export interface ConflictResult {
  requested_start_utc: string;
  requested_end_utc: string;
  timezone: string;
  conflicts: CalendarEvent[];
}

export interface SlotSuggestionReq {
  start_utc: string;
  end_utc: string;
  duration_minutes?: number;
  limit?: number;
  window_days?: number;
}

export interface AvailabilityReq {
  calendar_ids: string[];
  start_utc: string;
  end_utc: string;
}

export interface GoogleCalendarIntegrationStatus {
  provider: "google";
  sync_enabled: boolean;
  writeback_enabled: boolean;
  rollout_mode: "all" | "cohort" | "off";
  rollout_percent: number;
  in_rollout_cohort: boolean;
  connection_active: boolean;
  sync_health: string;
  last_sync_status: string;
  last_sync_at_utc: string;
  reauth_required: boolean;
}

export interface GoogleCalendarConnectStart {
  provider: "google";
  authorization_url: string;
  state: string;
  nonce: string;
  expires_at_utc: string;
}

export interface GoogleCalendarConnectCallback {
  provider: "google";
  connection_id: string;
  account_email: string;
  linked: boolean;
  updated_at_utc: string;
}

export interface GoogleCalendarDisconnect {
  provider: "google";
  connection_id: string;
  account_email: string;
  active: boolean;
  revoked: boolean;
  revoke_status: string;
  disconnected_at_utc: string;
}

export interface GoogleCalendarProviderCalendar {
  google_calendar_id: string;
  summary: string;
  access_role?: string | null;
  primary: boolean;
  mapped_internal_calendar_id?: string | null;
}

export interface GoogleCalendarProviderCalendars {
  calendars: GoogleCalendarProviderCalendar[];
}

export interface GoogleCalendarMappingCreateIn {
  internal_calendar_id: string;
  google_calendar_id: string;
}

export interface GoogleCalendarMapping {
  mapping_id: string;
  provider: "google";
  user_sub: string;
  internal_calendar_id: string;
  google_calendar_id: string;
  active: boolean;
  created_at_utc: string;
  updated_at_utc: string;
  unmapped_at_utc: string;
}

export interface GoogleCalendarSyncRun {
  accepted: boolean;
  mode: "incremental" | "full";
  rate_limited: boolean;
  metrics: Record<string, unknown>;
}

// ─── Shopping Cart ───────────────────────────────────────────────

export interface CartSummary {
  cart_id: string;
  status: string;
  created_at: string;
  purchased_at?: string;
  purchased_total_cents?: number;
  currency: string;
  // SHOP-003: Abandonment tracking
  last_activity_at?: number;
  abandoned_at?: number;
  reminder_count?: number;
}

export interface CartItemIn {
  sku: string;
  name: string;
  quantity?: number;
  unit_price_cents: number;
  image_url?: string;
  category_id?: string;
  item_id?: string;
}

export interface CartItem {
  sku: string;
  name: string;
  quantity: number;
  unit_price_cents: number;
  line_total_cents: number;
  updated_at: string;
  image_url?: string;
  category_id?: string;
  item_id?: string;
}

export interface CartItemsResp {
  cart_id: string;
  items: CartItem[];
}

export interface CartTotal {
  cart_id: string;
  total_cents: number;
  currency: string;
}

export interface CartPurchase {
  cart_id: string;
  order_id: string;
  purchased_at: string;
  purchased_total_cents: number;
  currency: string;
  purchase_txn_id?: string;
  original_total_cents?: number;
  discount_cents?: number;
  promo_code_id?: string;
  promo_discount_type?: string;
}

// ─── Catalog ─────────────────────────────────────────────────────

export interface CatalogCategoryIn {
  category_id?: string;
  name: string;
  description?: string;
}

export interface CatalogCategory {
  category_id: string;
  name: string;
  description?: string;
  creator_id?: string;
  created_at: string;
}

export interface CatalogItemIn {
  item_id?: string;
  name: string;
  description?: string;
  price_cents: number;
  currency?: string;
  image_urls?: string[];
  attributes?: Record<string, unknown>;
  stock_count?: number | null;
  low_stock_threshold?: number;
}

export interface CatalogItem {
  category_id: string;
  item_id: string;
  name: string;
  description?: string;
  price_cents: number;
  currency: string;
  image_urls: string[];
  attributes: Record<string, unknown>;
  creator_id?: string;
  created_at: string;
  updated_at: string;
  stock_count?: number | null;
  stock_status: string;
  low_stock_threshold: number;
  stock_updated_at?: string;
  position?: number | null;
}

export interface StockAdjustment {
  item_id: string;
  stock_count?: number | null;
  stock_status: string;
  low_stock_threshold: number;
  stock_updated_at?: string;
}

export interface CatalogReviewIn {
  rating: number;
  title?: string;
  body?: string;
}

export interface CatalogReview {
  item_id: string;
  review_id: string;
  rating: number;
  title?: string;
  body?: string;
  reviewer?: string;
  created_at: string;
}

export interface PaginatedList<T> {
  items: T[];
  next_token?: string;
}

// ─── Newsfeed ────────────────────────────────────────────────────

export interface PostFileAttachment {
  name: string;
  content_type?: string;
  size?: number;
  url: string;
}

/** Metadata attached to broadcast-related newsfeed posts (BCAST-010). */
export interface BroadcastPostMeta {
  session_id: string;
  post_type: "broadcast_announcement" | "broadcast_live" | "broadcast_vod";
  session_name?: string;
  session_description?: string;
  thumbnail_url?: string;
  scheduled_at?: number;
  started_at?: string;
  stopped_at?: string;
  recording_id?: string;
  recording_duration_seconds?: number;
  recording_playback_url?: string;
  peak_viewer_count?: number;
  is_live: boolean;
  broadcast_url?: string;
}

export interface ImageVariant {
  url: string;
  width: number;
  height: number;
  size_bytes?: number;
}

export interface FeedPost {
  post_id: string;
  author_id: string;
  body: string;
  body_plain?: string;
  body_markdown?: string;
  body_markdown_html?: string;
  body_rich?: Record<string, unknown>;
  body_format?: "plain" | "markdown" | "rich";
  body_version?: number;
  image_urls?: string[];
  image_variants?: Array<Record<string, ImageVariant>>;
  video?: {
    video_id: string;
    title: string;
    thumbnail_url?: string | null;
    duration_seconds?: number | null;
    hls_manifest_url?: string | null;
    playback_token?: string | null;
    playback_expires_at?: number | null;
  } | null;
  file_attachments?: PostFileAttachment[];
  lock_expired?: boolean | null;
  lock_type?: "fixed_price" | "tip_lottery";
  unlock_price_cents?: number | null;
  unlock_limit?: number | null;
  unlock_count?: number | null;
  unlock_limit_reached?: boolean | null;
  lottery_tip_cents?: number;
  lottery_quiet_period_seconds?: number;
  lottery_state?: "open" | "won" | "closed";
  lottery_last_tip_at?: string;
  lottery_last_tipper_user_id?: string;
  lottery_winner_user_id?: string;
  lottery_won_at?: string;
  lottery_version?: number;
  like_count: number;
  comment_count: number;
  tip_total_cents?: number;
  liked_by_me?: boolean;
  unlocked?: boolean;
  reactions_counts?: Record<string, number>;
  my_reactions?: string[];
  created_at: string;
  updated_at?: string;
  status?: "scheduled" | "published" | "cancelled";
  publish_at?: number;
  published_at?: string;
  schedule_timezone?: string;
  scheduled_at_local?: string;
  /** BCAST-010: post type for broadcast-related posts */
  post_type?: string;
  /** BCAST-010: broadcast metadata for broadcast post types */
  broadcast_meta?: BroadcastPostMeta;
  /** SOCIAL-001: whether the current viewer has bookmarked this post */
  bookmarked?: boolean;
  /** SOCIAL-002: repost count for this post */
  repost_count?: number;
  /** SOCIAL-002: whether the current viewer has reposted this post */
  reposted_by_me?: boolean;
  /** SOCIAL-002: present when a feed item is a repost — who reposted it */
  reposted_by?: { user_id: string; display_name: string };
  /** SOCIAL-002: quote text from a quote repost */
  repost_quote?: string;
  /** SOCIAL-006: hashtags/topics on this post */
  tags?: string[];
  /** ENGAGE-002: poll data when post_type is "poll" or "survey" */
  poll_data?: PollData | null;
  /** ENGAGE-002: vote counts per question per option */
  poll_vote_counts?: PollVoteCounts | null;
  /** ENGAGE-002: viewer's own votes per question */
  poll_my_votes?: PollMyVotes | null;

  /** SOC-002: feed source attribution — "own" for viewer's posts, "following" for fan-out posts */
  source?: "own" | "following";

  /** PWA-005: Offline queue metadata — only present for locally-queued posts */
  __offline?: {
    queueId: string;
    status: "pending" | "sending" | "failed";
    error?: string;
    enqueuedAt: number;
  };
}

// ENGAGE-002: Poll types
export interface PollOption {
  option_id: string;
  text: string;
}

export interface PollQuestion {
  question_id: string;
  text: string;
  choice_mode: "single" | "multi";
  options: PollOption[];
  max_selections?: number;
}

export interface PollData {
  questions: PollQuestion[];
  closes_at?: number;
  closed: boolean;
  anonymous: boolean;
  allow_vote_change: boolean;
  total_votes: number;
}

export interface PollVoteCounts {
  [questionId: string]: { [optionId: string]: number };
}

export interface PollMyVotes {
  [questionId: string]: string[];
}

export interface VoteResponse {
  ok: boolean;
  question_id: string;
  option_id: string;
  vote_counts: { [optionId: string]: number };
  total_votes: number;
  my_vote?: string;
  my_votes?: string[];
}

export interface PollResultsResponse {
  question_id: string;
  options: Array<{
    option_id: string;
    text: string;
    count: number;
    percentage: number;
    voters: string[];
  }>;
  total_votes: number;
  closed: boolean;
  closes_at?: number;
  my_vote?: string;
}

export interface FeedComment {
  comment_id: string;
  post_id: string;
  author_id: string;
  body: string;
  body_plain?: string;
  body_markdown?: string;
  body_markdown_html?: string;
  body_rich?: Record<string, unknown>;
  body_format?: "plain" | "markdown" | "rich";
  body_version?: number;
  created_at: string;
  updated_at?: string;
  deleted?: boolean;
  version?: number;
  tip_total_cents?: number;
}

export interface FeedCapabilities {
  unlock_limit_enabled: boolean;
  unlock_limit_rollout_mode: string;
}

export interface CreatePostReq {
  body?: string;
  body_plain?: string;
  body_markdown?: string;
  body_rich?: Record<string, unknown>;
  body_format?: "plain" | "markdown" | "rich";
  body_version?: number;
  image_urls?: string[];
  image_variants?: Array<Record<string, ImageVariant>>;
  file_paths?: string[];
  lock_type?: "fixed_price" | "tip_lottery";
  unlock_price_cents?: number;
  publish_at?: number;
  schedule_timezone?: string;
  scheduled_at_local?: string;
  unlock_limit?: number | null;
  lottery_tip_cents?: number;
  lottery_quiet_period_seconds?: number;
  lottery_state?: "open" | "won" | "closed";
  lottery_last_tip_at?: string;
  lottery_last_tipper_user_id?: string;
  lottery_winner_user_id?: string;
  lottery_won_at?: string;
  lottery_version?: number;
  video_id?: string;
  /** SOCIAL-006: explicit tags for the post */
  tags?: string[];
  /** ENGAGE-002: post type for poll/survey */
  post_type?: "standard" | "poll" | "survey";
  /** ENGAGE-002: poll data for creating poll/survey posts */
  poll_data?: {
    questions: Array<{
      text: string;
      choice_mode: "single" | "multi";
      options: Array<{ text: string }>;
      max_selections?: number;
    }>;
    closes_at?: number;
    anonymous: boolean;
    allow_vote_change: boolean;
  };
}

export interface CreateCommentReq {
  body?: string;
  body_plain?: string;
  body_markdown?: string;
  body_rich?: Record<string, unknown>;
  body_format?: "plain" | "markdown" | "rich";
  body_version?: number;
}

export interface EditPostReq {
  body?: string;
  body_plain?: string;
  body_markdown?: string;
  body_rich?: Record<string, unknown>;
  body_format?: "plain" | "markdown" | "rich";
  body_version?: number;
  image_urls?: string[] | null;
  publish_at?: number;
  schedule_timezone?: string;
  scheduled_at_local?: string;
  unlock_limit?: number | null;
}

export interface ScheduledPostsResp {
  items: FeedPost[];
  next_cursor?: string;
}

export interface EditCommentReq {
  body?: string;
  body_plain?: string;
  body_markdown?: string;
  body_rich?: Record<string, unknown>;
  body_format?: "plain" | "markdown" | "rich";
  body_version?: number;
}

export interface DraftPost {
  draft_id: string;
  author_id: string;
  created_at: string;
  updated_at: string;
  body?: string;
  body_plain?: string;
  body_markdown?: string;
  body_rich?: Record<string, unknown>;
  body_format?: "plain" | "markdown" | "rich";
  body_version?: number;
  image_urls?: string[];
  file_paths?: string[];
  unlock_price_cents?: number;
}

export interface CreateDraftPostReq {
  body?: string;
  body_plain?: string;
  body_markdown?: string;
  body_rich?: Record<string, unknown>;
  body_format?: "plain" | "markdown" | "rich";
  body_version?: number;
  image_urls?: string[];
  file_paths?: string[];
  unlock_price_cents?: number;
}

export interface UpdateDraftPostReq {
  body?: string;
  body_plain?: string;
  body_markdown?: string;
  body_rich?: Record<string, unknown>;
  body_format?: "plain" | "markdown" | "rich";
  body_version?: number;
  image_urls?: string[];
  file_paths?: string[];
  unlock_price_cents?: number;
  expected_updated_at?: string;
}

export interface ListDraftPostsResp {
  items: DraftPost[];
  next_cursor?: string;
}

export interface HidePostReq {
  post_id: string;
}

export interface PresignUploadReq {
  filename: string;
  content_type: string;
}

export interface PresignUploadResp {
  attachment: {
    attachment_id: string;
    filename: string;
    content_type: string;
    s3_key: string;
    url?: string;
  };
  put_url: string;
  put_headers: Record<string, string>;
}

export interface TipReq {
  amount_cents: number;
  payment_method_id?: string;
}

// ─── Purchase History ────────────────────────────────────────────

export interface PurchaseTransactionSummary {
  txn_id: string;
  created_at: number;
  updated_at: number;
  status: string;
  amount: number;
  currency: string;
  merchant_id?: string;
  external_ref?: string;
  description?: string;
}

export interface CarrierEvent {
  timestamp?: string;
  description?: string;
  location?: string;
}

export interface PurchaseShipping {
  carrier?: string;
  tracking_number?: string;
  tracking_url?: string;
  status?: string;
  shipped_at?: number;
  delivered_at?: number;
  estimated_delivery?: string;
  carrier_events?: CarrierEvent[];
  last_carrier_check?: number;
  address?: Record<string, unknown>;
}

export interface PurchaseTransactionInfo extends PurchaseTransactionSummary {
  buyer_id: string;
  buyer_profile?: Profile;
  shipping?: PurchaseShipping;
  cancel?: Record<string, unknown>;
  completed_at?: number;
  reverted_at?: number;
  version: number;
  metadata?: Record<string, unknown>;
  receipt_path?: string;
  receipt_generated_at?: number;
}

// ─── Subscriptions ──────────────────────────────────────────────

export interface SubscriptionPlan {
  plan_id: string;
  creator_id: string;
  name: string;
  description?: string;
  price_cents: number;
  currency: string;
  interval: string;
  annual_price_cents?: number;
  status: string;
  metadata?: Record<string, unknown>;
  assets?: { path: string; name: string; type: string; size: number; content_type: string }[];
  created_at: number;
  updated_at: number;
  creator_profile?: Profile;
}

export interface SubscriptionOut {
  subscription_id: string;
  plan_id: string;
  creator_id: string;
  subscriber_id: string;
  interval: string;
  provider: string;
  provider_subscription_id: string;
  status: string;
  start_at: number;
  current_period_end: number;
  cancel_at_period_end: boolean;
  price_cents: number;
  currency: string;
  auto_renew: boolean;
  trial_start?: number;
  trial_end?: number;
  proration_policy?: string;
  renewal_policy?: string;
  created_at: number;
  updated_at: number;
  creator_profile?: Profile;
  subscriber_profile?: Profile;
  plan?: SubscriptionPlan;
}

export interface SubscriptionSummary {
  subscription_id: string;
  status: string;
  cancel_at_period_end: boolean;
  total_paid_cents: number;
  currency: string;
  next_amount_cents: number;
  next_renewal_at?: number;
  last_invoice_at?: number;
}

export interface SubscriptionInvoice {
  invoice_id: string;
  subscription_id: string;
  provider_invoice_id: string;
  amount_cents: number;
  currency: string;
  status: string;
  period_start: number;
  period_end: number;
  created_at: number;
  is_proration?: boolean;
  proration_amount_cents?: number;
  proration_period_start?: number;
  proration_period_end?: number;
}

// ─── Plan CRUD Types ─────────────────────────────────────────────

export interface PlanCreateReq {
  name: string;
  description?: string;
  price_cents: number;
  currency?: string;
  interval: "month" | "year";
  annual_price_cents?: number;
  metadata?: Record<string, unknown>;
  asset_paths?: string[];
}

export interface PlanUpdateReq {
  name?: string;
  description?: string;
  price_cents?: number;
  currency?: string;
  interval?: "month" | "year";
  annual_price_cents?: number;
  status?: "active" | "archived";
  metadata?: Record<string, unknown>;
  asset_paths?: string[];
}

// ─── Discount Code Types ─────────────────────────────────────────

export interface DiscountCodeCreateReq {
  code: string;
  percent_off: number;
  duration: "once" | "forever" | "repeating";
  duration_months?: number;
  active?: boolean;
}

export interface DiscountCode {
  code: string;
  percent_off: number;
  duration: string;
  duration_months?: number;
  active: boolean;
  created_at: number;
  updated_at: number;
}

// ─── Push Devices ────────────────────────────────────────────────

export interface PushDevice {
  device_id: string;
  platform: string;
  created_at: number;
  last_seen_at: number;
}

export interface PushRegisterReq {
  token: string;
  platform: string;
}

export interface PushRevokeReq {
  device_id: string;
}

// ─── Profile Audit ──────────────────────────────────────────────

export interface ProfileAuditEntry {
  event: string;
  ts: number;
  outcome?: string;
  [key: string]: unknown;
}

// ─── Generic ─────────────────────────────────────────────────────

export interface OkResp {
  ok: boolean;
}

export interface StatusResp {
  status: string;
}

export interface ChallengeResp {
  challenge_id: string;
  sent_to?: string[];
}


export interface MessagingConfig {
  messaging_encrypted_messages_enabled: boolean;
  messaging_gallery_enabled: boolean;
  messaging_dm_lottery_enabled: boolean;
  messaging_hide_controls_enabled?: boolean;
  messaging_pins_enabled?: boolean;
  messaging_reporting_enabled?: boolean;
}

export interface LotteryOutcomeInput {
  outcome_id?: string;
  display_label?: string;
  weight_bps: number;
  payload_type: "text" | "image" | "video";
  text_content?: string;
  media_asset_id?: string;
}

export interface LotteryConfigInput {
  version?: string;
  outcomes: LotteryOutcomeInput[];
}

export interface CreateLotteryMessageReq {
  message_type?: "lottery_dm";
  conversation_id: string;
  lottery_config: LotteryConfigInput;
}

export interface LotteryOutcome {
  outcome_id: string;
  display_label?: string;
  weight_bps: number;
  payload_type: "text" | "image" | "video";
  text_content?: string;
  media_asset_id?: string;
  media_metadata?: {
    bucket?: string;
    key?: string;
    content_type?: string;
    content_length?: number;
    etag?: string | null;
    last_modified?: number | null;
  };
}

export interface LotteryConfig {
  version: string;
  outcomes: LotteryOutcome[];
}

export interface LotterySelectedOutcome {
  outcome_id: string;
  payload_type: "text" | "image" | "video";
  text_content?: string;
  media_asset_id?: string;
}

export interface LotteryMessage {
  message_id: string;
  conversation_id: string;
  sender_id: string;
  message_type: "lottery_dm";
  lock_state: "locked" | "unlocked";
  lottery_config: LotteryConfig;
  selected_outcome?: LotterySelectedOutcome;
  idempotent?: boolean;
  created_at: number;
}

export interface LotteryUnlockResp {
  message_id: string;
  lock_state: "unlocked";
  selected_outcome: LotterySelectedOutcome;
  unlocked_at: number;
}

// ─── Projects ───────────────────────────────────────────────────

export interface Project {
  id: string;
  owner: string;
  name: string;
  description?: string | null;
  tags: string[];
  settings: Record<string, unknown>;
  created_at: string;
  updated_at: string;
}

export interface ProjectCreateReq {
  name: string;
  description?: string | null;
  tags?: string[];
  settings?: Record<string, unknown>;
}

export interface ProjectUpdateReq {
  name?: string;
  description?: string | null;
  tags?: string[];
  settings?: Record<string, unknown>;
}

export interface ProjectListResp {
  items: Project[];
  cursor?: string | null;
}

export interface TrackedFile {
  id: string;
  project_id: string;
  owner: string;
  provider: string;
  provider_ref: string;
  display_path: string;
  status: string;
  metadata: Record<string, unknown>;
  created_at: string;
  updated_at: string;
  last_seen_at?: string | null;
  archived_at?: string | null;
}

export interface ProjectDetailResp {
  project: Project;
  files: TrackedFile[];
  cursor?: string | null;
}

export interface TrackedFileListResp {
  items: TrackedFile[];
  cursor?: string | null;
}

export interface TrackedFileCreateReq {
  provider: string;
  provider_ref: string;
  display_path?: string;
  metadata?: Record<string, unknown>;
}

export interface DeleteTrackedFileResp {
  ok: boolean;
  deleted: boolean;
}

export interface ProjectEvent {
  id: string;
  project_id: string;
  owner: string;
  event_type: string;
  tracked_file_id?: string | null;
  provider?: string | null;
  provider_ref?: string | null;
  message?: string | null;
  metadata: Record<string, unknown>;
  created_at: string;
}

export interface ProjectEventListResp {
  items: ProjectEvent[];
  cursor?: string | null;
}

export interface ProviderCredentialUpsertReq {
  token: string;
  org?: string;
  api_base_url?: string;
  required_scopes?: string[];
}

export interface ProviderCredential {
  provider: string;
  org?: string | null;
  scopes: string[];
  metadata: Record<string, unknown>;
  created_at: string;
  updated_at: string;
}

export interface DeleteProviderCredentialResp {
  ok: boolean;
  deleted: boolean;
}

// ─── Contacts ─────────────────────────────────────────────────────────────

export interface ContactEntry {
  owner_id: string;
  contact_id: string;
  display_name: string;
  profile_photo_url?: string;
  is_favorite: boolean;
  is_blocked: boolean;
  added_at: string;
}

export interface AddContactReq {
  user_id: string;
}

export interface UpdateContactReq {
  is_favorite?: boolean;
  is_blocked?: boolean;
}

// ─── Wallet ───────────────────────────────────────────────────────────────────

export interface WalletBalance {
  wallet_balance_cents: number;
  currency: string;
  updated_at?: number;
}

export interface WalletDepositReq {
  amount_cents: number;
  payment_method_id?: string;
  idempotency_key?: string;
}

export interface WalletWithdrawReq {
  amount_cents: number;
}

// ─── Internal Dev Tools ─────────────────────────────────────────

export interface DevtoolsParseWarningOut {
  source: "email" | "sms" | "billing";
  line_number?: number;
  code: string;
  message: string;
  sample?: string;
}

export interface DevtoolsIdentityOut {
  id: string;
  id_strategy: string;
}

export interface DevtoolsEmailMailboxOut extends DevtoolsIdentityOut {
  mailbox: string;
  thread_count: number;
  unread_count: number;
}

export interface DevtoolsEmailThreadOut extends DevtoolsIdentityOut {
  mailbox: string;
  subject?: string;
  message_count: number;
  unread_count: number;
  participant_emails: string[];
  latest_message_at: string;
}

export interface DevtoolsEmailMessageOut extends DevtoolsIdentityOut {
  thread_id: string;
  mailbox: string;
  sent_at: string;
  event_kind: "mfa_email_code" | "alert_email" | "unknown";
  direction: "inbound" | "outbound" | "unknown";
  from_email?: string;
  to_emails: string[];
  subject?: string;
  body_text?: string;
  body_html?: string;
  code?: string;
  purpose?: string;
  status?: string;
  parse_warnings: DevtoolsParseWarningOut[];
}

export interface DevtoolsEmailMessagesOut {
  mailboxes: DevtoolsEmailMailboxOut[];
  threads: DevtoolsEmailThreadOut[];
  messages: DevtoolsEmailMessageOut[];
  next_cursor?: string | null;
  parse_warnings: DevtoolsParseWarningOut[];
}

export interface DevtoolsSmsConversationOut extends DevtoolsIdentityOut {
  participant_numbers: string[];
  message_count: number;
  latest_message_at: string;
  latest_preview?: string;
}

export interface DevtoolsSmsMessageOut extends DevtoolsIdentityOut {
  conversation_id: string;
  sent_at: string;
  from_number?: string;
  to_number?: string;
  direction: "inbound" | "outbound" | "unknown";
  body_text?: string;
  code?: string;
  status?: string;
  provider_message_id?: string;
  event_kind: "mfa_sms_code" | "alert_sms" | "unknown";
  parse_warnings: DevtoolsParseWarningOut[];
}

export interface DevtoolsSmsConversationsOut {
  conversations: DevtoolsSmsConversationOut[];
  messages: DevtoolsSmsMessageOut[];
  next_cursor?: string | null;
  parse_warnings: DevtoolsParseWarningOut[];
}

export interface DevtoolsBillingLedgerEntryOut extends DevtoolsIdentityOut {
  provider: "stripe" | "ccbill" | "paypal" | "unknown";
  event_type: string;
  status: string;
  occurred_at: string;
  external_id?: string;
  amount: number;
  fee: number;
  net: number;
  currency: string;
  source_path?: string;
  raw_payload: Record<string, unknown>;
  parse_warnings: DevtoolsParseWarningOut[];
}

export interface DevtoolsBillingLedgerSummaryOut {
  gross_inflow: number;
  fees: number;
  net_total_balance: number;
  transaction_count: number;
  provider_counts: Record<string, number>;
  status_counts: Record<string, number>;
  parse_warnings: DevtoolsParseWarningOut[];
}

export interface DevtoolsBillingLedgerOut {
  entries: DevtoolsBillingLedgerEntryOut[];
  summary: DevtoolsBillingLedgerSummaryOut;
  next_cursor?: string | null;
  parse_warnings: DevtoolsParseWarningOut[];
}

// ─── Questionnaire Validation Contract (shared FE/BE) ───────────

export const QUESTIONNAIRE_VALIDATION_CONTRACT_VERSION = "2026-03-validation-v1" as const;

export type QuestionnaireValidationScopeKey = string; // question_id | group:<id> | form:<rule_id>

export interface QuestionnaireValidationIssue {
  code: string;
  message: string;
  blocking?: boolean;
  rule_id?: string;
}

export interface QuestionnaireValidationReq {
  contract_version?: typeof QUESTIONNAIRE_VALIDATION_CONTRACT_VERSION;
  answers_by_question_id: Record<string, unknown>;
  group_rules?: Array<Record<string, unknown>>;
  form_rules?: Array<Record<string, unknown>>;
  final_submit?: boolean;
}

export interface QuestionnaireValidationResp {
  contract_version: typeof QUESTIONNAIRE_VALIDATION_CONTRACT_VERSION;
  is_valid: boolean;
  can_submit: boolean;
  has_blocking_form_error: boolean;
  errors: Record<QuestionnaireValidationScopeKey, QuestionnaireValidationIssue[]>;
}

// ─── Questionnaire Builder ───────────────────────────────────────

export type QuestionnaireStatus = "draft" | "published" | "archived";

export interface QuestionnaireDraft {
  questionnaire_id: string;
  owner_id: string;
  title: string;
  description?: string;
  status: QuestionnaireStatus;
  updated_at: string;
  created_at?: string;
}

export interface QuestionnaireDraftListResp {
  items: QuestionnaireDraft[];
}

export interface QuestionnaireDraftUpdateReq {
  title?: string;
  description?: string;
}

export interface QuestionnaireSection {
  questionnaire_id: string;
  section_id: string;
  title: string;
  description?: string;
  position: number;
  updated_at?: string;
}

export interface QuestionnaireSectionCreateReq {
  section_id: string;
  title: string;
  description?: string;
}

export interface QuestionnaireSectionUpdateReq {
  title?: string;
  description?: string;
}


export type QuestionnaireQuestionType =
  | "text"
  | "select"
  | "multiselect"
  | "radio"
  | "slider"
  | "date"
  | "time"
  | "timezone"
  | "address";

export interface QuestionnaireQuestion {
  question_id: string;
  section_id: string;
  type: QuestionnaireQuestionType;
  label: string;
  required: boolean;
  hint?: string;
  config_json: Record<string, unknown>;
  position: number;
}

export interface QuestionnaireQuestionCreateReq {
  section_id: string;
  question_id: string;
  type: QuestionnaireQuestionType;
  label: string;
  required?: boolean;
  hint?: string;
  config_json: Record<string, unknown>;
}

export interface QuestionnaireQuestionUpdateReq {
  label?: string;
  required?: boolean;
  hint?: string;
  config_json?: Record<string, unknown>;
}


export interface QuestionnaireVersion {
  version_id: string;
  questionnaire_id: string;
  version_number: number;
  status: string;
  published_slug?: string;
  published_at: string;
  published_by?: string;
  schema_json: Record<string, unknown>;
}



export interface PublishedQuestionnaireVersion {
  questionnaire_id: string;
  version_id: string;
  version_number: number;
  published_slug: string;
  visibility: "private" | "public" | "unlisted";
  allow_anonymous: boolean;
  schema_json: Record<string, unknown>;
  published_at: string;
}

export interface QuestionnaireSessionState {
  response_session_id: string;
  questionnaire_id: string;
  version_id: string;
  status: "in_progress" | "submitted";
  started_at: string;
  current_section_index?: number;
  current_question_id?: string;
  respondent_id?: string | null;
}

export interface QuestionnaireSessionStateResp {
  session: QuestionnaireSessionState;
  answers_by_question_id: Record<string, unknown>;
}




export interface QuestionnaireAnalyticsPoint {
  label?: string;
  key?: string;
  count: number;
}

export interface QuestionnaireVersionAnalytics {
  version_id: string;
  version_number?: number;
  published_at?: string;
  funnel: { starts: number; completions: number; completion_rate: number };
  average_completion_seconds: number | null;
  dropoff_points: QuestionnaireAnalyticsPoint[];
  validation_hotspots: QuestionnaireAnalyticsPoint[];
}

export interface QuestionnaireAnalyticsResp {
  analytics: {
    generated_at: string;
    freshness_sla_seconds: number;
    versions: QuestionnaireVersionAnalytics[];
    totals: {
      starts: number;
      completions: number;
      top_dropoffs: QuestionnaireAnalyticsPoint[];
      top_validation_hotspots: QuestionnaireAnalyticsPoint[];
    };
  };
}

// ─── Rate Limiting (PLATFORM-001) ────────────────────────────────

export interface RateLimitGlobalIpConfig {
  window_seconds: number;
  max_requests: number;
  enabled: boolean;
}

export interface RateLimitGroupConfig {
  description: string;
  paths: string[];
  window_seconds: number;
  max_requests_per_user: number;
  max_requests_per_ip: number;
  bypass_roles: string[];
  is_override: boolean;
}

export interface RateLimitConfigResponse {
  global_ip: RateLimitGlobalIpConfig;
  groups: Record<string, RateLimitGroupConfig>;
}

export interface RateLimitEvent {
  pk: string;
  sk: string;
  endpoint_group: string;
  identity_type: string;
  identity_value: string;
  endpoint: string;
  method: string;
  status: string;
  count: number;
  limit: number;
}

export interface RateLimitTopOffenderIp {
  ip: string;
  rejected_count: number;
  last_seen: number;
}

export interface RateLimitTopOffenderUser {
  user_sub: string;
  rejected_count: number;
  last_seen: number;
}

export interface RateLimitTopOffendersResponse {
  top_ips: RateLimitTopOffenderIp[];
  top_users: RateLimitTopOffenderUser[];
}

// -- Creator Analytics Dashboard (ANALYTICS-001) --

export interface AnalyticsTopContentItem {
  content_id: string;
  content_type: string;
  title: string;
  views: number;
  revenue_cents: number;
  engagement_rate: number;
}

export interface AnalyticsOverview {
  period_views: number;
  period_revenue_cents: number;
  period_new_subscribers: number;
  total_subscribers: number;
  top_content: AnalyticsTopContentItem[];
  currency: string;
}

export interface AnalyticsRevenueTimeSeriesItem {
  date: string;
  total_cents: number;
  tips_cents: number;
  subscriptions_cents: number;
  unlocks_cents: number;
  vod_cents: number;
  ads_cents: number;
  calls_cents: number;
}

export interface AnalyticsRevenueBreakdown {
  tips: number;
  subscriptions: number;
  unlocks: number;
  vod: number;
  ads: number;
  calls: number;
}

export interface AnalyticsRevenue {
  total_cents: number;
  breakdown: AnalyticsRevenueBreakdown;
  time_series: AnalyticsRevenueTimeSeriesItem[];
  currency: string;
}

export interface AnalyticsViewsTimeSeriesItem {
  date: string;
  views: number;
  unique_viewers: number;
  watch_time_seconds: number;
}

export interface AnalyticsViews {
  time_series: AnalyticsViewsTimeSeriesItem[];
  total_views: number;
  total_watch_time_seconds: number;
}

export interface AnalyticsSubscribersTimeSeriesItem {
  date: string;
  new: number;
  churned: number;
  net: number;
  total: number;
}

export interface AnalyticsSubscribers {
  time_series: AnalyticsSubscribersTimeSeriesItem[];
  current_total: number;
  net_change: number;
}

export interface AnalyticsTopContent {
  items: AnalyticsTopContentItem[];
  total_items: number;
}

export interface AnalyticsCountryItem {
  code: string;
  name: string;
  viewers: number;
  percentage: number;
}

export interface AnalyticsDeviceItem {
  type: string;
  viewers: number;
  percentage: number;
}

export interface AnalyticsAudience {
  countries: AnalyticsCountryItem[];
  devices: AnalyticsDeviceItem[];
  total_unique_viewers: number;
}

export interface AnalyticsRefresh {
  ok: boolean;
  message: string;
  days_refreshed: number;
}

export interface AnalyticsDateRangeParams {
  from_date?: string;
  to_date?: string;
  granularity?: string;
  sort_by?: string;
  limit?: number;
}

export interface ContentAnalyticsViewsItem {
  date: string;
  views: number;
  unique_viewers: number;
}

export interface ContentAnalyticsRevenueBreakdown {
  tips: number;
  unlocks: number;
  vod: number;
}

export interface ContentAnalytics {
  content_id: string;
  content_type: string;
  title: string;
  thumbnail_url?: string;
  published_at?: number;
  total_views: number;
  total_revenue_cents: number;
  engagement_rate: number;
  like_count: number;
  comment_count: number;
  view_time_series: ContentAnalyticsViewsItem[];
  revenue_breakdown: ContentAnalyticsRevenueBreakdown;
  currency: string;
}

// ─── Privacy / GDPR (PRIVACY-001) ────────────────────────────────

export interface ExportRequestBody {
  include_messages: boolean;
  include_files: boolean;
  include_billing: boolean;
  include_profile: boolean;
}

export interface DeleteAccountBody {
  password: string;
  reason?: string;
}

export interface DataRequest {
  request_id: string;
  request_type: "export" | "deletion";
  status: "pending" | "processing" | "completed" | "cancelled" | "failed" | "rejected" | "held";
  created_at: number;
  updated_at?: number;
  completed_at?: number;
  grace_period_ends_at?: number;
  export_size_bytes?: number;
  export_download_url?: string;
  deletion_reason?: string;
  deletion_summary?: Record<string, unknown>;
  retention_hold?: boolean;
  retention_hold_reason?: string;
  user_sub?: string;
  admin_actor?: string;
  admin_note?: string;
}

export interface DataRequestListResp {
  requests: DataRequest[];
  next_cursor?: string;
}

export interface DataRequestAuditEntry {
  action: string;
  actor: string;
  created_at: number;
  details?: Record<string, unknown>;
}

// ─── Stories / Ephemeral Content (FEED-002) ─────────────────────

export interface Story {
  story_id: string;
  author_id: string;
  media_type: "image" | "video";
  media_url: string;
  text_overlay?: string;
  link_url?: string;
  link_label?: string;
  duration_seconds?: number;
  created_at: string;
  expires_at: number;
  view_count: number;
  highlighted: boolean;
  highlight_group_id?: string;
}

export interface StoryBarEntry {
  user_id: string;
  latest_story_id: string;
  latest_media_url: string;
  story_count: number;
  has_unseen: boolean;
  is_own: boolean;
}

export interface StoryViewer {
  user_id: string;
  viewed_at: string;
}

export interface StoryHighlightGroup {
  highlight_group_id: string;
  title: string;
  cover_url?: string;
  created_at: string;
  stories: Story[];
}

export interface CreateStoryReq {
  media_type: "image" | "video";
  media_url: string;
  text_overlay?: string;
  link_url?: string;
  link_label?: string;
  duration_seconds?: number;
}

export interface CreateStoryResp {
  story_id: string;
  expires_at: number;
  media_url: string;
  created_at: string;
}

export interface StoryBarResp {
  bar: StoryBarEntry[];
}

export interface StoryViewResp {
  ok: boolean;
  already_viewed: boolean;
}

export interface StoryViewersResp {
  viewers: StoryViewer[];
  total_count: number;
}

export interface UserStoriesResp {
  stories: Story[];
}

export interface UserHighlightsResp {
  groups: StoryHighlightGroup[];
}

export interface CreateHighlightGroupReq {
  title: string;
  cover_url?: string;
}

export interface CreateHighlightGroupResp {
  highlight_group_id: string;
  title: string;
  created_at: string;
}

// ─── Referral / Affiliate (AFFILIATE-001) ───────────────────────

export interface ReferralCode {
  code: string;
  active: boolean;
  commission_tier: string;
  referral_count?: number;
  created_at: string;
}

export interface ReferralCodeCreateResp {
  code: string;
  link: string;
  commission_tier: string;
  created_at: string;
}

export interface ReferralDashboardStats {
  total_referrals: number;
  confirmed_referrals: number;
  pending_referrals: number;
  total_earned_cents: number;
  pending_commission_cents: number;
  paid_commission_cents: number;
  available_for_withdrawal_cents: number;
  referral_codes: ReferralCode[];
}

export interface AffiliateCommission {
  source_type: string;
  referred_user_id: string;
  gross_amount_cents: number;
  net_amount_cents: number;
  commission_cents: number;
  commission_rate_bps: number;
  status: string;
  created_at: string;
}

export interface CommissionListResp {
  commissions: AffiliateCommission[];
  next_cursor: string | null;
}

export interface ReferralAttribution {
  referred_by: {
    user_id: string;
    attributed_at: string;
  } | null;
}

export interface ReferralItem {
  referred_user_id: string;
  referral_code: string;
  status: string;
  attributed_at: string;
}

// ─── Webhooks (PLATFORM-002 + ENTERPRISE-005) ──────────────────

export interface WebhookRetryPolicy {
  strategy: "linear" | "exponential" | "fibonacci" | "fixed";
  max_attempts: number;
  initial_delay_seconds: number;
  max_delay_seconds: number;
  jitter_enabled: boolean;
  jitter_max_seconds: number;
  retry_window_seconds: number;
}

export interface WebhookEndpointOut {
  endpoint_id: string;
  url: string;
  description: string;
  event_types: string[];
  enabled: boolean;
  secret: string | null;
  created_at: number;
  updated_at: number;
  last_delivery_at: number | null;
  failure_count: number;
  disabled_reason: string | null;
  retry_policy: WebhookRetryPolicy | null;
  signature_version: string;
  circuit_state: string | null;
  circuit_consecutive_failures: number;
  circuit_failure_threshold: number;
  circuit_cooldown_seconds: number | null;
  circuit_test_at: number | null;
}

export interface WebhookEndpointCreateReq {
  url: string;
  description: string;
  event_types: string[];
  retry_policy?: Partial<WebhookRetryPolicy>;
  signature_version?: string;
  circuit_failure_threshold?: number;
}

export interface WebhookEndpointUpdateReq {
  url?: string;
  description?: string;
  event_types?: string[];
  enabled?: boolean;
  retry_policy?: Partial<WebhookRetryPolicy>;
  signature_version?: string;
}

export interface WebhookDeliveryOut {
  delivery_id: string;
  endpoint_id: string;
  event_type: string;
  event_id: string;
  status: string;
  attempt_count: number;
  max_attempts: number;
  next_retry_at: number | null;
  last_attempt_at: number | null;
  last_response_code: number | null;
  last_response_body: string | null;
  last_error: string | null;
  created_at: number;
  payload: string | null;
}

export interface WebhookTestResult {
  delivery_id: string;
  status: string;
  response_code: number | null;
  response_body: string | null;
  error: string | null;
  duration_ms: number;
}

export interface WebhookHealthSummary {
  total_endpoints: number;
  enabled_endpoints: number;
  disabled_endpoints: number;
  total_deliveries_24h: number;
  success_count_24h: number;
  failed_count_24h: number;
  dead_letter_count_24h: number;
}

export interface WebhookEventType {
  type: string;
  description: string;
}

export interface WebhookDeadLetterOut {
  delivery_id: string;
  endpoint_id: string;
  event_type: string;
  event_id: string;
  payload_preview: string;
  created_at: number;
  failed_at: number;
  failure_reason: string;
  attempt_count: number;
  last_http_status: number | null;
  last_error_message: string | null;
}

export interface WebhookDeliveryStatsOut {
  endpoint_id: string;
  period: string;
  buckets: Array<{
    bucket: string;
    total: number;
    success: number;
    failed: number;
    avg_latency_ms: number;
  }>;
  total_deliveries: number;
  success_rate: number;
  avg_latency_ms: number;
}


// ─── Geo-Blocking (GEO-001) ────────────────────────────────────

export interface GeoRestrictionRequest {
  geo_mode: "allow" | "block" | null;
  geo_countries: string[] | null;
}

export interface GeoRestrictionOut {
  ok: boolean;
  geo_mode: string | null;
  geo_countries: string[] | null;
}

export interface GeoCountry {
  code: string;
  name: string;
}

export interface GeoCountriesListOut {
  countries: GeoCountry[];
}

export interface MyCountryOut {
  country: string | null;
  ip: string;
  source: string;
}

export interface GeoCheckResult {
  allowed: boolean;
  country: string | null;
  geo_mode: string | null;
  matched_rule: string | null;
}

// ─── Promo Codes & Coupons (PROMO-001) ──────────────────────────

export interface PromoCodeOut {
  code_id: string;
  code: string;
  discount_type: "percentage" | "fixed_amount" | "free_trial";
  discount_value: number;
  free_trial_days: number;
  applies_to: string[];
  min_purchase_cents: number;
  max_uses: number;
  max_uses_per_user: number;
  current_uses: number;
  expires_at: number;
  active: boolean;
  created_at: number;
  creator_user_id: string;
}

export interface PromoCodeListOut {
  items: PromoCodeOut[];
  next_cursor: string | null;
}

export interface PromoCodeStatsOut extends PromoCodeOut {
  stats?: {
    total_redemptions: number;
    total_discount_cents: number;
    redemptions: Array<{
      user_id: string;
      redeemed_at: number;
      discount_applied_cents: number;
      checkout_type: string;
    }>;
  };
}

export interface PromoValidateOut {
  valid: boolean;
  code_id: string | null;
  discount_type: string | null;
  discount_cents: number;
  final_price_cents: number;
  free_trial_days: number;
  message: string | null;
}

export interface PromoDeactivateOut {
  ok: boolean;
  code_id: string;
  active: boolean;
}


// ─── Group Video Calls (CALL-012) ────────────────────────────────

export interface GroupCallMediaStatus {
  audio: boolean;
  video: boolean;
  screen: boolean;
}

export interface GroupCallParticipant {
  user_id: string;
  display_name: string;
  joined_at: number;
  left_at: number;
  media_status: GroupCallMediaStatus;
  connection_quality: string;
  state: string;
}

export interface GroupCallSignalingInfo {
  mode: string;
  ice_servers: Array<Record<string, string>>;
}

export interface GroupCallOut {
  call_id: string;
  conversation_id: string;
  creator_user_id: string;
  state: string;
  mode: string;
  max_participants: number;
  current_participant_count: number;
  participants: GroupCallParticipant[];
  created_at: number;
  started_at: number;
  end_ts: number;
  end_reason: string;
  duration_seconds: number;
  signaling?: GroupCallSignalingInfo;
}

export interface GroupCallJoinOut {
  call_id: string;
  state: string;
  mode: string;
  current_participant_count: number;
  participants: GroupCallParticipant[];
  signaling: GroupCallSignalingInfo;
}

export interface GroupCallLeaveOut {
  ok: boolean;
  call_ended: boolean;
  remaining_participants: number;
}

export interface GroupCallEndOut {
  ok: boolean;
  call_id: string;
  duration_seconds: number;
  total_participants: number;
}

export interface GroupCallParticipantsOut {
  participants: GroupCallParticipant[];
  total_active: number;
  total_joined: number;
}

export interface GroupCallActiveOut {
  active: boolean;
  call_id?: string;
  state?: string;
  mode?: string;
  current_participant_count?: number;
  participants?: GroupCallParticipant[];
}

export interface GroupCallHistoryOut {
  calls: GroupCallOut[];
}

export interface GroupCallMediaUpdateOut {
  ok: boolean;
  media_status: GroupCallMediaStatus;
}

export interface GroupCallSignalOut {
  ok: boolean;
  relayed_to: string;
}

// ─── Blocking ───────────────────────────────────────────────────

export interface BlockedUser {
  user_id: string;
  display_name?: string;
  profile_photo_url?: string;
  blocked_at: string;
}

export interface BlockedUsersResponse {
  blocked_users: BlockedUser[];
  next_cursor?: string;
  total_count: number;
}

export interface BlockStatusResponse {
  is_blocked_by_me: boolean;
  is_blocking_me: boolean;
}

export interface BlockActionResponse {
  ok: boolean;
  status: "blocked" | "unblocked";
  target_user_id: string;
}

// ─── Tip Leaderboards (SOCIAL-005) ──────────────────────────────────

export interface TopSupporter {
  rank: number;
  user_id: string;
  display_name: string;
  avatar_url: string | null;
  total_cents: number;
  tip_count: number;
  last_tip_at: number;
}

export interface TopSupportersResp {
  creator_id: string;
  period: string;
  supporters: TopSupporter[];
  total_tip_cents: number;
  total_supporters: number;
  computed_at: number;
}

// ─── Creator Payouts (BILLING-002) ──────────────────────────────

export interface PayoutBalance {
  available_cents: number;
  pending_cents: number;
  total_earned_cents: number;
  hold_cents: number;
  currency: string;
  minimum_payout_cents: number;
}

export interface Payout {
  payout_id: string;
  user_id: string;
  amount_cents: number;
  method: string;
  status: string;
  created_at: number;
  updated_at: number;
  notes: string;
  reject_reason: string;
  approved_by: string;
  completed_at: number | null;
}

export interface PayoutCreateResp {
  ok: boolean;
  payout_id: string;
  amount_cents: number;
  status: string;
}

export interface PayoutActionResp {
  ok: boolean;
  payout_id: string;
  status: string;
}

export interface PayoutListResp {
  items: Payout[];
  next_cursor: string | null;
}

export interface EarningsBreakdown {
  subscriptions: number;
  tips: number;
  unlocks: number;
  vod_purchases: number;
  other: number;
}

export interface EarningsSummary {
  total_cents: number;
  breakdown: EarningsBreakdown;
  transaction_count: number;
  currency: string;
}

export interface EarningsTransaction {
  entry_id: string;
  ts: number;
  amount_cents: number;
  reason: string;
  category: string;
  currency: string;
  meta: Record<string, unknown>;
}

export interface EarningsTransactionsResp {
  items: EarningsTransaction[];
  next_cursor: string | null;
}

// ─── Video Subtitles (VOD-021) ─────────────────────────────────────

export interface SubtitleTrack {
  track_id: string;
  language: string;
  label: string;
  format: string;
  vtt_url: string;
  is_default: boolean;
  is_auto_generated: boolean;
  created_at: number;
}

export interface SubtitleListOut {
  video_id: string;
  tracks: SubtitleTrack[];
}

export interface SubtitleDeleteOut {
  ok: boolean;
  track_id: string;
  video_id: string;
}

// --- Broadcast Lottery (BCAST-014) ------------------------------------------

export interface BroadcastLotteryOutcomeIn {
  display_label?: string;
  weight_bps: number;
  payload_type: "text" | "image" | "video";
  text_content?: string;
  media_asset_id?: string;
}

export interface BroadcastLotteryCreateIn {
  title: string;
  outcomes: BroadcastLotteryOutcomeIn[];
  max_entries?: number | null;
  entry_fee_cents?: number;
  duration_seconds?: number | null;
}

export interface BroadcastLotteryEntryIn {
  payment_method_id?: string;
}

export interface BroadcastLotteryOutcomeOut {
  outcome_id: string;
  display_label?: string;
  weight_bps: number;
  payload_type: "text" | "image" | "video";
  text_content?: string;
  media_asset_id?: string;
}

export interface BroadcastLotteryConfigOut {
  lottery_id: string;
  message_id: string;
  title: string;
  status: "open" | "entries_closed" | "drawn";
  outcomes: BroadcastLotteryOutcomeOut[];
  entry_count: number;
  max_entries?: number | null;
  entry_fee_cents: number;
  currency: string;
  duration_seconds?: number | null;
  closes_at?: number | null;
  created_at: number;
  drawn_at?: number | null;
}

export interface BroadcastLotteryResultEntry {
  user_id: string;
  display_name: string;
  outcome_id: string;
  display_label?: string;
  payload_type: "text" | "image" | "video";
  text_content?: string;
  media_asset_id?: string;
  rng_roll: number;
}

export interface BroadcastLotteryDrawOut {
  lottery_id: string;
  status: "drawn";
  results: BroadcastLotteryResultEntry[];
  idempotent: boolean;
}

export interface BroadcastLotteryEntryOut {
  lottery_id: string;
  user_id: string;
  entered_at: number;
  already_entered: boolean;
  entry_fee_cents: number;
}

export interface BroadcastLotteryViewerStatus {
  lottery_id: string;
  title: string;
  status: "open" | "entries_closed" | "drawn";
  entry_count: number;
  max_entries?: number | null;
  entry_fee_cents: number;
  closes_at?: number | null;
  created_at: number;
  drawn_at?: number | null;
  has_entered: boolean;
  viewer_outcome?: BroadcastLotteryResultEntry | null;
}

// ─── Broadcast Multi-Input / Co-Streaming (BCAST-016) ────────────

export interface BroadcastInput {
  input_id: string;
  session_id: string;
  input_type: "primary" | "guest" | "screen";
  label: string;
  ingest_url: string | null;
  stream_key_ref: string | null;
  aws_input_arn: string | null;
  is_live: boolean;
  connected_at: number | null;
  disconnected_at: number | null;
  position: number;
  created_by: string;
  created_at: string;
  updated_at: string;
  relay_mode: string | null;
}

export interface BroadcastInputList {
  session_id: string;
  inputs: BroadcastInput[];
  count: number;
  max_inputs: number;
}

export interface BroadcastInputCreated {
  input_id: string;
  session_id: string;
  input_type: string;
  label: string;
  ingest_url: string;
  stream_key: string;
  aws_input_arn: string | null;
  position: number;
}

export interface BroadcastLayout {
  mode: "single" | "side_by_side" | "pip" | "grid";
  positions: Array<{
    input_id: string;
    x: number;
    y: number;
    width: number;
    height: number;
    z_index: number;
  }>;
  primary_input_id: string | null;
  input_ids: string[];
}

export interface BroadcastGuestInvite {
  invite_id: string;
  session_id: string;
  input_id: string;
  invite_url: string | null;
  ingest_url: string | null;
  stream_key: string | null;
  join_mode: "rtmp" | "browser";
  status: "pending" | "accepted" | "expired" | "revoked";
  guest_user_id: string | null;
  guest_display_name: string | null;
  expires_at: number;
  accepted_at: number | null;
  created_at: string;
}

export interface BroadcastGuestInviteList {
  session_id: string;
  invites: BroadcastGuestInvite[];
  count: number;
}

export interface BroadcastGuestAcceptResult {
  invite_id: string;
  input_id: string;
  ingest_url: string | null;
  join_mode: string;
  session_id: string;
}

export interface BroadcastWebRTCAnswer {
  sdp_answer: string;
  session_id: string;
  input_id: string;
}

// ─── Achievements & Gamification (ENGAGE-001) ──────────────────

export interface AchievementDefinition {
  achievement_id: string;
  category: "creator" | "viewer" | "general";
  subcategory: string;
  label: string;
  description: string;
  icon_url: string;
  rarity: "common" | "uncommon" | "rare" | "epic" | "legendary";
  threshold: number;
  points: number;
  metric_key: string;
  active: boolean;
  sort_order: number;
  created_at: number;
  updated_at: number;
}

export interface UserAchievement {
  achievement_id: string;
  label: string;
  description: string;
  icon_url: string;
  rarity: string;
  points: number;
  unlocked_at: number;
  trigger_event: string;
  displayed: boolean;
}

export interface AchievementProgress {
  metric_key: string;
  current_value: number;
  last_updated_at: number;
  last_updated_date: string;
  highest_value: number;
  streak_anchor_date?: string;
  next_threshold?: number | null;
  next_achievement?: {
    achievement_id: string;
    label: string;
    rarity: string;
    points: number;
  } | null;
}

export interface LeaderboardEntry {
  rank: number;
  user_sub: string;
  display_name: string;
  total_points: number;
  achievement_count: number;
  display_badges: BadgeSummary[];
}

export interface BadgeSummary {
  achievement_id: string;
  label: string;
  icon_url: string;
  rarity: string;
}

// ─── Collaboration Requests (CREATOR-001) ──────────────────────────

export interface CollaborationCreateIn {
  recipient_id: string;
  content_types: string[];
  split_pct: number;
  title: string;
  description?: string;
  terms_text?: string;
  valid_from?: number;
  valid_until?: number;
  max_content_items?: number;
}

export interface CollaborationCounterIn {
  counter_split_pct: number;
  counter_terms_text?: string;
  counter_valid_until?: number;
  reason?: string;
}

export interface CollaborationOut {
  collaboration_id: string;
  initiator_id: string;
  recipient_id: string;
  status: string;
  content_types: string[];
  split: Record<string, number>;
  title: string;
  description?: string;
  terms_text?: string;
  valid_from?: number;
  valid_until?: number;
  max_content_items?: number;
  content_count: number;
  total_revenue_cents: number;
  revision: number;
  created_at: number;
  updated_at: number;
  accepted_at?: number;
  terminated_at?: number;
  terminated_by?: string;
  termination_reason?: string;
  last_proposed_by?: string;
}

export interface CollaborationListOut {
  items: CollaborationOut[];
  next_cursor?: string;
}

export interface CollaborationRevisionOut {
  revision: number;
  split: Record<string, number>;
  terms_text?: string;
  proposed_by: string;
  proposed_at: number;
  status: string;
}

export interface CollaborationSettingsOut {
  accepting_requests: boolean;
  min_split_pct: number;
  allowed_content_types: string[];
  auto_expire_days: number;
  updated_at: number;
}

export interface CollaborationSettingsIn {
  accepting_requests?: boolean;
  min_split_pct?: number;
  allowed_content_types?: string[];
  auto_expire_days?: number;
}

// ENGAGE-003: Live Q&A Mode
export interface QAQuestion {
  question_id: string;
  session_id: string;
  submitter_id: string;
  submitter_display_name: string;
  text: string;
  status: "pending" | "featured" | "answered" | "dismissed" | "removed";
  upvote_count: number;
  featured_at?: number;
  answered_at?: number;
  created_at: number;
  featured_by?: string;
}

export interface QAQueueResponse {
  questions: QAQuestion[];
  has_more: boolean;
}

export interface QAStats {
  total_questions: number;
  answered: number;
  dismissed: number;
  pending: number;
  total_upvotes: number;
  avg_upvotes: number;
  answer_rate: number;
}

// ─── Fan Club / Membership Tiers (CREATOR-002) ──────────────────

export interface TierBenefit {
  type: string;
  label?: string;
  delay_hours?: number;
  channel_id?: string;
  emoji_pack_id?: string;
  display?: boolean;
  percent_off?: number;
  applies_to?: string[];
}

export interface TierCreateIn {
  plan_id: string;
  name: string;
  level: number;
  color: string;
  badge_emoji?: string;
  description?: string;
  benefits: TierBenefit[];
  welcome_message?: string;
  sort_order?: number;
}

export interface TierOut {
  tier_id: string;
  creator_id: string;
  plan_id: string;
  name: string;
  level: number;
  color: string;
  badge_emoji?: string;
  badge_image_url?: string;
  description?: string;
  benefits: TierBenefit[];
  welcome_message?: string;
  member_count: number;
  sort_order: number;
  active: boolean;
  created_at: number;
  updated_at: number;
}

export interface ChannelOut {
  channel_id: string;
  creator_id: string;
  name: string;
  description?: string;
  min_tier_level: number;
  message_count: number;
  last_message_at: number;
  last_message_preview?: string;
  pinned_message_id?: string;
  slowmode_seconds: number;
  max_message_length: number;
  created_at: number;
  updated_at: number;
}

export interface ChannelMessageOut {
  message_id: string;
  channel_id: string;
  sender_id: string;
  sender_display_name: string;
  sender_badge?: MemberBadgeData;
  text: string;
  kind: string;
  reply_to_message_id?: string;
  reactions: Record<string, Record<string, boolean>>;
  created_at: number;
  deleted: boolean;
}

export interface MemberBadgeData {
  tier_name: string;
  tier_level: number;
  badge_emoji?: string;
  badge_color?: string;
  badge_image_url?: string;
}

// -- Creator Dashboard (CREATOR-003) --

export interface DashboardTopContentItem {
  content_id: string;
  content_type: string;
  title: string;
  views: number;
  revenue_cents: number;
}

export interface DashboardActiveBroadcast {
  session_id: string;
  status: string;
  name?: string;
  started_at?: string;
}

export interface DashboardMilestone {
  milestone_id: string;
  user_id: string;
  metric: string;
  threshold: number;
  current_value: number;
  formatted: string;
  achieved_at: number;
  acknowledged: boolean;
}

export interface DashboardEarningsBreakdown {
  subscriptions: number;
  tips: number;
  unlocks: number;
  vod_purchases: number;
  other: number;
}

export interface DashboardSummary {
  today_earnings_cents: number;
  earnings_breakdown: DashboardEarningsBreakdown;
  period_views: number;
  period_revenue_cents: number;
  total_subscribers: number;
  top_content: DashboardTopContentItem[];
  active_broadcasts: DashboardActiveBroadcast[];
  recent_milestones: DashboardMilestone[];
  currency: string;
  generated_at: number;
  warnings: string[];
}

export interface MilestoneSettings {
  push_enabled: boolean;
  email_enabled: boolean;
  celebration_enabled: boolean;
}

// ─── Multi-Tenancy (ENTERPRISE-001) ──────────────────────────────

export interface TenantOut {
  tenant_id: string;
  slug: string;
  display_name: string;
  status: string;
  plan: string;
  custom_domains: string[];
  primary_domain?: string | null;
  branding?: Record<string, unknown> | null;
  limits?: Record<string, unknown> | null;
  member_count: number;
  storage_used_bytes: number;
  created_at: number;
  updated_at: number;
}

export interface TenantCreateReq {
  slug: string;
  display_name: string;
  plan?: string;
  primary_domain?: string | null;
}

export interface TenantUpdateReq {
  display_name?: string | null;
  plan?: string | null;
  status?: string | null;
  branding?: Record<string, unknown> | null;
  settings_overrides?: Record<string, unknown> | null;
}

export interface TenantBranding {
  tenant_id: string;
  display_name: string;
  logo_url?: string | null;
  favicon_url?: string | null;
  primary_color: string;
  accent_color: string;
}

// ─── Watch Parties (ENGAGE-004) ─────────────────────────────────

export interface WatchParty {
  party_id: string;
  host_user_sub: string;
  video_id: string;
  video_title: string;
  video_duration_seconds: number;
  title: string;
  invite_code: string;
  status: "waiting" | "playing" | "paused" | "ended";
  max_participants: number;
  participant_count: number;
  position: number;
  position_updated_at: number;
  created_at: number;
  updated_at: number;
  ended_at?: number | null;
}

export interface WatchPartyParticipant {
  party_id: string;
  user_sub: string;
  role: "host" | "co-host" | "member";
  status: "active" | "left" | "kicked";
  joined_at: number;
  last_seen?: number | null;
}

export interface CreatePartyReq {
  video_id: string;
  title?: string;
  max_participants?: number;
}

export interface PlaybackControlReq {
  action: "play" | "pause" | "seek";
  position?: number;
}

export interface InviteResolveResp {
  party_id: string;
  title: string;
  host_user_sub: string;
  video_title: string;
  status: string;
  participant_count: number;
  max_participants: number;
}

// ─── Content Calendar (CREATOR-005) ─────────────────────────────

export type ContentItemType = "post" | "broadcast" | "vod";

export interface ContentCalendarItem {
  id: string;
  type: ContentItemType;
  title: string;
  scheduled_at: number;
  timezone: string | null;
  local_time: string | null;
  status: "scheduled" | "overdue" | "cancelled";
  color: string;
  icon: string;

  // Post-specific
  has_images?: boolean;
  has_video?: boolean;
  visibility?: string;
  locked?: boolean;
  unlock_price_cents?: number;

  // Broadcast-specific
  description?: string;
  profile_id?: string;
  has_announcement?: boolean;

  // VOD-specific
  duration_seconds?: number;
  thumbnail_url?: string;
}

export interface ContentCalendarConflict {
  item_a_id: string;
  item_a_type: ContentItemType;
  item_b_id: string;
  item_b_type: ContentItemType;
  gap_seconds: number;
  gap_minutes: number;
}

export interface ContentCalendarResponse {
  items: ContentCalendarItem[];
  from_ts: number;
  to_ts: number;
  count: number;
  conflicts: ContentCalendarConflict[];
}

export interface TodayAgendaResponse {
  today: ContentCalendarItem[];
  tomorrow: ContentCalendarItem[];
  today_count: number;
  tomorrow_count: number;
  conflicts: ContentCalendarConflict[];
}

export interface ConflictsResponse {
  conflicts: ContentCalendarConflict[];
  count: number;
}

// --- Broadcast Clips (ENGAGE-005) ---

export interface BroadcastClip {
  clip_id: string;
  session_id: string;
  broadcaster_user_id: string;
  creator_user_id: string;
  creator_display_name: string;
  video_id: string;
  title: string;
  start_seconds: number;
  end_seconds: number;
  duration_seconds: number;
  status: "processing" | "ready" | "failed" | "deleted";
  view_count: number;
  share_count: number;
  thumbnail_url: string;
  created_at: number;
}

export interface ClipListResponse {
  clips: BroadcastClip[];
  next_cursor?: string;
}

// ─── SSO / SAML (ENTERPRISE-002) ────────────────────────────────

export interface SsoInfoOut {
  sso_available: boolean;
  sso_only: boolean;
  sso_login_url?: string;
  provider_display_name?: string;
  provider_protocol?: string;
}

export interface SsoProviderOut {
  provider_id: string;
  tenant_id: string;
  protocol: string;
  display_name: string;
  status: string;
  sso_only: boolean;
  idp_entity_id?: string;
  idp_sso_url?: string;
  sp_entity_id: string;
  sp_acs_url: string;
  attribute_mappings: Record<string, string>;
  role_mappings: Array<{
    idp_group: string;
    platform_role: string;
    admin_profile?: Record<string, unknown>;
  }>;
  jit_provisioning_enabled: boolean;
  auto_update_profile: boolean;
  auto_update_role: boolean;
  default_role: string;
  allowed_email_domains?: string[];
  login_count: number;
  last_login_at?: number;
  created_at: number;
  updated_at: number;
}

export interface SsoProviderStatsOut {
  provider_id: string;
  login_count: number;
  last_login_at?: number;
  status: string;
}

// ─── Social / Follow System (SOC-001) ────────────────────────────

export interface FollowUser {
  user_id: string;
  display_name?: string;
  profile_photo_url?: string;
  is_following: boolean;
  is_mutual: boolean;
}

export interface FollowListResponse {
  items: FollowUser[];
  next_cursor?: string;
  total_count: number;
}

export interface FollowCounts {
  follower_count: number;
  following_count: number;
}

export interface FollowStatus {
  is_following: boolean;
  is_followed_by: boolean;
  is_mutual: boolean;
  is_blocked_by_me?: boolean;
  is_blocking_me?: boolean;
}

export interface FollowResponse {
  ok: boolean;
  status: "followed" | "already_following";
  follower_count: number;
  following_count: number;
}

export interface UnfollowResponse {
  ok: boolean;
  status: "unfollowed" | "not_following";
}

// -- LLM Provider Keys (AGENT-001) --

export interface LlmKeyOut {
  key_id: string;
  user_id?: string;
  provider: string;
  label: string;
  key_suffix: string;
  base_url: string;
  model_preference: string;
  available_models: string[];
  rate_limit_rpm: number;
  monthly_budget_cents: number;
  current_month_usage_cents: number;
  total_requests: number;
  total_tokens_used: number;
  status: string;
  last_tested_at: number;
  last_used_at: number;
  created_at: number;
  updated_at: number;
  assigned_worker_ids: string[];
}

export interface LlmKeyListOut {
  keys: LlmKeyOut[];
  count: number;
}

export interface LlmKeyCreateIn {
  provider: string;
  label: string;
  api_key: string;
  base_url?: string;
  model_preference?: string;
  rate_limit_rpm?: number;
  monthly_budget_cents?: number;
}

export interface LlmKeyRotateIn {
  new_api_key: string;
}

export interface LlmKeyAssignIn {
  worker_id: string;
}

export interface LlmKeyTestOut {
  ok: boolean;
  models: string[];
  error: string;
  latency_ms: number;
}

export interface LlmKeyUsageOut {
  key_id: string;
  provider: string;
  local_usage_cents: number;
  local_total_requests: number;
  local_total_tokens: number;
  provider_balance_cents?: number;
  provider_usage_cents?: number;
  budget_remaining_cents?: number;
}

export interface LlmProviderInfo {
  provider: string;
  display_name: string;
  base_url: string;
  models: string[];
  supports_usage_api: boolean;
}

export interface LlmProviderListOut {
  providers: LlmProviderInfo[];
}

// --- Advertiser Accounts & Campaigns (ADS-001) ---

export interface AdAccount {
  account_id: string;
  owner_sub: string;
  company_name: string;
  billing_email: string;
  status: "pending_review" | "active" | "suspended" | "rejected";
  balance_cents: number;
  lifetime_spend_cents: number;
  created_at: number;
  updated_at: number;
}

export interface Campaign {
  campaign_id: string;
  account_id: string;
  name: string;
  objective: "awareness" | "traffic" | "conversions";
  budget_cents: number;
  budget_type: "daily" | "lifetime";
  daily_budget_cents: number;
  spent_today_cents: number;
  lifetime_spent_cents: number;
  status: "draft" | "pending_review" | "active" | "paused" | "completed" | "rejected" | "archived";
  start_date?: number | null;
  end_date?: number | null;
  created_at: number;
  updated_at: number;
}

// ─── Delegates (DELEGATE-001) ──────────────────────────────────

export interface DelegateAddReq {
  delegate_id: string;
  permissions: string[];
  preset?: string;
  label?: string;
}

export interface DelegateUpdatePermissionsReq {
  permissions: string[];
  preset?: string;
}

export interface DelegateInviteRespondReq {
  accept: boolean;
}

export interface DelegateSettingsReq {
  require_acceptance: boolean;
  max_delegates: number;
  default_preset?: string;
  delegate_tag_enabled: boolean;
  delegate_tag_format: string;
}

export interface DelegateOut {
  delegate_id: string;
  creator_id: string;
  permissions: string[];
  preset?: string;
  status: string;
  label: string;
  show_delegate_tag: boolean;
  delegate_tag_format: string;
  invited_at: number;
  accepted_at: number;
  updated_at: number;
}

export interface ManagedCreatorOut {
  creator_id: string;
  permissions: string[];
  preset?: string;
  status: string;
  label: string;
  accepted_at: number;
}

export interface DelegateSettingsOut {
  require_acceptance: boolean;
  max_delegates: number;
  default_preset?: string;
  delegate_tag_enabled: boolean;
  delegate_tag_format: string;
}

export interface DelegateAuditOut {
  event_id: string;
  actor_id: string;
  actor_type: string;
}

// -- Syndicates (SYND-001) --

export interface SyndicateOut {
  syndicate_id: string;
  name: string;
  description: string;
  admin_user_id: string;
  status: string;
  member_count: number;
  created_at: number;
  updated_at: number;
  members: SyndicateMemberOut[];
}

export interface SyndicateMemberOut {
  user_id: string;
  display_name: string;
  role: string;
  joined_at: number;
}

export interface SyndicateInviteOut {
  syndicate_id: string;
  syndicate_name: string;
  user_id: string;
  invited_by: string;
  invited_at: number;
  status: string;
}

export interface SyndicateRequestOut {
  syndicate_id: string;
  user_id: string;
  display_name: string;
  requested_at: number;
  message: string;
  status: string;
}

export interface SyndicateAuditOut {
  event_id: string;
  actor_id: string;
  action: string;
  target_id: string;
  details?: Record<string, unknown>;
  ts: number;
}

export interface PermissionPresetOut {
  key: string;
  label: string;
  permissions: string[];
}

export interface SyndicateUserEntry {
  syndicate_id: string;
  syndicate_name: string;
  role: string;
  joined_at: number;
}

// ---------------------------------------------------------------------------
// Bot Framework (BOT-001)
// ---------------------------------------------------------------------------

export interface ChatBot {
  bot_id: string;
  creator_id: string;
  name: string;
  avatar_url?: string;
  description?: string;
  personality: "friendly" | "professional" | "casual" | "custom";
  custom_personality?: string;
  status: "active" | "paused" | "disabled";
  trigger_config?: BotTriggerConfig;
  created_at: number;
  updated_at: number;
  message_count: number;
}

export interface BotTriggerConfig {
  triggers: BotTrigger[];
  priority_order: string[];
}

export interface BotTrigger {
  type: "keyword" | "first_message" | "mention" | "all_messages" | "idle" | "scheduled";
  keywords?: string[];
  response_template_id?: string;
  idle_minutes?: number;
  cron?: string;
}

export interface BotAssignment {
  bot_id: string;
  target_type: "conversation" | "broadcast" | "all_dms" | "all_groups" | "all_broadcasts";
  target_id?: string;
  created_at: number;
  sk: string;
}

export interface BotStats {
  message_count: number;
  last_active_at?: number;
  assignment_count: number;
}

// -- User Groups (GROUP-001) --

export interface UserGroup {
  group_id: string;
  name: string;
  description: string;
  topic?: string;
  visibility: "public" | "private";
  status: "active" | "dissolved";
  admin_user_id: string;
  cover_image_url?: string;
  member_count: number;
  created_at: number;
  updated_at: number;
  my_role?: "admin" | "moderator" | "member";
}

export interface GroupMember {
  user_id: string;
  role: "admin" | "moderator" | "member";
  status: "active" | "invited" | "pending_approval";
  display_name: string;
  joined_at?: number;
  promoted_at?: number;
}

export interface GroupListOut {
  groups: UserGroup[];
  cursor?: string;
  has_more: boolean;
}

export interface GroupMemberListOut {
  members: GroupMember[];
  count: number;
}

// ─── SSH Key Manager (INFRA-002) ─────────────────────────────────

export interface SshKeyOut {
  key_id: string;
  label: string;
  key_type: string;
  key_bits: number;
  public_key_openssh: string;
  public_key_fingerprint: string;
  passphrase_protected: boolean;
  created_at: number;
  last_used_at: number;
  associated_hosts: string[];
  use_count: number;
}

export interface SshKeyListOut {
  keys: SshKeyOut[];
  count: number;
}

export interface PublicKeyOut {
  key_id: string;
  public_key_openssh: string;
  public_key_fingerprint: string;
}

export interface GenerateSshKeyIn {
  label: string;
  key_type?: "rsa" | "ed25519";
  key_bits?: number;
}

export interface UploadSshKeyIn {
  label: string;
  private_key_pem: string;
  passphrase?: string;
}

// --- Ad Creatives (ADS-002) ---

export interface AdCreative {
  creative_id: string;
  campaign_id: string;
  account_id: string;
  format: "image" | "video" | "native_post";
  title: string;
  headline?: string | null;
  body_text?: string | null;
  cta_text?: string | null;
  cta_url?: string | null;
  image_url?: string | null;
  video_url?: string | null;
  thumbnail_url?: string | null;
  alt_text?: string | null;
  width?: number | null;
  height?: number | null;
  duration_seconds?: number | null;
  skip_after_seconds: number;
  rotation_weight: number;
  status: "draft" | "pending_review" | "approved" | "rejected" | "archived";
  review_notes?: string | null;
  reviewed_by?: string | null;
  promo_code_id?: string | null;
  affiliate_link_id?: string | null;
  created_at: number;
  updated_at: number;
}
