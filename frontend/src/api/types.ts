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

// ─── Activity Feed (SOC-003) ───────────────────────────────────

export interface ActivityItem {
  activity_id: string;
  actor_id: string;
  activity_type: string;
  target_type: string;
  target_id: string;
  metadata: Record<string, unknown>;
  created_at: number;
  read: boolean;
}

export interface ActivityFeedPageResponse {
  items: ActivityItem[];
  next_cursor: string | null;
  total_unread: number;
}

export interface UnreadCountResponse {
  count: number;
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

// ── Billing Disputes (BILLING-001) ──────────────────────────────────────────
export interface DisputeFileIn {
  transaction_entry_id?: string | null;
  amount_cents: number;
  currency?: string;
  reason: string;
  provider?: string;
}

export interface DisputeOut {
  dispute_id: string;
  provider: string;
  provider_dispute_id?: string | null;
  user_id?: string | null;
  amount_cents: number;
  currency: string;
  reason: string;
  status: string;
  evidence_submitted: boolean;
  evidence_text?: string | null;
  resolution?: string | null;
  admin_notes?: string | null;
  transaction_entry_id?: string | null;
  created_at: number;
  updated_at?: number | null;
  deadline_at?: number | null;
}

export interface DisputeRespondIn {
  evidence_text: string;
  evidence_files?: string[];
}

export interface DisputeResolveIn {
  resolution: "won" | "lost" | "accepted";
  notes?: string;
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

// SHOP-003: Cart abandonment
export interface CartAbandonmentStatus {
  cart_id: string;
  status: string;
  last_activity_at: number;
  abandoned_at: number;
  reminder_count: number;
  is_abandoned: boolean;
}

export interface CartAbandonmentStats {
  total_open: number;
  total_abandoned: number;
  total_purchased: number;
  total_carts: number;
  abandonment_rate: number;
}

export interface CartAbandonmentSweepResult {
  scanned: number;
  reminded: number;
  expired: number;
  threshold_hours: number;
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
// ─── BCAST-010: Broadcast Newsfeed Promotion ──────────────────────

export interface BroadcastPromoLink {
  broadcast_id: string;
  post_id: string;
  owner_user_id: string;
  promoted_at: number;
  last_synced_status: string;
  removed: boolean;
}

export interface BroadcastPromoLiveItem {
  broadcast_id: string;
  post_id: string;
  title: string;
  owner_user_id: string;
  promoted_at: number;
}

export interface BroadcastPromoLinkResponse {
  link: BroadcastPromoLink;
}

export interface BroadcastPromoLiveResponse {
  items: BroadcastPromoLiveItem[];
}

export interface BroadcastPromoDeleteResponse {
  ok: boolean;
}

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
  // ADS-013: sponsored content / FTC disclosure (set server-side, immutable)
  sponsored_by?: string | null;
  deal_id?: string | null;
  ftc_disclosure?: string | null;
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
  /** FEED-007: aggregate count of viewers who marked this post interesting */
  interesting_count?: number;
  /** FEED-007: whether the current viewer marked this post interesting */
  is_interesting?: boolean;
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

  /** ADS-005: Sponsored post fields */
  is_sponsored?: boolean;
  sponsor_account_id?: string;
  sponsor_label?: string;
  headline?: string | null;
  cta_text?: string | null;
  cta_url?: string | null;
  impression_url?: string;
  click_url?: string;
  creative_id?: string;
  campaign_id?: string;
  comments_enabled?: boolean;
  allow_ads_near?: boolean;

  /** PWA-005: Offline queue metadata — only present for locally-queued posts */
  __offline?: {
    queueId: string;
    status: "pending" | "sending" | "failed";
    error?: string;
    enqueuedAt: number;
  };
}

// GROUP-001: User Groups
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

// GROUP-002: Group Feed
export interface GroupFeedPost extends FeedPost {
  group_id: string;
  audience: "public" | "members_only";
  pinned: boolean;
  pinned_at?: number;
  pinned_by?: string;
}

export interface GroupFeedResponse {
  posts: GroupFeedPost[];
  cursor?: string;
  has_more: boolean;
}

/** ADS-005: Ad feedback request */
export interface AdFeedbackRequest {
  creative_id: string;
  campaign_id?: string;
  feedback_type: "hide" | "not_relevant" | "repetitive" | "offensive";
  reason?: string;
}


/** ADS-005: Why this ad response */
export interface WhyThisAdResponse {
  reason: string;
  categories: string[];
  note: string;
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
  status_description?: string;
  shipped_at?: number;
  delivered_at?: number;
  estimated_delivery?: string;
  carrier_events?: CarrierEvent[];
  last_carrier_check?: number;
  address?: Record<string, unknown>;
}

export interface CarrierTrackingView {
  txn_id: string;
  carrier?: string | null;
  tracking_number?: string | null;
  tracking_url?: string | null;
  status?: string | null;
  status_description?: string | null;
  estimated_delivery?: string | null;
  delivered_at?: number | null;
  carrier_events?: CarrierEvent[] | null;
  last_carrier_check?: number | null;
}

export interface CarrierPollResult {
  txn_id: string;
  polled: boolean;
  updated: boolean;
  old_status?: string | null;
  new_status?: string | null;
  reason: string;
}

export interface CarrierPollTransactionOut {
  poll: CarrierPollResult;
  tracking: CarrierTrackingView;
}

export interface CarrierPollNowOut {
  checked: number;
  updated: number;
  results: CarrierPollResult[];
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

// FIN-011: Collaboration Revenue Splitting
export interface CollabContentAssignIn {
  content_id: string;
  content_type: "vod" | "post" | "broadcast";
  title?: string;
}

export interface CollabContentItem {
  content_id: string;
  content_type: string;
  title: string;
  assigned_by: string;
  assigned_at: number;
  total_revenue_cents: number;
  split_count: number;
}

export interface CollabContentListOut {
  items: CollabContentItem[];
  collaboration_id: string;
}

export interface CollabSplitDistribution {
  user_id: string;
  amount_cents: number;
  percentage: number;
}

export interface CollabSplitRecord {
  split_id: string;
  content_id: string;
  content_type: string;
  gross_amount_cents: number;
  source: string;
  distributions: CollabSplitDistribution[];
  created_at: number;
  dispute_status?: string | null;
}

export interface CollabSplitHistoryOut {
  items: CollabSplitRecord[];
  next_cursor?: string | null;
}

export interface CollabContentSplitTriggerIn {
  content_id: string;
  amount_cents: number;
  source?: "tip" | "unlock" | "vod_purchase" | "subscription" | "sale";
  currency?: string;
}

export interface CollabDisputeIn {
  reason: string;
  proposed_split?: Record<string, number> | null;
}

export interface CollabDisputeResolveIn {
  resolution: string;
  accept: boolean;
}

export interface CollabDisputeOut {
  dispute_id: string;
  split_id: string;
  collaboration_id: string;
  filed_by: string;
  reason: string;
  proposed_split?: Record<string, number> | null;
  status: string;
  resolution: string;
  resolved_by: string;
  resolved_at: number;
  created_at: number;
}

export interface CollabDisputeListOut {
  items: CollabDisputeOut[];
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

// ─── License Revenue (LICENSE-003) ───────────────────────────────

export interface RevenueSummaryOut {
  total_cents: number;
  total_transactions: number;
  last_transaction_at?: number;
  currency: string;
}

export interface RevenueTransactionOut {
  txn_id: string;
  issued_license_id: string;
  content_id: string;
  counterparty_id: string;
  source_type: string;
  source_amount_cents: number;
  split_amount_cents: number;
  split_type: string;
  currency: string;
  created_at: number;
}

export interface RevenueListOut {
  summary: RevenueSummaryOut;
  transactions: RevenueTransactionOut[];
  next_cursor?: string;
}

export interface RevenueSplitPreviewOut {
  source_amount_cents: number;
  platform_fee_cents: number;
  revenue_share_cents: number;
  profit_share_cents: number;
  total_licensor_share_cents: number;
  licensee_net_cents: number;
}

export interface AdminRevenueEntryOut {
  txn_id: string;
  licensor_id: string;
  licensee_id: string;
  content_id: string;
  source_type: string;
  source_amount_cents: number;
  split_amount_cents: number;
  created_at: number;
}

export interface AdminRevenueListOut {
  transactions: AdminRevenueEntryOut[];
  next_cursor?: string;
}

// -- Delegate Management (DELEGATE-001) --

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
  require_acceptance?: boolean;
  max_delegates?: number;
  default_preset?: string;
  delegate_tag_enabled?: boolean;
  delegate_tag_format?: string;
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

// -- Chat Delegation (DELEGATE-002) --

export interface DelegatedSendMessageReq {
  text: string;
  reply_to_message_id?: string;
}

export interface DelegatedMessage {
  conversation_id: string;
  message_id: string;
  sender_id: string;
  created_at: number;
  kind: string;
  text?: string;
  is_encrypted: boolean;
  sent_by_delegate?: string;
  delegate_display_name?: string;
  delegate_tag?: string;
  delegate_cannot_decrypt?: boolean;
  reply_to_message_id?: string;
}

export interface DelegatedConversation {
  conversation_id: string;
  type: string;
  title?: string;
  created_at: number;
  last_message_at: number;
  last_message_preview?: string;
  participant_count: number;
  status: string;
  unread_count: number;
  participants: Array<Record<string, unknown>>;
}

export interface ChatDelegateAuditEntry {
  event_id: string;
  delegate_id: string;
  conversation_id: string;
  message_id: string;
  text_preview: string;
  delegate_display_name: string;
  created_at: number;
}

// -- Newsfeed Delegation (DELEGATE-003) --

export interface DelegatedPostCreateReq {
  text: string;
  image_url?: string;
  lock_price_cents?: number;
  tags?: string[];
  scheduled_at?: number;
}

export interface DelegatedPostEditReq {
  text?: string;
  image_url?: string;
  lock_price_cents?: number;
  tags?: string[];
}

export interface DraftApprovalReq {
  note?: string;
}

export interface CommentModerationReq {
  action: "hide" | "pin" | "unpin" | "delete";
}

export interface DelegatedPostOut {
  post_id: string;
  author_id: string;
  text: string;
  image_url?: string;
  lock_price_cents: number;
  tags: string[];
  status: string;
  posted_by_delegate?: string;
  delegate_display_name?: string;
  delegate_tag?: string;
  approval_status?: string;
  approval_note?: string;
  approved_at?: number;
  created_at: string;
  updated_at: string;
  view_count: number;
  like_count: number;
  comment_count: number;
}

export interface FeedAnalyticsOut {
  period: string;
  total_posts: number;
  total_views: number;
  total_likes: number;
  total_comments: number;
  engagement_rate: number;
  locked_post_revenue_cents: number;
  delegate_post_count: number;
  top_posts: Array<Record<string, unknown>>;
}

export interface FeedDelegateAuditEntry {
  event_id: string;
  delegate_id: string;
  delegate_display_name: string;
  action: string;
  target_id: string;
  details?: Record<string, unknown>;
  ts: number;
}

export interface FeedDelegationSettingsReq {
  require_post_approval?: boolean;
  allow_delegate_scheduling?: boolean;
  allow_delegate_locking?: boolean;
  delegate_tag_on_posts?: boolean;
  delegate_tag_format?: string;
}

export interface FeedDelegationSettingsOut {
  require_post_approval: boolean;
  allow_delegate_scheduling: boolean;
  allow_delegate_locking: boolean;
  delegate_tag_on_posts: boolean;
  delegate_tag_format: string;
}

// ─── Notification Engine (SOC-004) ──────────────────────────────

export interface NotificationOut {
  notification_id: string;
  notification_type: string;
  title: string;
  body: string;
  data: Record<string, unknown>;
  read: boolean;
  created_at: number;
  batch_key?: string | null;
  batch_count: number;
  batch_actors: string[];
}

export interface NotificationListResponse {
  items: NotificationOut[];
  next_cursor?: string | null;
  unread_count: number;
}

export interface MarkNotificationsReadReq {
  notification_ids: string[];
}

export interface SendNotificationReq {
  user_id: string;
  notification_type: string;
  title: string;
  body?: string;
  data?: Record<string, unknown>;
  batch_key?: string | null;
}

// ─── Call History (CALL-004) ─────────────────────────────────────

export interface CallRecordIn {
  caller_id: string;
  callee_id: string;
  call_type: "audio" | "video";
  duration_seconds: number;
  status: "completed" | "missed" | "declined" | "failed";
}

export interface CallRecordOut {
  call_id: string;
  caller_id: string;
  callee_id: string;
  call_type: string;
  duration_seconds: number;
  status: string;
  direction: string;
  created_at: number;
}

export interface CallHistoryResponse {
  items: CallRecordOut[];
  next_cursor?: string | null;
}

export interface CallStatsOut {
  total_calls: number;
  total_duration_seconds: number;
  calls_by_type: Record<string, number>;
  calls_by_status: Record<string, number>;
}

// ─── Risk Scoring (KYC-008) ────────────────────────────────────

export interface RiskFactorDetail {
  score: number;
  weight: number;
  weighted_score: number;
  raw_value: string;
  description: string;
}

export interface RiskScoreOut {
  score_id: string;
  case_id: string;
  user_sub: string;
  total_score: number;
  risk_tier: "low" | "medium" | "high" | "critical";
  factors: Record<string, RiskFactorDetail>;
  trigger: string;
  auto_action_taken: string;
  model_version: string;
  created_at: number;
  previous_score?: number | null;
  previous_tier?: string | null;
}

export interface RiskFactorOut {
  factor_name: string;
  score: number;
  weight: number;
  weighted_score: number;
  raw_value: string;
  description: string;
}

export interface RiskProfileOut {
  user_sub: string;
  latest_score: RiskScoreOut | null;
  history: RiskScoreOut[];
}

export interface RiskDistributionOut {
  distribution: Record<string, number>;
  total_scored: number;
  auto_approve_rate: number;
  auto_escalate_rate: number;
}

export interface RiskOverrideIn {
  score: number;
  reason: string;
}
// ─── Issued Licenses (LICENSE-002) ───────────────────────────────────────────

export interface IssuedLicenseOut {
  issued_license_id: string;
  content_id: string;
  content_type: string;
  licensor_id: string;
  licensor_display_name: string;
  licensee_id?: string | null;
  license_mode: string;
  status: string;
  profit_share_pct: number;
  fixed_cost_cents: number;
  revenue_share_pct: number;
  currency: string;
  title: string;
  thumbnail_url: string;
  created_at: number;
  updated_at: number;
  expires_at?: number | null;
}

export interface IssuedLicenseIndexItem {
  issued_license_id: string;
  content_id: string;
  licensee_id?: string | null;
  license_mode: string;
  status: string;
  created_at: number;
}

export interface HeldLicenseOut {
  issued_license_id: string;
  content_id: string;
  content_type: string;
  licensor_id: string;
  licensor_display_name: string;
  status: string;
  terms_snapshot: Record<string, number>;
}

export interface LibraryItemOut {
  content_id: string;
  content_type: string;
  licensor_id: string;
  licensor_display_name: string;
  title: string;
  thumbnail_url: string;
  profit_share_pct: number;
  fixed_cost_cents: number;
  created_at: number;
}

export interface LicenseCheckOut {
  has_license: boolean;
  issued_license_id?: string | null;
  license_mode?: string | null;
  terms?: Record<string, number> | null;
}

// ─── License Requests (LICENSE-004) ──────────────────────────────────────────

export interface LicenseTerms {
  profit_share_pct: number;
  fixed_cost_cents: number;
  revenue_share_pct: number;
}

export interface LicenseRequestOut {
  request_id: string;
  content_id: string;
  content_type: string;
  requester_id: string;
  requester_display_name: string;
  owner_id: string;
  owner_display_name: string;
  status: string;
  proposed_terms: LicenseTerms;
  counter_terms?: LicenseTerms | null;
  denial_reason: string;
  message: string;
  created_at: number;
  updated_at: number;
  expires_at: number;
}

export interface LicenseRequestApprovalOut {
  request: LicenseRequestOut;
  issued_license: IssuedLicenseOut | null;
}

export interface LicenseRequestListOut {
  items: LicenseRequestOut[];
  next_cursor?: string | null;
}

// -- Broadcast Delegation (DELEGATE-004) --

export interface BroadcastMuteReq {
  user_id: string;
  duration_seconds: number;
}

export interface BroadcastBanReq {
  user_id: string;
  reason?: string;
}

export interface BroadcastAnnouncementReq {
  text: string;
}

export interface BroadcastScheduleReq {
  title: string;
  scheduled_at: number;
  profile_id?: string;
}

export interface BroadcastModeratorOut {
  delegate_id: string;
  display_name: string;
  connected_at: number;
  status: string;
  actions_count: number;
}

export interface BroadcastBanOut {
  user_id: string;
  banned_by: string;
  banned_by_display_name: string;
  banned_at: number;
  reason: string;
}

export interface BroadcastModerationLogEntry {
  event_id: string;
  moderator_id: string;
  moderator_display_name: string;
  moderation_type: string;
  target_user_id?: string;
  target_message_id?: string;
  details?: Record<string, unknown>;
  ts: number;
}

// ─── Kubernetes Container Launcher (INFRA-004) ──────────────────────

export interface K8sLaunchPodIn {
  label: string;
  image: string;
  preset?: "small" | "medium" | "large" | "xlarge";
  ssh_key_id?: string;
  ttl_seconds?: number;
  env_vars?: Record<string, string>;
  template_id?: string;
}

export interface K8sPodOut {
  pod_id: string;
  k8s_pod_name: string;
  namespace: string;
  label: string;
  image: string;
  image_display_name: string;
  preset: string;
  cpu_millicores: number;
  memory_mb: number;
  status: string;
  pod_ip: string;
  service_hostname: string;
  ssh_port: number;
  ssh_key_id: string;
  host_id: string;
  created_at: number;
  started_at: number;
  terminated_at: number;
  ttl_seconds: number;
  expires_at: number;
  last_activity_at: number;
}

export interface K8sPodListOut {
  pods: K8sPodOut[];
  count: number;
}

export interface K8sPodLogsOut {
  pod_id: string;
  lines: string[];
}

export interface K8sImageInfo {
  image: string;
  display_name: string;
  os_type: string;
  username: string;
}

export interface K8sImageListOut {
  images: K8sImageInfo[];
}

export interface K8sPresetInfo {
  preset: string;
  cpu_millicores: number;
  memory_mb: number;
  cost_cents_per_min: number;
}

export interface K8sPresetListOut {
  presets: K8sPresetInfo[];
}

// ── KYC Tiered Verification (KYC-009) ─────────────────────────────

export interface TierHistoryEntry {
  from_tier: number;
  to_tier: number;
  changed_at: number;
  reason: string;
  actor_sub: string;
  case_id: string | null;
}

export interface TierDetails {
  user_sub: string;
  current_tier: number;
  tier_name: string;
  updated_at: number | null;
  history: TierHistoryEntry[];
}

export interface TierRequirements {
  target_tier: number;
  current_tier: number;
  met: string[];
  unmet: string[];
  eligible: boolean;
}

// -- Agent Worker Provisioning (AGENT-002) --

export interface CreateWorkerIn {
  label: string;
  agent_type: "coder" | "qa" | "reviewer" | "devops" | "custom";
  tool: "claude_code" | "codex" | "custom";
  compute_type: "ec2" | "k8s";
  instance_type: string;
  llm_key_id: string;
  repo_url?: string;
  branch_convention?: string;
  idle_timeout_seconds?: number;
  template_id?: string;
  custom_install_commands?: string[];
  custom_env_var?: string;
  custom_verify_command?: string;
}

export interface ProvisionStep {
  step: string;
  status: "running" | "done" | "error";
  ts: number;
  detail: string;
}

export interface Worker {
  worker_id: string;
  user_id: string;
  label: string;
  agent_type: string;
  tool: string;
  tool_version: string;
  compute_type: string;
  compute_instance_id: string;
  instance_type: string;
  llm_key_id: string;
  llm_provider: string;
  host_id: string;
  public_ip: string;
  worker_status: "provisioning" | "installing" | "ready" | "running" | "stopped" | "error" | "terminated";
  provision_log: ProvisionStep[];
  repo_url: string;
  branch_convention: string;
  idle_timeout_seconds: number;
  last_activity_at: number;
  created_at: number;
  started_at: number;
  stopped_at: number;
  terminated_at: number;
  template_id: string;
  error_message: string;
}

export interface WorkerList {
  workers: Worker[];
  count: number;
}

export interface ToolInfo {
  tool: string;
  display_name: string;
  description: string;
  install_time_seconds: number;
  required_provider: string;
}

export interface ToolListOut {
  tools: ToolInfo[];
}

export interface ComputeOption {
  compute_type: "ec2" | "k8s";
  instance_type: string;
  vcpu: number;
  memory_gb: number;
  cost_cents_per_min: number;
  startup_seconds: number;
}

export interface ComputeOptionListOut {
  options: ComputeOption[];
}

// ─── Ad Accounts & Campaigns (ADS-001) ──────────────────────────────

export interface AdAccount {
  account_id: string;
  owner_sub: string;
  company_name: string;
  billing_email: string;
  status: string;
  balance_cents: number;
  lifetime_spend_cents: number;
  created_at: number;
  updated_at: number;
}

export interface Campaign {
  campaign_id: string;
  account_id: string;
  name: string;
  objective: string;
  budget_cents: number;
  budget_type: string;
  daily_budget_cents: number;
  spent_today_cents: number;
  lifetime_spent_cents: number;
  status: string;
  created_at: number;
  updated_at: number;
}

// ─── Ad Billing (ADS-007) ───────────────────────────────────────────

export interface AdBillingEntry {
  entry_id: string;
  account_id: string;
  campaign_id: string;
  entry_type: string;
  amount_cents: number;
  state: string;
  reason: string;
  meta: Record<string, unknown>;
  created_at: number;
}

export interface AdInvoiceCampaignLine {
  campaign_id: string;
  impressions: number;
  clicks: number;
  conversions: number;
  total_cents: number;
}

export interface AdInvoice {
  account_id: string;
  month: string;
  campaigns: AdInvoiceCampaignLine[];
  total_charges_cents: number;
  total_deposits_cents: number;
  entry_count: number;
}

// ---------------------------------------------------------------------------
// Group Treasury (GROUP-004)
// ---------------------------------------------------------------------------

export interface TreasuryBalance {
  balance_cents: number;
  currency: string;
  total_contributed_cents: number;
  total_donated_cents: number;
  total_spent_cents: number;
  fundraising_goal_cents?: number | null;
}

export interface TreasuryLedgerEntry {
  entry_id: string;
  amount_cents: number;
  currency: string;
  direction: "credit" | "debit";
  reason: string;
  category: string;
  actor_user_id?: string;
  actor_display_name?: string;
  reference_id?: string;
  created_at: number;
}

export interface TreasuryLedgerResponse {
  entries: TreasuryLedgerEntry[];
  cursor?: string | null;
  has_more: boolean;
}

export interface Contributor {
  user_id: string;
  display_name: string;
  total_contributed_cents: number;
  contribution_count: number;
  first_contributed_at: number;
  last_contributed_at: number;
}

export interface ContributorListResponse {
  contributors: Contributor[];
  count: number;
}

export interface ContributeResponse {
  ok: boolean;
  balance_cents: number;
  personal_balance_cents: number;
  contribution_total_cents: number;
  ledger_entry_id: string;
}

export interface SpendResponse {
  ok: boolean;
  balance_cents: number;
  total_spent_cents: number;
  ledger_entry_id: string;
}

// -- Agent Orchestrator (AGENT-003) --

export interface TicketFilterConfig {
  types: string[];
  tags: string[];
  space_ids: string[];
  priorities: string[];
}

export type AgentState =
  | "idle"
  | "claiming"
  | "working"
  | "awaiting_feedback"
  | "completing"
  | "paused"
  | "error";

export interface AgentStatus {
  worker_id: string;
  agent_state: AgentState;
  current_ticket_id: string;
  current_ticket_title: string;
  tickets_completed: number;
  tickets_failed: number;
  heartbeat_at: number;
  last_activity_at: number;
  ticket_filter: TicketFilterConfig | null;
  loop_running: boolean;
}

export interface AgentClaim {
  ticket_id: string;
  worker_id: string;
  claimed_at: number;
  status: "active" | "released" | "completed" | "failed";
  checkpoint: string;
}

export interface EligibleTicket {
  ticket_id: string;
  title: string;
  priority: string;
  type: string;
  tags: string[];
  space_id: string;
  created_at: number;
}

export interface EligibleTicketsResponse {
  tickets: EligibleTicket[];
  count: number;
  filter_applied: TicketFilterConfig | null;
}

export interface CheckpointData {
  ticket_id: string;
  checkpoint: Record<string, unknown>;
  claimed_at: number;
}

// ── Ad Analytics (ADS-008) ────────────────────────────────────────────────

export interface AdAnalyticsSummary {
  impressions: number;
  clicks: number;
  ctr_pct: number;
  spend_cents: number;
  cpa_cents: number;
  effective_cpm_cents: number;
  completes: number;
  skips: number;
  completion_rate_pct: number;
  previous_period: { impressions: number; clicks: number; spend_cents: number };
  impressions_change_pct: number;
  clicks_change_pct: number;
  spend_change_pct: number;
  days: number;
}

export interface AdTimeSeriesPoint {
  date: string;
  impressions: number;
  clicks: number;
  spend_cents: number;
  completes: number;
  ctr_pct: number;
}

export interface AdBreakdownEntry {
  dimension_key: string;
  dimension: string;
  impressions: number;
  clicks: number;
  spend_cents: number;
  ctr_pct: number;
}

// ---------------------------------------------------------------------------
// Compute Cost Tracking (INFRA-005)
// ---------------------------------------------------------------------------

export interface ComputeBillingTickIn {
  resource_type: "ec2" | "k8s";
  resource_id: string;
  resource_label?: string;
  instance_type_or_preset: string;
  duration_minutes: number;
}

export interface ComputeBillingTickOut {
  ok: boolean;
  entry_id: string;
  amount_cents: number;
  wallet_balance_after: number;
  rate_cents_per_min: number;
  created_at: number;
}

export interface SpendingSummaryOut {
  month: string;
  total_cents: number;
  budget_cents: number;
  budget_pct: number;
  ec2_total_cents: number;
  k8s_total_cents: number;
  resource_count: number;
}

export interface BillingLedgerEntry {
  entry_id: string;
  resource_type: string;
  resource_id: string;
  resource_label: string;
  instance_type_or_preset: string;
  event: string;
  amount_cents: number;
  duration_minutes: number;
  rate_cents_per_min: number;
  wallet_balance_after: number;
  created_at: number;
}

export interface BillingLedgerOut {
  entries: BillingLedgerEntry[];
  count: number;
  cursor?: string;
}

export interface ResourceBreakdownEntry {
  resource_id: string;
  resource_label: string;
  resource_type: string;
  instance_type_or_preset: string;
  total_cents: number;
  total_minutes: number;
  status: string;
}

export interface ResourceBreakdownOut {
  resources: ResourceBreakdownEntry[];
  month: string;
}

export interface BudgetOut {
  budget_monthly_cents: number;
  alert_thresholds: number[];
  current_month_total_cents: number;
  current_month_pct: number;
}

export interface UpdateBudgetIn {
  budget_monthly_cents: number;
  alert_thresholds?: number[];
}

// -- Agent Fleet Management (AGENT-004) --

export interface WorkerSummary {
  worker_id: string;
  label: string;
  agent_type: string;
  tool: string;
  worker_status: string;
  agent_state: string;
  current_ticket_id: string;
  current_ticket_title: string;
  uptime_seconds: number;
  estimated_cost_cents: number;
  tickets_completed: number;
}

export interface FleetStatus {
  total_workers: number;
  status_counts: Record<string, number>;
  queue_depth: number;
  workers: WorkerSummary[];
}

export interface BulkActionResult {
  count: number;
  errors: Array<{ worker_id: string; error: string }>;
}

export interface Capacity {
  queue_by_type: Record<string, number>;
  workers_by_type: Record<string, number>;
  workers_by_state: Record<string, number>;
  recommended_action: string;
}

export interface WorkerTemplateIn {
  label: string;
  agent_type: string;
  tool: string;
  compute_type: string;
  instance_type: string;
  llm_key_id: string;
  repo_url?: string;
  branch_convention?: string;
  idle_timeout_seconds?: number;
  ticket_filter?: {
    types?: string[];
    tags?: string[];
    space_ids?: string[];
    priorities?: string[];
  };
}

export interface WorkerTemplate {
  template_id: string;
  label: string;
  agent_type: string;
  tool: string;
  compute_type: string;
  instance_type: string;
  llm_key_id: string;
  repo_url: string;
  branch_convention: string;
  idle_timeout_seconds: number;
  ticket_filter?: Record<string, unknown>;
  created_at: number;
}

export interface WorkerTemplateList {
  templates: WorkerTemplate[];
  count: number;
}

// -- Agent Memory & Context Injection (AGENT-005) --

export interface AgentIdentity {
  agent_type: string;
  identity_text: string;
  custom_instructions: string;
  updated_at: number;
}

export interface AgentIdentityUpdate {
  identity_text?: string;
  custom_instructions?: string;
}

export interface ProjectContext {
  repo_url: string;
  branch_convention: string;
  coding_standards: string;
  pr_template: string;
  test_framework: string;
  ci_commands: string;
  file_structure_notes: string;
  updated_at: number;
}

export interface ProjectContextUpdate {
  repo_url?: string;
  branch_convention?: string;
  coding_standards?: string;
  pr_template?: string;
  test_framework?: string;
  ci_commands?: string;
  file_structure_notes?: string;
}

export interface MemoryEntry {
  memory_id: string;
  category: string;
  title: string;
  content: string;
  ticket_id: string;
  importance: number;
  token_count: number;
  created_at: number;
  summarized: boolean;
  summary: string;
}

export interface MemoryEntryCreate {
  category: "learning" | "decision" | "pattern" | "error" | "custom";
  title: string;
  content: string;
  ticket_id?: string;
  importance?: number;
}

export interface MemoryEntryUpdate {
  title?: string;
  content?: string;
  importance?: number;
}

export interface MemoryListOut {
  entries: MemoryEntry[];
  count: number;
  total_tokens: number;
}

export interface FullContextOut {
  context_text: string;
  total_tokens: number;
  sections: string[];
}

export interface MemoryExport {
  worker_id: string;
  exported_at: number;
  identity: AgentIdentity | null;
  project_context: ProjectContext | null;
  memories: MemoryEntry[];
}

export interface MemoryImportIn {
  identity?: Record<string, unknown>;
  project_context?: Record<string, unknown>;
  memories?: Record<string, unknown>[];
}

export interface MemoryImportOut {
  identity: boolean;
  project: boolean;
  memories: number;
}

export interface MemoryTemplate {
  agent_type: string;
  identity_text: string;
  description: string;
}

// -- Agent Feedback & Terminal Monitoring (AGENT-006) --

export interface FeedbackRequest {
  request_id: string;
  worker_id: string;
  ticket_id: string;
  feedback_status: string;
  question: string;
  terminal_context: string;
  detected_pattern: string;
  response_text: string;
  responded_at: number;
  timeout_at: number;
  timeout_action: string;
  created_at: number;
  user_id: string;
}

export interface FeedbackListOut {
  requests: FeedbackRequest[];
  count: number;
  pending_count: number;
}

export interface CreateFeedbackRequestIn {
  ticket_id: string;
  question: string;
  terminal_context?: string;
  detected_pattern?: string;
  timeout_seconds?: number;
  timeout_action?: string;
}

export interface FeedbackRespondIn {
  response_text: string;
}

export interface TerminalOutputOut {
  worker_id: string;
  output: string;
  char_count: number;
}

export interface TerminalSearchOut {
  worker_id: string;
  keyword: string;
  matches: string[];
  match_count: number;
}

export interface PatternConfigOut {
  agent_type: string;
  completion: string[];
  feedback_needed: string[];
  error: string[];
}

export interface PatternUpdateIn {
  completion?: string[];
  feedback_needed?: string[];
  error?: string[];
}

export interface PatternTestIn {
  patterns: Record<string, string[]>;
  sample_text: string;
}

export interface PatternTestOut {
  matches: Array<{ signal: string; pattern: string; match: string }>;
  match_count: number;
}

// ─── Agent PR & Ticket Integration (AGENT-007) ──────────────────

export interface AgentPr {
  pr_id: string;
  worker_id: string;
  ticket_id: string;
  repo_url: string;
  pr_url: string;
  pr_number: number;
  branch: string;
  title: string;
  description: string;
  files_changed: string[];
  commit_count: number;
  status: string;
  created_at: number;
  merged_at: number;
  user_id: string;
}

export interface AgentPrListOut {
  prs: AgentPr[];
  count: number;
}

export interface AgentPrCreateIn {
  ticket_id: string;
  repo_url?: string;
  branch?: string;
  title?: string;
  description?: string;
  files_changed?: string[];
  method?: "cli" | "api";
}

export interface WorkSummary {
  ticket_id: string;
  text: string;
  files_changed: string[];
  decisions: string[];
  test_results: Record<string, number>;
}

export interface AgentCompletion {
  ticket_id: string;
  summary: WorkSummary;
  pr: AgentPr | null;
  new_status: string;
  next_agent_type: string;
}

export interface StatusFlowConfig {
  agent_type: string;
  on_claim: string;
  on_working: string;
  on_complete: string;
  on_pr_created: string;
  on_pr_merged: string;
  next_agent_type: string;
}

export interface StatusFlowUpdateIn {
  on_claim?: string;
  on_working?: string;
  on_complete?: string;
  on_pr_created?: string;
  on_pr_merged?: string;
  next_agent_type?: string;
}

// ─── Admin Compute Dashboard (INFRA-012) ─────────────────────────

export interface AdminInstance {
  instance_id: string;
  user_sub: string;
  label: string;
  instance_type: string;
  ami_name: string;
  status: string;
  public_ip: string;
  created_at: number;
  last_activity_at: number;
  auto_terminate_after: number;
}

export interface AdminInstanceListOut {
  instances: AdminInstance[];
  count: number;
  cursor: string | null;
}

export interface AdminPod {
  pod_id: string;
  user_sub: string;
  label: string;
  image: string;
  preset: string;
  status: string;
  pod_ip: string;
  created_at: number;
  ttl_seconds: number;
  expires_at: number;
}

export interface AdminPodListOut {
  pods: AdminPod[];
  count: number;
  cursor: string | null;
}

export interface ForceTerminateReq {
  reason?: string;
}

export interface PlatformSpendingOut {
  month: string;
  total_cents: number;
  ec2_total_cents: number;
  k8s_total_cents: number;
  active_user_count: number;
  active_instance_count: number;
  active_pod_count: number;
}

export interface PerUserSpendingEntry {
  user_sub: string;
  total_cents: number;
  ec2_cents: number;
  k8s_cents: number;
  instance_count: number;
  pod_count: number;
}

export interface PerUserSpendingOut {
  users: PerUserSpendingEntry[];
  month: string;
}

export interface InstanceTypeStatEntry {
  instance_type: string;
  running_count: number;
  total_launched: number;
}

export interface InstanceTypeStatsOut {
  stats: InstanceTypeStatEntry[];
}

export interface ComputeQuota {
  user_sub: string;
  max_ec2_instances: number;
  max_k8s_pods: number;
  max_monthly_spend_cents: number;
  allowed_instance_types: string[];
  allowed_k8s_presets: string[];
  is_custom: boolean;
  updated_at: number;
  updated_by: string;
  notes: string;
}

export interface SetQuotaReq {
  max_ec2_instances: number;
  max_k8s_pods: number;
  max_monthly_spend_cents: number;
  allowed_instance_types: string[];
  allowed_k8s_presets: string[];
  notes?: string;
}

// ─── Coder Agent (AGENT-008) ───────────────────────────────────

export interface CoderConfig {
  repo_url: string;
  repo_branch_base: string;
  branch_pattern: string;
  test_commands: string[];
  test_timeout_seconds: number;
  test_retry_limit: number;
  pr_template: string;
  pr_base_branch: string;
  skill_level: "junior" | "mid" | "senior";
  max_ticket_time_seconds: number;
  complexity_labels?: Record<string, string[]>;
  coding_tool: "claude_code" | "codex";
  coding_tool_model?: string | null;
  pre_commands?: string[] | null;
  post_commands?: string[] | null;
  file_exclude_patterns?: string[] | null;
  updated_at?: number | null;
}

export interface CoderConfigIn {
  repo_url: string;
  repo_branch_base?: string;
  branch_pattern?: string;
  test_commands: string[];
  test_timeout_seconds?: number;
  test_retry_limit?: number;
  pr_template?: string;
  pr_base_branch?: string;
  skill_level?: "junior" | "mid" | "senior";
  max_ticket_time_seconds?: number;
  complexity_labels?: Record<string, string[]>;
  coding_tool?: "claude_code" | "codex";
  coding_tool_model?: string | null;
  pre_commands?: string[] | null;
  post_commands?: string[] | null;
  file_exclude_patterns?: string[] | null;
}

export interface CoderConfigValidation {
  valid: boolean;
  errors: string[];
}

export interface CoderOutput {
  branch_name: string;
  pr_url: string;
  pr_number: number;
  files_changed: string[];
  files_added: string[];
  files_deleted: string[];
  insertions: number;
  deletions: number;
  test_results: Array<{
    command: string;
    exit_code: number;
    duration_seconds: number;
    stdout_tail?: string;
    stderr_tail?: string;
  }>;
  test_retry_count: number;
  total_duration_seconds: number;
  escalated: boolean;
  escalation_reason?: string | null;
}

export interface CoderMetrics {
  completed_count: number;
  avg_duration_seconds: number;
  failure_rate: number;
  escalation_rate: number;
  tickets_by_skill_level: Record<string, number>;
  period_start: number;
  period_end: number;
}

export interface EligibleTicket {
  ticket_id: string;
  subject: string;
  labels: string[];
  complexity?: string | null;
  estimated_effort_hours?: number | null;
  created_at: number;
}

export interface EligibleTicketsResult {
  tickets: EligibleTicket[];
  count: number;
}

export interface CoderWorkflowStep {
  step_id: number;
  type: string;
  command?: string | null;
  timeout_seconds: number;
  on_failure: string;
}

export interface CoderWorkflowPreview {
  steps: CoderWorkflowStep[];
  branch_name: string;
  total_timeout_seconds: number;
}

// --- QA Agent (AGENT-009) ---

export interface QaConfig {
  test_framework: "playwright" | "cypress" | "pytest";
  browser: "chromium" | "firefox" | "webkit";
  test_dir: string;
  test_file_pattern: string;
  test_run_command: string;
  test_run_specific_command: string;
  regression_scope: "full" | "affected" | "none";
  regression_command: string;
  screenshot_enabled: boolean;
  screenshot_on_failure: boolean;
  screenshot_s3_prefix: string;
  visual_diff_threshold: number;
  max_test_time_seconds: number;
  flaky_retry_count: number;
  bug_ticket_space_id?: string | null;
  pr_review_enabled: boolean;
  coding_tool: "claude_code" | "codex";
  coding_tool_model?: string | null;
  updated_at?: number | null;
}

export interface QaConfigIn {
  test_framework?: "playwright" | "cypress" | "pytest";
  browser?: "chromium" | "firefox" | "webkit";
  test_dir?: string;
  test_file_pattern?: string;
  test_run_command?: string;
  test_run_specific_command?: string;
  regression_scope?: "full" | "affected" | "none";
  regression_command?: string;
  screenshot_enabled?: boolean;
  screenshot_on_failure?: boolean;
  screenshot_s3_prefix?: string;
  visual_diff_threshold?: number;
  max_test_time_seconds?: number;
  flaky_retry_count?: number;
  bug_ticket_space_id?: string | null;
  pr_review_enabled?: boolean;
  coding_tool?: "claude_code" | "codex";
  coding_tool_model?: string | null;
}

export interface QaConfigValidation {
  valid: boolean;
  errors: string[];
}

// --- Solution Architect Agent (AGENT-011) ---

export interface ArchitectConfig {
  repo_url: string;
  repo_branch: string;
  reference_docs: string[];
  scan_paths: string[];
  ticket_template: string;
  architecture_guidelines: string;
  tech_stack_constraints?: Record<string, string> | null;
  naming_conventions?: Record<string, string> | null;
  max_tickets_per_feature: number;
  target_ticket_space_id?: string | null;
  complexity_estimation?: Record<string, number> | null;
  coding_tool: "claude_code" | "codex";
  coding_tool_model?: string | null;
  max_analysis_time_seconds: number;
  require_design_review: boolean;
  ticket_spec_style: "full" | "compact";
  updated_at?: number | null;
}

export interface ArchitectConfigIn {
  repo_url: string;
  repo_branch?: string;
  reference_docs: string[];
  scan_paths: string[];
  ticket_template?: string;
  architecture_guidelines?: string;
  tech_stack_constraints?: Record<string, string> | null;
  naming_conventions?: Record<string, string> | null;
  max_tickets_per_feature?: number;
  target_ticket_space_id?: string | null;
  complexity_estimation?: Record<string, number> | null;
  coding_tool?: "claude_code" | "codex";
  coding_tool_model?: string | null;
  max_analysis_time_seconds?: number;
  require_design_review?: boolean;
  ticket_spec_style?: "full" | "compact";
}

export interface ArchitectConfigValidation {
  valid: boolean;
  errors: string[];
}

// ─── DevOps/SRE Agent (AGENT-010) ───────────────────────────────────

export interface EnvironmentConfig {
  name: string;
  requires_approval: boolean;
  deploy_commands: string[];
  rollback_commands: string[];
  health_check_urls: string[];
  health_check_timeout_seconds: number;
  smoke_test_command?: string | null;
  rollback_window_seconds: number;
  env_vars?: Record<string, string> | null;
}

export interface DevOpsMonitoringEndpoint {
  name: string;
  url: string;
  metric_type: string;
  threshold: number;
}

export interface DevOpsRunbook {
  trigger_label: string;
  name: string;
  steps: string[];
}

export interface DevOpsConfig {
  environments: EnvironmentConfig[];
  deploy_ticket_labels: string[];
  infra_ticket_labels: string[];
  incident_ticket_labels: string[];
  auto_deploy_on_qa_approved: boolean;
  coding_tool: "claude_code" | "codex";
  max_operation_time_seconds: number;
  incident_space_id?: string | null;
  monitoring_endpoints?: DevOpsMonitoringEndpoint[] | null;
  runbooks?: DevOpsRunbook[] | null;
}

export interface DevOpsConfigIn {
  environments: EnvironmentConfig[];
  deploy_ticket_labels?: string[];
  infra_ticket_labels?: string[];
  incident_ticket_labels?: string[];
  auto_deploy_on_qa_approved?: boolean;
  coding_tool?: "claude_code" | "codex";
  max_operation_time_seconds?: number;
  incident_space_id?: string | null;
  monitoring_endpoints?: DevOpsMonitoringEndpoint[] | null;
  runbooks?: DevOpsRunbook[] | null;
}

export interface DevOpsConfigResult {
  type_id: string;
  devops_config: DevOpsConfig;
  updated_at: number;
}

export interface DevOpsConfigValidation {
  valid: boolean;
  errors: string[];
}

export interface QaScreenshot {
  name: string;
  presigned_url: string;
  step: string;
  status: "pass" | "fail";
}

export interface QaScreenshotsResult {
  screenshots: QaScreenshot[];
}

export interface QaOutput {
  verdict: "pass" | "fail" | "flaky" | "error";
  pr_url: string;
  pr_branch: string;
  ticket_id: string;
  acceptance_criteria_count: number;
  new_tests_written: number;
  new_test_file: string;
  new_tests_pass_count: number;
  new_tests_fail_count: number;
  regression_tests_run: number;
  regression_tests_pass: number;
  regression_tests_fail: number;
  regression_failures: string[];
  screenshots: Array<{ name: string; s3_key: string; step: string; status: string }>;
  bug_ticket_ids: string[];
  pr_review_action: "approved" | "changes_requested" | "none";
  total_duration_seconds: number;
  flaky_tests: string[];
}

export interface QaReport {
  run_id: string;
  verdict: string;
  report_markdown: string;
  generated_at: number;
}

export interface QaMetrics {
  tested_count: number;
  pass_rate: number;
  bugs_found_count: number;
  avg_duration_seconds: number;
  flaky_test_rate: number;
}

export interface DevOpsHealthCheckResult {
  url: string;
  status_code: number;
  response_time_ms: number;
  healthy: boolean;
}

export interface DevOpsSmokeTestResult {
  command: string;
  exit_code: number;
  passed: boolean;
}

export interface DevOpsOutput {
  deployment_id: string;
  ticket_id: string;
  environment: string;
  operation_type: "deployment" | "infrastructure" | "incident_response" | "runbook";
  status: "success" | "failed" | "rolled_back" | "awaiting_approval" | "rejected" | "executing";
  version_deployed?: string | null;
  steps_total: number;
  steps_completed: number;
  health_check_results: DevOpsHealthCheckResult[];
  smoke_test_result?: DevOpsSmokeTestResult | null;
  rollback_executed: boolean;
  rollback_success?: boolean | null;
  incident_ticket_id?: string | null;
  total_duration_seconds: number;
  approval_received_at?: number | null;
  monitoring_snapshot?: Record<string, unknown> | null;
}

export interface DeploymentLogStep {
  step_number: number;
  step_type: string;
  command: string;
  exit_code?: number | null;
  stdout_tail: string;
  stderr_tail: string;
  started_at: number;
  completed_at: number;
  duration_seconds: number;
  status: "pending" | "running" | "success" | "failed" | "skipped" | "rolled_back";
}

export interface DeploymentLog {
  deployment_id: string;
  environment: string;
  steps: DeploymentLogStep[];
}

export interface DevOpsMetrics {
  deployment_frequency: number;
  success_rate: number;
  mttr_seconds: number;
  rollback_rate: number;
  incidents_count: number;
  period_start: number;
  period_end: number;
}

export interface QaEligibleTicket {
  ticket_id: string;
  subject: string;
  status: string;
  pr_url?: string | null;
  pr_branch?: string | null;
  created_at: number;
  labels: string[];
}

export interface QaEligibleTicketsResult {
  tickets: QaEligibleTicket[];
  count: number;
}

export interface QaWorkflowStep {
  step_id: number;
  type: string;
  command?: string | null;
  timeout_seconds: number;
  on_failure: string;
}

export interface DevOpsEligibleTicket {
  ticket_id: string;
  subject: string;
  labels: string[];
  operation_type: string;
  status: string;
  created_at: number;
}

export interface DevOpsEligibleTicketsResult {
  tickets: DevOpsEligibleTicket[];
  count: number;
}

export interface DevOpsDeploymentRow {
  run_id: string;
  agent_type_id: string;
  deployment_id: string;
  ticket_id: string;
  environment: string;
  status: string;
  version_deployed?: string | null;
  total_duration_seconds: number;
  created_at: number;
}

export interface DevOpsDeploymentsResult {
  deployments: DevOpsDeploymentRow[];
  count: number;
}

export interface DevOpsWorkflowStep {
  step_id: number;
  type: string;
  command?: string | null;
  timeout_seconds: number;
  on_failure: string;
}

export interface QaWorkflowPreview {
  steps: QaWorkflowStep[];
  new_test_file: string;
  pr_branch: string;
  total_timeout_seconds: number;
}
export interface DevOpsWorkflowPreview {
  steps: DevOpsWorkflowStep[];
  environment: string;
  operation_type: string;
  requires_approval: boolean;
  total_timeout_seconds: number;
}

export interface DeploymentApproval {
  run_id: string;
  deployment_id: string;
  approval_status: "approved" | "rejected";
  approved_by: string;
  approved_at: number;
  notes?: string | null;
}
export interface ArchitectEligibleTicket {
  ticket_id: string;
  subject: string;
  labels: string[];
  status: string;
  created_at: number;
}

export interface ArchitectEligibleTicketsResult {
  tickets: ArchitectEligibleTicket[];
  count: number;
}

export interface DevTicketSummary {
  ticket_id: string;
  subject: string;
  complexity: string;
  estimated_hours: number;
  order: number;
  depends_on: string[];
  ticket_type?: string;
}

export interface Decomposition {
  feature_ticket_id: string;
  decomposition_summary: string;
  total_tickets_created: number;
  total_estimated_hours: number;
  dependency_graph: Record<string, string[]>;
  tickets: DevTicketSummary[];
}

export interface DevTicketListResult {
  tickets: DevTicketSummary[];
  count: number;
}

export interface DependencyGraphNode {
  id: string;
  subject: string;
  complexity: string;
  order: number;
  status?: string;
}

export interface DependencyGraphEdge {
  from: string;
  to: string;
}

export interface DependencyGraph {
  nodes: DependencyGraphNode[];
  edges: DependencyGraphEdge[];
}

export interface ArchitectOutput {
  feature_ticket_id: string;
  decomposition_summary: string;
  tickets_created: DevTicketSummary[];
  total_tickets: number;
  total_estimated_hours: number;
  dependency_graph: Record<string, string[]>;
  codebase_analysis: {
    files_scanned: number;
    patterns_found: string[];
    existing_related_files: string[];
  };
  design_decisions: Array<{
    decision: string;
    rationale: string;
    alternatives_considered: string[];
  }>;
  feedback_requested: boolean;
  feedback_response?: string | null;
  total_duration_seconds: number;
}

export interface ArchitectWorkflowStep {
  step_id: number;
  type: string;
  command?: string | null;
  timeout_seconds: number;
  on_failure: string;
}

export interface ArchitectWorkflowPreview {
  steps: ArchitectWorkflowStep[];
  feature_ticket_id: string;
  require_design_review: boolean;
  total_timeout_seconds: number;
}

export interface ArchitectMetrics {
  features_decomposed: number;
  avg_tickets_per_feature: number;
  avg_hours_per_feature: number;
  decomposition_rate: number;
  period_start: number;
  period_end: number;
}

// --- Documentation Agent (AGENT-014) ---

export interface DocCoverageRecord {
  doc_path: string;
  doc_type: "api" | "architecture" | "user_guide" | "adr" | "readme" | "inline";
  source_refs: string[];
  coverage_score: number;
  is_stale: boolean;
  stale_since?: number;
  last_verified: number;
  last_updated: number;
  created_at: number;
}

export interface DocCoverageDetails {
  docs: DocCoverageRecord[];
  count: number;
}

export interface DocTypeSummary {
  count: number;
  avg_coverage: number;
  stale_count: number;
}

export interface DocCoverageSummary {
  overall_coverage: number;
  total_docs: number;
  stale_docs: number;
  by_type: Record<string, DocTypeSummary>;
}

export interface FreshnessCheckResult {
  total: number;
  stale: number;
  fresh: number;
  stale_docs: Array<{
    doc_path: string;
    doc_type: string;
    changed_sources: string[];
    stale_since: number;
  }>;
  checked_at: number;
}

export interface StaleDocsList {
  docs: DocCoverageRecord[];
  count: number;
}

export interface PrImpactAssessment {
  docs_to_update: DocCoverageRecord[];
  uncovered_files: string[];
  impact_level: "none" | "low" | "medium" | "high";
}

export interface DocTemplate {
  template_id: string;
  name: string;
  doc_type: string;
  template_body: string;
  required_sections: string[];
  created_at: number;
}

export interface DocTemplatesList {
  templates: DocTemplate[];
  count: number;
}

export interface DocTemplateIn {
  name: string;
  doc_type: "api" | "architecture" | "user_guide" | "adr" | "readme";
  template_body: string;
  required_sections: string[];
}

export interface DocAgentConfig {
  trigger_on_pr_merge: boolean;
  freshness_check_frequency: "hourly" | "daily" | "weekly";
  freshness_check_hour_utc: number;
  doc_format: string;
  doc_root: string;
  min_coverage_threshold: number;
  create_tickets_for_inline_docs: boolean;
  inline_doc_target_agent_type: string;
  ignored_paths: string[];
}

export interface RegisterDocBody {
  doc_path: string;
  doc_type: "api" | "architecture" | "user_guide" | "adr" | "readme" | "inline";
  source_refs: string[];
  coverage_score: number;
}

// ---------------------------------------------------------------------------
// Product Manager Agent (AGENT-013)
// ---------------------------------------------------------------------------

export type PmIdeaCategory =
  | "ux"
  | "feature"
  | "performance"
  | "integration"
  | "monetization"
  | "accessibility";

export type PmIdeaPriority = "critical" | "high" | "medium" | "low";

export type PmIdeaStatus = "pending" | "approved" | "rejected" | "archived";

export interface FeatureIdeaEvidence {
  type: string;
  url?: string;
  description: string;
}

export interface FeatureIdeaCompetitorRef {
  url: string;
  feature: string;
  notes: string;
}

export interface FeatureIdea {
  idea_id: string;
  user_id: string;
  agent_id: string;
  title: string;
  description: string;
  category: PmIdeaCategory;
  priority_suggestion: PmIdeaPriority;
  user_impact: string;
  mockup_description?: string;
  evidence?: FeatureIdeaEvidence[];
  competitor_refs?: FeatureIdeaCompetitorRef[];
  support_ticket_refs?: string[];
  status: PmIdeaStatus;
  rejection_reason?: string;
  created_ticket_id?: string;
  created_at: number;
  reviewed_at?: number;
}

export interface FeatureIdeaList {
  ideas: FeatureIdea[];
  next_cursor?: string | null;
}

export interface CreateFeatureIdeaIn {
  agent_id?: string;
  worker_id?: string;
  title: string;
  description?: string;
  category: PmIdeaCategory;
  priority_suggestion: PmIdeaPriority;
  user_impact?: string;
  mockup_description?: string;
  evidence?: FeatureIdeaEvidence[];
  competitor_refs?: FeatureIdeaCompetitorRef[];
  support_ticket_refs?: string[];
}

export interface PreferenceSummary {
  category: string;
  total_suggested: number;
  total_approved: number;
  total_rejected: number;
  approval_rate: number;
}

export interface PreferenceSummaryList {
  preferences: PreferenceSummary[];
}

export interface PmAgentConfig {
  review_frequency: "daily" | "weekly" | "biweekly";
  review_day?: string;
  review_hour_utc: number;
  focus_areas: string[];
  competitor_urls: Array<{ url: string; name: string }>;
  max_ideas_per_review: number;
  analyze_support_tickets: boolean;
  support_ticket_lookback_days: number;
  app_url?: string;
}

export interface UpdatePmConfigIn {
  review_frequency?: "daily" | "weekly" | "biweekly";
  review_day?: string;
  review_hour_utc?: number;
  focus_areas?: string[];
  competitor_urls?: Array<{ url: string; name: string }>;
  max_ideas_per_review?: number;
  analyze_support_tickets?: boolean;
  support_ticket_lookback_days?: number;
  app_url?: string;
}

export interface PmReviewSession {
  review_id: string;
  agent_id: string;
  worker_id: string;
  ideas_count: number;
  screenshots_count: number;
  session_at: number;
}

export interface PmReviewSessionList {
  reviews: PmReviewSession[];
}

export interface PmReviewScreenshot {
  idea_id?: string;
  description: string;
  url?: string;
}

export interface PmTriggerReviewResult {
  ok: boolean;
  agent_id: string;
  ideas_created: number;
  ideas: FeatureIdea[];
  completed_at: number;
}

// ─── Project Manager Agent (AGENT-012) ──────────────────────────────

export interface PmConfig {
  priority_framework: Record<string, string>;
  priority_weights: Record<string, number>;
  sprint_duration_days: number;
  capacity_per_agent_type: Record<string, number>;
  reporting_cadence: "daily" | "weekly" | "both";
  report_time_utc: string;
  idea_intake_enabled: boolean;
  auto_prioritize: boolean;
  auto_create_feature_requests: boolean;
  blocker_stale_hours: number;
  escalation_on_conflict: boolean;
  coding_tool: "claude_code" | "codex";
  coding_tool_model?: string | null;
  project_space_id?: string | null;
  stakeholder_subs?: string[] | null;
  updated_at?: number;
}

export type PmConfigIn = Omit<PmConfig, "updated_at">;

export interface PmConfigValidation {
  valid: boolean;
  errors: string[];
}

export interface ProductIdea {
  idea_id: string;
  submitted_by: string;
  title: string;
  description: string;
  status: "submitted" | "triaging" | "accepted" | "rejected" | "converted";
  priority_suggestion?: string | null;
  impact_score?: number | null;
  effort_score?: number | null;
  priority_rationale?: string | null;
  feature_ticket_id?: string | null;
  agent_run_id?: string | null;
  rejection_reason?: string | null;
  created_at: number;
  updated_at: number;
}

export interface IdeaListResult {
  ideas: ProductIdea[];
  next_cursor?: string | null;
}

export interface BacklogItem {
  ticket_id: string;
  subject: string;
  labels: string[];
  priority: string;
  priority_score: number;
  complexity?: string | null;
  estimated_hours: number;
  status: string;
  assigned_to?: string | null;
  age_hours: number;
}

export interface BacklogResult {
  items: BacklogItem[];
  count: number;
}

export interface ReprioritizeResult {
  tickets_reprioritized: number;
  operation_type: string;
  escalations_created: number;
}

export interface Sprint {
  sprint_id: string;
  sprint_number: number;
  start_date: string;
  end_date: string;
  status: "planned" | "active" | "completed";
  planned_hours: number;
  completed_hours: number;
  tickets_planned: number;
  tickets_completed: number;
  tickets_carried_over: number;
  velocity: number;
  blockers_count: number;
  created_at: number;
  updated_at: number;
  planned_ticket_ids: string[];
}

export interface SprintListResult {
  sprints: Sprint[];
  count: number;
}

export interface SprintBurndown {
  date: string;
  remaining_hours: number;
  ideal_hours: number;
}

export interface SprintDetail {
  sprint: Sprint;
  burndown: SprintBurndown[];
}

export interface ProjectReport {
  report_id: string;
  report_type: "daily" | "weekly" | "sprint_summary";
  content: string;
  metrics_snapshot: Record<string, unknown>;
  created_at: number;
}

export interface ReportListResult {
  reports: ProjectReport[];
  count: number;
}

export interface Blocker {
  ticket_id: string;
  ticket_subject: string;
  blocker_type: "stale" | "blocked" | "agent_error" | "dependency";
  stale_since?: number | null;
  assigned_agent?: string | null;
  details: string;
  priority: string;
}

export interface BlockerListResult {
  blockers: Blocker[];
  count: number;
}

export interface AgentCapacity {
  agent_type: string;
  total_capacity_hours: number;
  used_hours: number;
  available_hours: number;
  utilization_pct: number;
}

export interface CapacityResult {
  capacity: AgentCapacity[];
  fits: boolean;
  overflow_hours: number;
  recommendation: string;
}

export interface PmOutput {
  operation_type: string;
  ideas_processed: number;
  ideas_accepted: number;
  ideas_rejected: number;
  feature_tickets_created: string[];
  tickets_reprioritized: number;
  blockers_found: number;
  escalations_created: number;
  report_id?: string | null;
  sprint_id?: string | null;
  velocity_current?: number | null;
  velocity_trend?: string | null;
  total_duration_seconds: number;
}

export interface PmMetrics {
  ideas_submitted: number;
  ideas_converted: number;
  features_in_pipeline: number;
  velocity_current: number;
  velocity_trend: "increasing" | "stable" | "decreasing";
  backlog_size: number;
  p0_count: number;
  blockers_count: number;
  avg_cycle_time_hours: number;
  period_start: number;
  period_end: number;
}

export interface ProjectDashboard {
  sprint: Sprint | null;
  velocity_trend: { sprint_number: number; velocity: number }[];
  backlog_by_priority: Record<string, number>;
  pipeline_funnel: { stage: string; count: number }[];
  agent_utilization: AgentCapacity[];
  blockers: Blocker[];
  recent_completions: Array<{ ticket_id: string; subject: string; completed_at: number }>;
}

// ---------------------------------------------------------------------------
// Stylist / UI Agent (AGENT-016)
// ---------------------------------------------------------------------------

export interface UIReviewScreenshot {
  url: string;
  viewport: string;
  label: string;
}

export interface UIReviewIssue {
  issue_id: string;
  category: string;
  severity: "error" | "warning" | "info";
  title: string;
  description: string;
  page_element?: string;
  screenshot_index?: number;
  annotation_rect?: { x: number; y: number; width: number; height: number };
  design_rule_id?: string;
  suggestion: string;
  created_ticket_id?: string | null;
}

export interface UIReview {
  review_id: string;
  agent_id: string;
  worker_id: string;
  page_url: string;
  page_name: string;
  review_type: "full_page" | "component" | "responsive" | "accessibility" | "pr_review";
  source_ref?: string | null;
  screenshots: UIReviewScreenshot[];
  annotations?: Array<{ screenshot_index: number; x: number; y: number; width: number; height: number; issue: string }>;
  design_score: number;
  accessibility_score?: number | null;
  issues_found: number;
  issues: UIReviewIssue[];
  status: "completed" | "in_progress" | "failed";
  created_at: number;
}

export interface UIReviewListResult {
  reviews: UIReview[];
}

// ── Compliance & Security Agent (AGENT-015) ─────────────────────────────────

export interface SecurityFinding {
  finding_id: string;
  agent_id: string;
  source: "pr_review" | "ticket_review" | "periodic_audit" | "manual_scan";
  source_ref: string;
  severity: "critical" | "high" | "medium" | "low" | "info";
  category: string;
  title: string;
  description: string;
  file_path?: string;
  line_range?: string;
  code_snippet?: string;
  remediation: string;
  status: "open" | "acknowledged" | "remediated" | "false_positive" | "accepted_risk";
  remediation_ticket_id?: string;
  resolved_at?: number;
  note?: string;
  created_at: number;
}

export interface SecurityFindingsList {
  findings: SecurityFinding[];
  count: number;
  next_cursor?: string | null;
}

export interface PageDesignScore {
  page_url: string;
  page_name: string;
  design_score: number;
  accessibility_score?: number | null;
  issues_found: number;
  last_reviewed: number;
}

export interface OverallDesignScore {
  overall_design_score: number;
  overall_accessibility_score: number;
  pages_reviewed: number;
  total_issues: number;
}

export interface DesignRule {
  rule_id: string;
  name: string;
  category: string;
  description: string;
  severity: "error" | "warning" | "info";
  enabled: boolean;
  config?: Record<string, unknown> | null;
  created_at: number;
}

export interface CreateDesignRuleInput {
  name: string;
  category: "spacing" | "color" | "typography" | "layout" | "component" | "responsive" | "accessibility";
  description: string;
  severity: "error" | "warning" | "info";
  config?: Record<string, unknown>;
}

export interface UpdateDesignRuleInput {
  name?: string;
  category?: string;
  description?: string;
  severity?: "error" | "warning" | "info";
  enabled?: boolean;
  config?: Record<string, unknown>;
}

export interface StylistConfig {
  review_on_pr_merge: boolean;
  review_on_ui_ticket: boolean;
  periodic_review_frequency: string;
  periodic_review_day: string;
  periodic_review_hour_utc: number;
  viewports: Array<{ name?: string; width: number; height: number }>;
  pages_to_review: string[];
  design_system_ref: string;
  tailwind_config_path: string;
  contrast_ratio_min: number;
  auto_create_tickets: boolean;
  ticket_min_severity: "error" | "warning" | "info";
  brand_colors: string[];
  font_families: string[];
  updated_at?: number | null;
}

export interface CreateIssueTicketResult {
  ok: boolean;
  ticket_id: string;
  review_id: string;
  issue_id: string;
}

export interface TriggerUIReviewResult {
  ok: boolean;
  reviews: UIReview[];
}

// ─── Marketing Agent (AGENT-017) ─────────────────────────────────────────

export type MarketingContentType =
  | "blog_post"
  | "social_twitter"
  | "social_linkedin"
  | "social_instagram"
  | "newsletter"
  | "release_notes"
  | "changelog"
  | "landing_page"
  | "meta_seo";

export type MarketingContentStatus =
  | "draft"
  | "review"
  | "approved"
  | "scheduled"
  | "published"
  | "archived";

export interface MarketingContent {
  content_id: string;
  user_id: string;
  agent_id?: string | null;
  content_type: MarketingContentType;
  title: string;
  body: string;
  summary?: string | null;
  feature_refs?: string[] | null;
  tags?: string[] | null;
  seo_meta?: { title?: string; description?: string; keywords?: string[] } | null;
  variations?: Array<{ variant_id: string; title: string; body: string }> | null;
  status: MarketingContentStatus;
  scheduled_publish_at?: number | null;
  published_at?: number | null;
  target_platform?: string | null;
  created_at: number;
  updated_at: number;
}

export interface MarketingContentList {
  items: MarketingContent[];
  cursor?: string | null;
  count: number;
}

export interface CreateMarketingContentIn {
  content_type: MarketingContentType;
  title: string;
  body: string;
  summary?: string;
  feature_refs?: string[];
  tags?: string[];
  seo_meta?: Record<string, unknown>;
  variations?: Array<{ variant_id: string; title: string; body: string }>;
  target_platform?: string;
}

export interface UpdateMarketingContentIn {
  content_type?: MarketingContentType;
  title?: string;
  body?: string;
  summary?: string;
  feature_refs?: string[];
  tags?: string[];
  seo_meta?: Record<string, unknown>;
  variations?: Array<{ variant_id: string; title: string; body: string }>;
  target_platform?: string;
}

export interface ContentEngagementStats {
  content_id: string;
  total_views: number;
  total_clicks: number;
  total_signups: number;
  total_shares: number;
  click_rate: number;
  signup_rate: number;
  by_day: Array<{ date: string; views: number; clicks: number; signups: number }>;
  by_variant?: Array<{ variant_id: string; views: number; clicks: number; signups: number }>;
}

export interface ContentCalendarEntry {
  content_id: string;
  title: string;
  content_type: string;
  status: string;
  date: number;
}

export interface MarketingEngagementSummary {
  total_content: number;
  total_views: number;
  total_clicks: number;
  total_signups: number;
  avg_click_rate: number;
  avg_signup_rate: number;
  top_performing: Array<{ content_id: string; title: string; clicks: number }>;
}

export interface MarketingConfig {
  trigger_on_feature_completion: boolean;
  auto_generate_content_types: string[];
  brand_voice: {
    tone?: string;
    vocabulary_level?: string;
    personality_traits?: string[];
    words_to_avoid?: string[];
    tagline?: string;
  };
  target_audience: { primary?: string; secondary?: string; demographics?: string };
  social_platforms: string[];
  content_calendar_enabled: boolean;
  newsletter_frequency?: string | null;
  newsletter_day?: string | null;
  ab_test_variations: number;
  seo_keywords: string[];
  max_content_per_feature: number;
  updated_at?: number | null;
}

export interface UpdateMarketingConfigIn {
  trigger_on_feature_completion?: boolean;
  auto_generate_content_types?: string[];
  brand_voice?: Record<string, unknown>;
  target_audience?: Record<string, unknown>;
  social_platforms?: string[];
  content_calendar_enabled?: boolean;
  newsletter_frequency?: "daily" | "weekly" | "biweekly" | "monthly";
  newsletter_day?: string;
  ab_test_variations?: number;
  seo_keywords?: string[];
  max_content_per_feature?: number;
}

export interface MarketingGenerateResult {
  status: string;
  executed: boolean;
  content_types_requested: string[];
  feature_ticket_ids: string[];
  missing_ticket_ids: string[];
  contents: MarketingContent[];
  count: number;
}

export interface SecurityAudit {
  audit_id: string;
  agent_id: string;
  worker_id: string;
  status: "running" | "completed" | "failed";
  started_at: number;
  completed_at?: number;
  finding_counts: Record<string, number>;
  files_scanned: number;
  compliance_summary: Record<string, { passed: number; failed: number; open: number }>;
  report_s3_key?: string;
}

export interface SecurityAuditsList {
  audits: SecurityAudit[];
  count: number;
  next_cursor?: string | null;
}

export interface SecurityTrendWeek {
  week_start: number;
  by_severity: Record<string, number>;
  by_category: Record<string, number>;
  total: number;
}

export interface SecurityTrends {
  weeks: SecurityTrendWeek[];
  days: number;
  total: number;
}

export interface ComplianceFrameworkStatus {
  name: string;
  passed: number;
  failed: number;
  open_findings: number;
  status: "passing" | "failing" | "unknown";
}

export interface ComplianceStatus {
  frameworks: Record<string, ComplianceFrameworkStatus>;
}

export interface SecurityAgentConfig {
  scan_on_pr: boolean;
  scan_on_ticket_update: boolean;
  block_merge_on_critical: boolean;
  block_merge_on_high: boolean;
  periodic_audit_frequency: string;
  periodic_audit_day: string;
  periodic_audit_hour_utc: number;
  compliance_frameworks: string[];
  wcag_level: string;
  severity_thresholds: Record<string, string>;
  ignored_paths: string[];
  auto_create_remediation_tickets: boolean;
  remediation_ticket_min_severity: string;
  updated_at?: number;
}

export interface SecurityAgentConfigIn {
  scan_on_pr?: boolean;
  scan_on_ticket_update?: boolean;
  block_merge_on_critical?: boolean;
  block_merge_on_high?: boolean;
  periodic_audit_frequency?: "daily" | "weekly" | "biweekly" | "monthly";
  periodic_audit_day?: string;
  periodic_audit_hour_utc?: number;
  compliance_frameworks?: Array<"owasp_top_10" | "gdpr" | "pci_dss" | "wcag">;
  wcag_level?: "A" | "AA" | "AAA";
  severity_thresholds?: Record<string, string>;
  ignored_paths?: string[];
  auto_create_remediation_tickets?: boolean;
  remediation_ticket_min_severity?: "critical" | "high" | "medium" | "low";
}

export interface CreateSecurityFindingIn {
  agent_id?: string;
  source: "pr_review" | "ticket_review" | "periodic_audit" | "manual_scan";
  source_ref: string;
  severity: "critical" | "high" | "medium" | "low" | "info";
  category: string;
  title: string;
  description: string;
  file_path?: string;
  line_range?: string;
  code_snippet?: string;
  remediation?: string;
}

// ─── Admin Subscription Tier Manager (ADMIN-001) ─────────────────────────────

export type SubscriptionTierBillingCycle = "monthly" | "quarterly" | "yearly";
export type SubscriptionTierAccessLevel = "basic" | "premium" | "vip";
export type SubscriptionTierStatus = "active" | "archived";

export interface SubscriptionTierCreate {
  name: string;
  price_cents: number;
  billing_cycle?: SubscriptionTierBillingCycle;
  description?: string;
  benefits?: string[];
  access_level?: SubscriptionTierAccessLevel;
  plan_id?: string | null;
}

export interface SubscriptionTierUpdate {
  name?: string;
  price_cents?: number;
  billing_cycle?: SubscriptionTierBillingCycle;
  description?: string;
  benefits?: string[];
  access_level?: SubscriptionTierAccessLevel;
  plan_id?: string | null;
}

export interface SubscriptionTierOut {
  tier_id: string;
  name: string;
  price_cents: number;
  billing_cycle: string;
  description: string;
  benefits: string[];
  access_level: string;
  display_order: number;
  status: SubscriptionTierStatus;
  subscriber_count: number;
  plan_id?: string | null;
  created_at: number;
  updated_at: number;
  archived_at?: number | null;
}

export interface SubscriptionTierReorderResult {
  tier_id: string;
  display_order: number;
}

export interface SubscriptionTierAnalyticsRow {
  tier_id: string;
  name: string;
  subscriber_count: number;
  revenue_cents: number;
  churn_rate: number;
}

export interface SubscriptionTierAnalytics {
  tiers: SubscriptionTierAnalyticsRow[];
  total_subscribers: number;
  total_revenue_cents: number;
  growth_series: Array<{ date: string; count: number }>;
}

export interface SubscriptionTierPreviewItem {
  tier_id: string;
  name: string;
  price_cents: number;
  billing_cycle: string;
  description: string;
  benefits: string[];
  access_level: string;
  display_order: number;
}

export interface SubscriptionTierPreviewOut {
  tiers: SubscriptionTierPreviewItem[];
  creator_id: string;
}

export interface SubscriptionTierDeleteResult {
  ok: boolean;
  tier_id: string;
  deleted: boolean;
}

// ─── Accountant / Cost Tracking Agent (AGENT-018) ───────────────────────────

export interface AgentCostEntry {
  worker_id: string;
  agent_type: string;
  agent_id: string;
  date: string;
  llm_input_tokens: number;
  llm_output_tokens: number;
  llm_cached_tokens: number;
  llm_cost_cents: number;
  llm_provider: string;
  llm_model: string;
  compute_hours: number;
  compute_cost_cents: number;
  total_cost_cents: number;
  tickets_worked: number;
  tickets_completed: number;
}

export interface CostDailySummary {
  date: string;
  total_cents: number;
  llm_cents: number;
  compute_cents: number;
  by_agent_type: Record<string, number>;
  by_worker: AgentCostEntry[];
}

export interface BudgetUtilization {
  budget_id: string;
  name: string;
  scope: string;
  scope_ref?: string | null;
  period: string;
  limit_cents: number;
  spent_cents: number;
  utilization_pct: number;
}

export interface CostPeriodSummary {
  period: string;
  start_date: string;
  end_date: string;
  total_cents: number;
  llm_cents: number;
  compute_cents: number;
  by_agent_type: Record<string, number>;
  budget_utilization: BudgetUtilization[];
}

export interface AgentTypeCosts {
  agent_type: string;
  days: number;
  total_cents: number;
  llm_cents: number;
  compute_cents: number;
  daily_costs: Array<{ date: string; cost_cents: number }>;
  entries: AgentCostEntry[];
}

export interface TicketCost {
  ticket_id: string;
  agent_type: string;
  total_llm_tokens: number;
  total_llm_cost_cents: number;
  total_compute_hours: number;
  total_compute_cost_cents: number;
  total_cost_cents: number;
  worker_sessions: number;
  status: string;
  started_at?: number | null;
  completed_at?: number | null;
}

export interface TicketCostList {
  ticket_costs: TicketCost[];
  next_cursor?: string | null;
}

export interface CostBudget {
  budget_id: string;
  name: string;
  scope: "overall" | "agent_type" | "agent_instance";
  scope_ref?: string | null;
  period: "daily" | "weekly" | "monthly";
  limit_cents: number;
  alert_threshold_pct: number;
  auto_pause_on_exceed: boolean;
  enabled: boolean;
  created_at: number;
}

export interface CostBudgetIn {
  name: string;
  scope: "overall" | "agent_type" | "agent_instance";
  scope_ref?: string | null;
  period: "daily" | "weekly" | "monthly";
  limit_cents: number;
  alert_threshold_pct?: number;
  auto_pause_on_exceed?: boolean;
}

export interface CostBudgetUpdateIn {
  name?: string;
  limit_cents?: number;
  alert_threshold_pct?: number;
  auto_pause_on_exceed?: boolean;
  enabled?: boolean;
}

export interface CostAlert {
  alert_id: string;
  budget_id?: string | null;
  alert_type: string;
  severity: "info" | "warning" | "critical";
  title: string;
  message: string;
  current_spend_cents: number;
  budget_limit_cents?: number | null;
  acknowledged: boolean;
  auto_action_taken?: string | null;
  created_at: number;
}

export interface CostAlertList {
  alerts: CostAlert[];
  next_cursor?: string | null;
}

export interface CostTrendWeek {
  week_start: string;
  total_cents: number;
  llm_cents: number;
  compute_cents: number;
  by_agent_type: Record<string, number>;
}

export interface CostTrends {
  weeks: CostTrendWeek[];
}

export interface OptimizationRecommendation {
  type: "idle_worker" | "model_downgrade" | "high_cost_ticket" | "underutilized_agent";
  title: string;
  description: string;
  potential_savings_cents: number;
  action: string;
}

export interface AccountantConfig {
  collection_frequency: string;
  report_frequency: string;
  report_hour_utc: number;
  compute_pricing: Record<string, number>;
  anomaly_detection_enabled: boolean;
  anomaly_threshold_pct: number;
  idle_worker_threshold_minutes: number;
  optimization_suggestions_enabled: boolean;
  updated_at?: number | null;
}

export interface AccountantConfigIn {
  collection_frequency?: "hourly" | "every_6h" | "daily";
  report_frequency?: "daily" | "weekly" | "monthly";
  report_hour_utc?: number;
  compute_pricing?: Record<string, number>;
  anomaly_detection_enabled?: boolean;
  anomaly_threshold_pct?: number;
  idle_worker_threshold_minutes?: number;
  optimization_suggestions_enabled?: boolean;
}

export interface CostCollectResult {
  ok: boolean;
  executed: boolean;
  alerts_created: number;
  alerts: CostAlert[];
  collected_at: number;
}

// ── ADMIN-002: Admin Email/SMS Dashboards ──────────────────────────────
export interface EmailDashboardStats {
  sent: number;
  delivered: number;
  bounced: number;
  complained: number;
  failed: number;
  suppressed: number;
  total: number;
  delivery_rate: number;
  bounce_rate: number;
  complaint_rate: number;
  period_days: number;
}

export interface SmsDashboardStats {
  sent: number;
  delivered: number;
  failed: number;
  total: number;
  total_segments: number;
  estimated_cost_usd: number;
  suppressed_numbers: number;
  delivery_rate: number;
  failure_rate: number;
  period_days: number;
}

export interface DashboardTimeseriesPoint {
  date: string;
  sent: number;
  delivered: number;
  bounced: number;
  complained: number;
  failed: number;
  segments: number;
}

export interface DashboardTimeseries {
  channel: string;
  period_days: number;
  points: DashboardTimeseriesPoint[];
}

export interface DashboardBreakdownItem {
  key: string;
  label: string;
  count: number;
}

export interface DashboardBreakdown {
  channel: string;
  dimension: string;
  items: DashboardBreakdownItem[];
}

export interface MessagingDeliveryItem {
  [key: string]: unknown;
  to_email?: string;
  phone?: string;
  subject?: string;
  status?: string;
  created_at?: number;
  bounce_type?: string;
  diagnostic_code?: string;
  complaint_feedback_type?: string;
  error?: string;
  segments?: number;
}

export interface MessagingDeliveryList {
  items: MessagingDeliveryItem[];
  next_cursor: string | null;
}

export interface MessagingSuppressionItem {
  [key: string]: unknown;
  email?: string;
  phone?: string;
  reason?: string;
  suppressed_at?: number;
}

export interface MessagingSuppressionList {
  items: MessagingSuppressionItem[];
  count: number;
}

export interface NotificationTemplate {
  template_id: string;
  channel: string;
  name: string;
  subject?: string | null;
  body: string;
  variables: string[];
  active: boolean;
  updated_at?: number | null;
  updated_by?: string | null;
}

export interface NotificationTemplateUpdate {
  subject?: string | null;
  body?: string;
  active?: boolean;
}

export interface NotificationTemplatePreview {
  template_id: string;
  channel: string;
  rendered_subject?: string | null;
  rendered_body: string;
  missing_vars: string[];
}

export interface NotificationTemplateTestSendResult {
  ok: boolean;
  template_id: string;
  channel: string;
  recipient: string;
  sent_at: number;
}

// ── KYC-002: Identity Document Verification ──────────────────────────────
export type KycDocumentType = "id_front" | "id_back";
export type KycDocumentStatus = "pending" | "extracted" | "failed" | "approved" | "rejected";
export type KycDocumentConfidence = "high" | "medium" | "low" | "failed";
export type KycDocumentMatchStatus = "match" | "mismatch" | "partial" | "not_available";

export interface KycDocumentFieldMatch {
  status: KycDocumentMatchStatus;
  profile_value?: string | null;
  extracted_value?: string | null;
  similarity?: number | null;
}

export interface KycDocumentOut {
  document_id: string;
  case_id?: string | null;
  user_sub?: string | null;
  document_type: KycDocumentType;
  file_name: string;
  status: KycDocumentStatus;
  provider?: string | null;
  image_url?: string | null;
  extraction_id?: string | null;
  extracted_fields: Record<string, string>;
  match_results?: Record<string, KycDocumentFieldMatch> | null;
  overall_confidence?: KycDocumentConfidence | null;
  review_decision?: string | null;
  review_note?: string | null;
  created_at: number;
  updated_at: number;
}

export interface KycDocumentListResponse {
  documents: KycDocumentOut[];
}

export interface KycDocumentUploadRequest {
  document_type: KycDocumentType;
  file_name: string;
  case_id?: string | null;
  content_b64?: string | null;
}

export interface KycDocumentReviewRequest {
  decision: "approve" | "reject";
  note?: string | null;
}

// KYC-010: Passport / National-ID Scanner
export type KycIdScannerDocumentType =
  | "passport"
  | "national_id_card"
  | "driving_license"
  | "residence_permit";
export type KycIdScannerFileType = "id_front" | "id_back";
export type KycIdScannerStatus = "matched" | "flagged" | "rejected" | "approved" | "declined";
export type KycIdScannerExpiryStatus = "valid" | "expired" | "expiring_soon" | "unknown";

export interface KycIdScannerChecksums {
  document_number: boolean;
  date_of_birth: boolean;
  expiry_date: boolean;
  optional_data?: boolean | null;
  composite: boolean;
}

export interface KycIdScannerExtraction {
  valid?: boolean | null;
  format?: string | null;
  error?: string | null;
  document_type?: string | null;
  issuing_state?: string | null;
  surname?: string | null;
  given_names?: string | null;
  document_number?: string | null;
  nationality?: string | null;
  date_of_birth?: string | null;
  sex?: string | null;
  expiry_date?: string | null;
  checksums?: KycIdScannerChecksums | null;
}

export interface KycIdScannerExpiryCheck {
  status: KycIdScannerExpiryStatus;
  message: string;
  expiry_date?: string | null;
  days_until_expiry?: number | null;
}

export interface KycIdScannerCrossReference {
  match_score: number;
  total_fields_checked: number;
  fields_matched: number;
  matches: Record<string, unknown>;
  mismatches: Record<string, unknown>;
}

export interface KycIdScannerScanOut {
  scan_id: string;
  case_id: string;
  user_sub?: string | null;
  document_type: string;
  file_type: string;
  status: KycIdScannerStatus;
  mrz_valid: boolean;
  extraction: KycIdScannerExtraction;
  expiry_check: KycIdScannerExpiryCheck;
  cross_reference?: KycIdScannerCrossReference | null;
  image_url?: string | null;
  review_decision?: string | null;
  review_note?: string | null;
  created_at: number;
  updated_at: number;
}

export interface KycIdScannerScanSummary {
  scan_id: string;
  case_id: string;
  document_type: string;
  file_type: string;
  status: KycIdScannerStatus;
  mrz_valid: boolean;
  expiry_status?: KycIdScannerExpiryStatus | null;
  match_score?: number | null;
  created_at: number;
}

export interface KycIdScannerScanListResponse {
  scans: KycIdScannerScanSummary[];
}

export interface KycIdScannerScanRequest {
  document_type: KycIdScannerDocumentType;
  file_type?: KycIdScannerFileType;
  mrz_lines?: string[] | null;
  image_ref?: string | null;
}

export interface KycIdScannerValidateRequest {
  document_type: KycIdScannerDocumentType;
}

export interface KycIdScannerAdjudicateRequest {
  decision: "approve" | "decline";
  note?: string | null;
}

export interface KycIdScannerValidationOut {
  document_type: string;
  sides_required: string[];
  has_mrz: boolean;
  mrz_format?: string | null;
  sides_present: string[];
  all_sides_present: boolean;
}

// KYC-004: Proof of Residency Verification
export type KycResidencyDocumentType =
  | "utility_bill"
  | "bank_statement"
  | "government_letter"
  | "tax_document"
  | "lease_agreement";
export type KycResidencyStatus = "pending" | "verified" | "rejected" | "expired";
export type KycResidencyMatchStatus = "match" | "partial" | "mismatch" | "not_available";

export interface KycResidencyAddressMatch {
  status: KycResidencyMatchStatus;
  profile_address: Record<string, string>;
  field_matches: Record<string, "match" | "partial" | "mismatch">;
}

export interface KycResidencyDocumentOut {
  document_id: string;
  case_id?: string | null;
  user_sub?: string | null;
  document_type: KycResidencyDocumentType;
  issuing_entity?: string | null;
  document_date?: string | null;
  file_name: string;
  status: KycResidencyStatus;
  provider?: string | null;
  document_url?: string | null;
  extraction_id?: string | null;
  recency_valid: boolean;
  recency_days: number;
  extracted_address?: Record<string, string> | null;
  address_match?: KycResidencyAddressMatch | null;
  review_decision?: string | null;
  review_note?: string | null;
  created_at: number;
  updated_at: number;
}

export interface KycResidencyListResponse {
  documents: KycResidencyDocumentOut[];
}

export interface KycResidencyUploadRequest {
  document_type: KycResidencyDocumentType;
  issuing_entity: string;
  document_date: string;
  file_name: string;
  case_id?: string | null;
  content_b64?: string | null;
}

export interface KycResidencyReviewRequest {
  decision: "approve" | "reject";
  note?: string | null;
}

// KYC-003: Liveness Video Verification Call
export type KycLivenessCallStatus =
  | "scheduled"
  | "in_progress"
  | "passed"
  | "failed"
  | "cancelled"
  | "expired";

export interface KycLivenessCallScheduleRequest {
  case_id: string;
  scheduled_at: number;
  duration_minutes?: number;
  verifier_sub?: string | null;
  note?: string | null;
}

export interface KycLivenessCallResultRequest {
  result: "passed" | "failed";
  notes: string;
  recording_linked?: boolean;
}

export interface KycLivenessCallOut {
  call_id: string;
  case_id: string;
  user_sub?: string | null;
  status: KycLivenessCallStatus;
  scheduled_at: number;
  duration_minutes: number;
  note?: string | null;
  verifier_sub?: string | null;
  result?: "passed" | "failed" | null;
  result_notes?: string | null;
  result_set_at?: number | null;
  recording_ref?: string | null;
  started_at?: number | null;
  join_url?: string | null;
  created_at: number;
  updated_at: number;
}

export interface KycLivenessCallStatusOut {
  call_id: string;
  case_id: string;
  status: KycLivenessCallStatus;
  scheduled_at: number;
  duration_minutes: number;
  result?: "passed" | "failed" | null;
  join_url?: string | null;
  created_at: number;
  updated_at: number;
}

export interface KycLivenessCallListResponse {
  calls: KycLivenessCallOut[];
}

export interface KycLivenessCallStatusResponse {
  verification_call?: KycLivenessCallStatusOut | null;
}

// FIN-001: Invoice / Receipt PDF
export interface InvoiceLineItem {
  description: string;
  quantity: number;
  amount_cents: number;
}

export interface Invoice {
  invoice_id: string;
  invoice_number: string;
  invoice_type: string;
  user_sub: string;
  amount_cents: number;
  tax_cents: number;
  total_cents: number;
  currency: string;
  status: string;
  seller_id: string;
  seller_name: string;
  buyer_name: string;
  buyer_email: string;
  line_items: InvoiceLineItem[];
  payment_method_summary: string;
  ledger_entry_id: string;
  created_at: number;
}

export interface InvoiceList {
  invoices: Invoice[];
  next_cursor: string | null;
}

export interface InvoiceEmailResult {
  ok: boolean;
  emailed_to: string;
  message: string;
}

// MOD-001: Video Review Queue
export interface VideoReviewQueueItem {
  entry_id: string;
  video_id: string;
  owner_user_id: string;
  title: string;
  description: string;
  status: string;
  priority: string;
  priority_rank: number;
  source: string;
  created_at: number;
  updated_at: number;
  claimed_by: string;
  claimed_at: number;
  reviewed_by: string;
  reviewed_at: number;
  review_notes: string;
  decision: string;
  escalated: boolean;
  thumbnail_url?: string | null;
  hls_manifest_url?: string | null;
  duration_seconds?: number | null;
  flag_reason?: string | null;
}

export interface VideoReviewQueueList {
  items: VideoReviewQueueItem[];
  total: number;
  next_cursor?: string | null;
}

export interface VideoReviewQueueStats {
  counts: Record<string, number>;
  total_open: number;
}

export interface VideoReviewDetail {
  entry: VideoReviewQueueItem;
  prior_review_history: Array<Record<string, unknown>>;
  prior_approvals_count: number;
  prior_rejections_count: number;
}

export interface VideoReviewDecision {
  ok: boolean;
  entry_id: string;
  decision: string;
  new_status: string;
  reviewed_by: string;
  reviewed_at: number;
  audit_id: string;
}

// -- Syndicate Revenue Splitting (SYND-003) --
// percentages are integer basis points (10000 = 100%); money is integer cents.

export type SplitMode = "equal" | "weighted" | "performance";
export type PerformanceMetric = "views" | "engagement" | "subscribers";

export interface SplitConfig {
  mode: SplitMode;
  platform_fee_bps: number;
  weights_bps: Record<string, number>;
  performance_metric: string;
  performance_window_days: number;
  updated_at: number;
  updated_by: string;
}

export interface SplitConfigInput {
  mode: SplitMode;
  weights_bps?: Record<string, number>;
  performance_metric?: string;
  performance_window_days?: number;
  platform_fee_bps?: number;
}

export interface SplitDistribution {
  user_id: string;
  display_name: string;
  amount_cents: number;
  percentage_bps: number;
  ledger_entry_id: string;
}

export interface SplitExecution {
  split_id: string;
  syndicate_id: string;
  source_type: string;
  subscription_id: string;
  invoice_id: string;
  gross_amount_cents: number;
  platform_fee_cents: number;
  platform_fee_bps: number;
  net_amount_cents: number;
  currency: string;
  mode: string;
  distributions: SplitDistribution[];
  created_at: number;
}

export interface ExecuteSplitInput {
  source_type?: "subscription" | "tip";
  subscription_id?: string;
  invoice_id?: string;
  gross_amount_cents: number;
  currency?: string;
}

export interface MemberEarningEntry {
  split_id: string;
  amount_cents: number;
  percentage_bps: number;
  created_at: number;
  source_type: string;
}

export interface MemberEarnings {
  syndicate_id: string;
  user_id: string;
  total_cents: number;
  split_count: number;
  entries: MemberEarningEntry[];
}

// ─── Account Deletion (PLATFORM-018) ────────────────────────────

export interface AccountDeletionRequestBody {
  password: string;
  confirm_text: string;
  reason?: string;
}

export interface AccountDeletionStatus {
  request_id: string;
  status: string;
  created_at: number;
  scheduled_for?: number | null;
  grace_days_remaining?: number | null;
  can_cancel: boolean;
  retention_hold: boolean;
  retention_hold_reason?: string | null;
  reason?: string | null;
  completed_at?: number | null;
  deletion_summary?: Record<string, unknown> | null;
  user_sub?: string | null;
}

export interface AccountDeletionListResp {
  requests: AccountDeletionStatus[];
  total: number;
}

export interface AccountDeletionCancelResp {
  ok: boolean;
  request_id: string;
  status: string;
  cancelled_at: number;
}

export interface PrivacyExportRequestBody {
  categories: Record<string, boolean>;
}

export interface PrivacyExportStatus {
  request_id: string;
  status: string;
  created_at: number;
  completed_at?: number | null;
  download_url?: string | null;
  download_expires_at?: number | null;
  categories_requested: number;
  file_size_bytes?: number | null;
  data?: Record<string, unknown> | null;
}

export interface AccountDeletionRetentionHoldBody {
  reason: string;
}

export interface AccountDeletionAuditEvent {
  event_id: string;
  event_type: string;
  actor: string;
  timestamp: number;
  details: Record<string, unknown>;
}

export interface AccountDeletionAuditTrail {
  request_id: string;
  events: AccountDeletionAuditEvent[];
}

// ── Live Q&A Mode (ENGAGE-003) ──────────────────────────────────────────────

export type LiveQaStatus =
  | "pending"
  | "featured"
  | "answered"
  | "dismissed"
  | "removed";

export interface LiveQaQuestion {
  question_id: string;
  session_id: string;
  submitter_id: string;
  submitter_display_name: string;
  text: string;
  status: LiveQaStatus;
  vote_count: number;
  pinned: boolean;
  featured_at?: number | null;
  answered_at?: number | null;
  created_at: number;
  featured_by?: string | null;
}

export interface LiveQaQueueResponse {
  questions: LiveQaQuestion[];
  has_more: boolean;
}

export interface LiveQaModeResponse {
  ok: boolean;
  session_id: string;
  qa_mode_enabled: boolean;
}

export interface LiveQaStats {
  total_questions: number;
  answered: number;
  dismissed: number;
  featured: number;
  pending: number;
  total_upvotes: number;
  avg_upvotes: number;
  answer_rate: number;
}

// ─── Platform Financial Dashboard (FIN-013) ──────────────────────

export interface PlatformFinancialKpis {
  gmv_cents: number;
  net_revenue_cents: number;
  refunds_cents: number;
  take_rate_bps: number;
  tx_count: number;
  unique_payers: number;
  avg_tx_cents: number;
  period: Record<string, string>;
}

export interface PlatformFinancialTrendPoint {
  date: string;
  gmv_cents: number;
  net_revenue_cents: number;
  tx_count: number;
}

export interface PlatformFinancialTrendsResponse {
  data: PlatformFinancialTrendPoint[];
  granularity: string;
}

export interface PlatformFinancialProviderEntry {
  provider: string;
  total_cents: number;
  tx_count: number;
  avg_cents: number;
  pct: number;
  success_rate: number;
}

export interface PlatformFinancialProviderResponse {
  data: PlatformFinancialProviderEntry[];
}

export interface PlatformFinancialTypeEntry {
  entry_type: string;
  total_cents: number;
  tx_count: number;
  avg_cents: number;
}

export interface PlatformFinancialTypeResponse {
  data: PlatformFinancialTypeEntry[];
}

export interface PlatformFinancialTopCreatorEntry {
  user_id: string;
  revenue_cents: number;
  tx_count: number;
  avg_cents: number;
}

export interface PlatformFinancialTopCreatorsResponse {
  data: PlatformFinancialTopCreatorEntry[];
}

export interface PlatformFinancialRollupOut {
  date: string;
  gmv_cents: number;
  net_revenue_cents: number;
  tx_count: number;
  unique_payers: number;
  computed_at: number;
}

// ── License Agreements (LICENSE-001) ─────────────────────────────────────────

export type LicenseAgreementStatus =
  | "pending_review"
  | "active"
  | "rejected"
  | "expired"
  | "archived"
  | "deleted";

export interface LicenseAgreementOut {
  license_id: string;
  title: string;
  licensor_name: string;
  license_type: string;
  file_name: string;
  file_size: number;
  mime_type: string;
  status: LicenseAgreementStatus | string;
  version: number;
  territory: string;
  expires_at: number | null;
  notes: string;
  rejection_reason: string;
  created_at: number;
  updated_at: number;
  content_count: number;
  expiring_soon: boolean;
}

export interface LicenseAgreementListOut {
  items: LicenseAgreementOut[];
  next_cursor?: string | null;
}

export interface LicenseAgreementContentLinkOut {
  content_id: string;
  content_type: string;
  license_id: string;
  linked_at: number;
}

export interface LicenseAgreementDownloadOut {
  download_url: string;
}

export interface LicenseAgreementReviewItemOut {
  license_id: string;
  creator_id: string;
  creator_display_name: string;
  title: string;
  licensor_name: string;
  license_type: string;
  submitted_at: number;
}

export interface LicenseAgreementReviewQueueOut {
  items: LicenseAgreementReviewItemOut[];
  next_cursor?: string | null;
}

// ─── Security Groups & Network Rules (INFRA-009) ────────────────────────────

export type SgProtocol = "tcp" | "udp" | "icmp" | "all";
export type SgDirection = "inbound" | "outbound";

export interface SecurityRuleIn {
  protocol: SgProtocol;
  port_from?: number;
  port_to?: number;
  source: string;
  direction?: SgDirection;
  description?: string;
}

export interface SecurityRuleOut {
  rule_id: string;
  protocol: string;
  port_from: number;
  port_to: number;
  source: string;
  direction: string;
  description: string;
}

export interface CreateSgIn {
  name: string;
  description?: string;
  rules?: SecurityRuleIn[];
}

export interface UpdateSgIn {
  name?: string;
  description?: string;
}

export interface UpdateRuleIn {
  protocol?: SgProtocol;
  port_from?: number;
  port_to?: number;
  source?: string;
  direction?: SgDirection;
  description?: string;
}

export interface SecurityGroupOut {
  sg_id: string;
  name: string;
  description: string;
  rules: SecurityRuleOut[];
  is_default: boolean;
  created_at: number;
  updated_at: number;
  associated_instances: string[];
}

export interface SgListOut {
  security_groups: SecurityGroupOut[];
  count: number;
}

export interface EffectiveRuleOut {
  rule_id: string;
  protocol: string;
  port_from: number;
  port_to: number;
  source: string;
  resolved_sources: string[];
  direction: string;
  description: string;
}

export interface EffectiveRulesOut {
  sg_id: string;
  rules: EffectiveRuleOut[];
  count: number;
}

// ─── Ad Fraud Prevention (ADS-014) ────────────────────────────────────────────

export interface AdFraudEvent {
  event_id: string;
  user_id: string;
  ip_address: string;
  account_id: string;
  campaign_id: string;
  creative_id: string;
  event_type: string;
  fraud_score: number;
  rule_scores: Record<string, number>;
  details: Record<string, unknown>;
  status: string;
  created_at: number;
  reviewed_by?: string | null;
  reviewed_at?: number | null;
}

export interface AdFraudAccountRisk {
  account_id: string;
  fraud_rate_bps: number;
  total_events: number;
  flagged_events: number;
  status: string;
  last_fraud_event_at?: number | null;
  last_event_at?: number | null;
  recent_events?: AdFraudEvent[];
}

export interface AdFraudSummary {
  flagged_events_today: number;
  total_events: number;
  flagged_events: number;
  fraud_rate_bps: number;
  suspended_accounts: number;
  tracked_accounts: number;
  top_fraud_rules: Record<string, number>;
}

// ─── Ad Scheduling & Dayparting (ADS-016) ───────────────────────────────────

export interface DaypartingSchedule {
  timezone: string;
  schedule: Record<string, number[]>;
}

export interface CampaignFlight {
  flight_id?: string;
  name: string;
  start_date: string;
  end_date: string;
  daily_budget_cents: number;
  creative_ids: string[];
  status?: string;
}

export interface CampaignScheduleUpdate {
  dayparting?: DaypartingSchedule | null;
  flights?: CampaignFlight[] | null;
  campaign_timezone?: string | null;
}

export interface CampaignScheduleOut {
  campaign_id?: string;
  campaign_timezone: string;
  dayparting?: DaypartingSchedule | null;
  flights?: CampaignFlight[] | null;
  start_date?: number | string | null;
  end_date?: number | string | null;
}

export interface ScheduleEligibility {
  eligible: boolean;
  timezone?: string;
  local_time?: string;
  day?: string;
  hour?: number;
  active_hours?: number[];
  reason?: string;
  active_flight?: CampaignFlight | null;
}

export interface BudgetPacing {
  active_hours_today: number;
  hours_remaining: number;
  hourly_budget_cents: number;
  remaining_budget_cents: number;
}

export interface ScheduleTemplatesResponse {
  templates: Record<string, Record<string, number[]>>;
}

// FIN-014: Payment Provider Health
export interface PaymentHealthProviderStatus {
  provider: string;
  status: string; // "healthy" | "degraded" | "down"
  enabled: boolean;
  success_rate: number;
  error_rate_bps: number;
  avg_latency_ms: number;
  p50_latency_ms: number;
  p95_latency_ms: number;
  p99_latency_ms: number;
  total_success: number;
  total_failure: number;
  last_check_at: number;
}

export interface PaymentHealthTimelineBucket {
  hour: string;
  success: number;
  failure: number;
  avg_latency_ms: number;
  status: string;
}

export interface PaymentHealthTimeline {
  provider: string;
  hours: number;
  data: PaymentHealthTimelineBucket[];
}

export interface PaymentHealthRecentFailure {
  ts: number;
  provider: string;
  error_type: string;
  op: string;
  latency_ms: number;
}

export interface PaymentHealthErrorDrilldown {
  provider: string;
  error_types: Record<string, number>;
  recent_failures: PaymentHealthRecentFailure[];
}

export interface PaymentHealthProviderConfig {
  provider: string;
  enabled: boolean;
  alert_error_rate_threshold: number;
  alert_latency_threshold_ms: number;
  alert_email: string;
  disabled_at: number | null;
  disabled_by: string;
  disable_reason: string;
}

export interface PaymentHealthConfigUpdate {
  alert_error_rate_threshold?: number;
  alert_latency_threshold_ms?: number;
  alert_email?: string;
}

export interface PaymentHealthToggleIn {
  enabled: boolean;
  reason?: string;
}

export interface PaymentHealthToggleOut {
  provider: string;
  enabled: boolean;
  toggled_at: number;
  reason: string;
}

export interface PaymentHealthIncident {
  incident_id: string;
  provider: string;
  started_at: number;
  ended_at: number | null;
  status: string;
  peak_error_rate: number;
  affected_webhooks: number;
}

export interface PaymentHealthUptimeReport {
  provider: string;
  days: number;
  uptime_pct: number;
  total_incidents: number;
  total_downtime_minutes: number;
}

// --- Delegation API (DELEGATE-005) ---

export interface DelegationApiKeyCreateReq {
  label: string;
  creator_id: string;
  permissions: string[];
  expires_in_days?: number | null;
}

export interface DelegationApiKeyOut {
  key_id: string;
  label: string;
  owner_sub: string;
  creator_id: string;
  permissions: string[];
  preset?: string | null;
  status: string;
  prefix: string;
  rate_limit_rpm: number;
  total_calls: number;
  last_used_at: number;
  created_at: number;
  expires_at: number;
  key_secret?: string | null;
}

export interface DelegationApiKeyAction {
  method: string;
  path: string;
  description: string;
}

export interface DelegationApiKeyScopeOut {
  key_id: string;
  creator_id: string;
  permissions: string[];
  preset?: string | null;
  available_actions: DelegationApiKeyAction[];
  rate_limit_rpm: number;
  total_calls: number;
}

// ── SSH Session Recording & Playback (INFRA-010) ──────────────────
export interface StartSshRecordingIn {
  hostname: string;
  port?: number;
  username?: string;
  terminal_cols?: number;
  terminal_rows?: number;
  host_id?: string;
  session_id?: string;
}

export interface SshRecordingEventIn {
  offset?: number;
  type?: "o" | "i";
  data?: string;
}

export interface AppendSshRecordingEventsIn {
  events: SshRecordingEventIn[];
}

export interface SshRecordingOut {
  recording_id: string;
  session_id: string;
  host_id: string;
  hostname: string;
  port: number;
  username: string;
  host_key: string;
  status: string;
  start_time: number;
  end_time: number;
  duration_seconds: number;
  file_size_bytes: number;
  terminal_cols: number;
  terminal_rows: number;
  event_count: number;
  created_at: number;
  retention_days: number;
  expires_at: number;
}

export interface SshRecordingListOut {
  recordings: SshRecordingOut[];
  count: number;
}

export type SshRecordingEvent = [number, string, string];

export interface SshRecordingPlaybackOut {
  recording_id: string;
  content_type: string;
  header: Record<string, unknown>;
  events: SshRecordingEvent[];
  event_count: number;
}

// ─── VOD-019: Rental / View-Once Access ───────────────────────────────────────

export interface VodRentalStartRequest {
  tier: "rental" | "view_once";
  payment_method_id?: string;
  rental_duration_hours?: number;
}

export interface VodRentalStartResponse {
  video_id: string;
  rental_id: string;
  tier: string;
  already_active: boolean;
  started: boolean;
  expires_at?: number | null;
  views_remaining: number;
  amount_cents: number;
  duration_hours?: number | null;
}

export interface VodRentalAccess {
  active: boolean;
  tier: string;
  reason: string;
  expires_at?: number | null;
  remaining_seconds: number;
  views_remaining: number;
  rental_id: string;
  started: boolean;
}

export interface VodRentalPlayback {
  video_id: string;
  playback_url: string;
  manifest_key: string;
  mode: string;
  thumbnail_url?: string | null;
  token_expires_at: number;
  access: VodRentalAccess;
}

export interface VodRentalStatus {
  video_id: string;
  rental_id: string;
  tier: string;
  amount_cents: number;
  created_at: number;
  started_at: number;
  duration_hours: number;
  active: boolean;
  reason: string;
  expires_at?: number | null;
  remaining_seconds: number;
  views_remaining: number;
  started: boolean;
}

export interface VodRentalList {
  items: VodRentalStatus[];
}

// ── Per-Content Revenue Breakdown (FIN-006) ──────────────────────────

export interface ContentRevenueItem {
  content_id: string;
  content_type: string; // "vod" | "post" | "broadcast"
  title: string;
  published_at: number;
  tips_cents: number;
  unlocks_cents: number;
  subscriptions_cents: number;
  ads_cents: number;
  vod_cents: number;
  total_cents: number;
}

export interface ContentRevenueListResponse {
  items: ContentRevenueItem[];
  total_items: number;
  total_revenue_cents: number;
  next_cursor: string | null;
  currency: string;
}

export interface ContentRevenueTimeSeriesPoint {
  date: string;
  tips_cents: number;
  unlocks_cents: number;
  subscriptions_cents: number;
  ads_cents: number;
  vod_cents: number;
  total_cents: number;
}

export interface ContentRevenueDetailResponse {
  content_id: string;
  content_type: string;
  title: string;
  published_at: number;
  tips_cents: number;
  unlocks_cents: number;
  subscriptions_cents: number;
  ads_cents: number;
  vod_cents: number;
  total_cents: number;
  time_series: ContentRevenueTimeSeriesPoint[];
  currency: string;
}

export interface ContentRevenueListParams {
  from_date?: string;
  to_date?: string;
  sort_by?: string;
  sort_order?: string;
  content_type?: string;
  limit?: number;
  cursor?: string;
}

// ---------------------------------------------------------------------------
// Instance Monitoring & Health (INFRA-008)
// ---------------------------------------------------------------------------

export interface InstanceMetricIngestIn {
  cpu_pct: number;
  mem_pct: number;
  disk_pct: number;
  net_in_kbps?: number;
  net_out_kbps?: number;
  status?: string;
  ts?: number;
}

export interface InstanceMonitoringSeedIn {
  points?: number;
  interval_seconds?: number;
  base_cpu_pct?: number;
  base_mem_pct?: number;
  base_disk_pct?: number;
}

export interface InstanceMetricPoint {
  instance_id: string;
  ts: number;
  cpu_pct: number;
  mem_pct: number;
  disk_pct: number;
  net_in_kbps: number;
  net_out_kbps: number;
  status: string;
}

export interface InstanceMetricLatestOut {
  instance_id: string;
  has_data: boolean;
  point: InstanceMetricPoint | null;
}

export interface InstanceMetricSeriesOut {
  instance_id: string;
  points: InstanceMetricPoint[];
  count: number;
}

export type InstanceHealthStatus = "healthy" | "warning" | "critical" | "unknown";

export interface InstanceHealthOut {
  instance_id: string;
  instance_type: string;
  instance_status: string;
  health_status: InstanceHealthStatus;
  reasons: string[];
  cpu_pct: number;
  mem_pct: number;
  disk_pct: number;
  datapoints: number;
  last_metric_ts: number;
  checked_at: number;
  thresholds: Record<string, number>;
}

export interface InstanceMonitoringIngestOut {
  instance_id: string;
  ts: number;
  health_status: InstanceHealthStatus;
  stored: boolean;
}

// -- Consumer Tax Documents (FIN-004) --

export interface SpendingCategory {
  category: string;
  total_cents: number;
  transaction_count: number;
}

export interface SpendingSummary {
  date_from: number;
  date_to: number;
  categories: SpendingCategory[];
  grand_total_cents: number;
  transaction_count: number;
  currency: string;
}

export interface YearComparison {
  current_year: number;
  previous_year: number;
  current_summary: SpendingSummary;
  previous_summary: SpendingSummary;
  change_pct: number;
}

export interface TaxDocument {
  doc_id: string;
  doc_type: string;
  year?: number;
  date_from: number;
  date_to: number;
  grand_total_cents: number;
  transaction_count: number;
  currency: string;
  created_at: number;
}

export interface TaxDocumentList {
  documents: TaxDocument[];
}

// ── Creator 1099 / Tax-Form Generation (FIN-008) ────────────────────────────
// Platform-issuer side: annual 1099-NEC earnings forms for creators/payees.
// DISTINCT from the consumer TaxDocument types above.

export interface TaxForm1099 {
  form_id: string;
  user_sub: string;
  tax_year: number;
  total_earnings_cents: number;
  qualifies: boolean;
  status: string;
  correction_count: number;
  generated_at: number;
  updated_at: number;
  payer_name: string;
  payer_tin_last4: string;
  download_url?: string | null;
}

export interface TaxForm1099List {
  items: TaxForm1099[];
}

export interface TaxForm1099Download {
  download_url: string;
}

export interface BatchGenerateTaxForm1099Result {
  tax_year: number;
  total_creators: number;
  qualifying: number;
  generated: number;
  skipped: number;
  errors: number;
}

// ── Admin Ad Platform Management (ADS-018) ──────────────────────────────────

export interface AdminAdAccount {
  account_id: string;
  owner_sub: string;
  company_name: string;
  billing_email: string;
  status: string;
  balance_cents: number;
  lifetime_spend_cents: number;
  created_at: number;
  updated_at: number;
}

export interface AdminAdCampaign {
  campaign_id: string;
  account_id: string;
  name: string;
  objective: string;
  status: string;
  budget_cents: number;
  lifetime_spent_cents: number;
  created_at: number;
}

export interface AdminAdCreative {
  creative_id: string;
  campaign_id: string;
  account_id: string;
  format: string;
  title: string;
  status: string;
  created_at: number;
}

export interface AdminAdAccountDetail {
  account: AdminAdAccount;
  campaigns: AdminAdCampaign[];
  campaign_count: number;
}

export interface AdminAdModerationAction {
  action: "approve" | "reject" | "suspend";
  reason?: string;
  notes?: string;
}

export interface AdminAdModerationResult {
  ok: boolean;
  item_type: string;
  item_id: string;
  status: string;
}

export interface AdminAdModerationEvent {
  event_id: string;
  item_type: string;
  item_id: string;
  action: string;
  admin_sub: string;
  reason: string;
  notes: string;
  prev_status: string;
  new_status: string;
  created_at: number;
}

export interface AdminAdPlatformMetrics {
  total_spend_cents: number;
  platform_revenue_cents: number;
  creator_share_cents: number;
  revenue_share_percent: number;
  impressions: number;
  clicks: number;
  conversions: number;
  effective_cpm_cents: number;
  account_count: number;
  campaign_count: number;
  creative_count: number;
  accounts_by_status: Record<string, number>;
  campaigns_by_status: Record<string, number>;
  creatives_by_status: Record<string, number>;
  pending_account_reviews: number;
  pending_creative_reviews: number;
}

export interface AdminAdRevenuePoint {
  month: string;
  spend_cents: number;
  platform_revenue_cents: number;
  creator_share_cents: number;
  impressions: number;
  clicks: number;
}

export interface AdminAdTopSpender {
  account_id: string;
  company_name: string;
  owner_sub: string;
  spend_cents: number;
}

export interface AdminAdModerationQueue {
  accounts: AdminAdAccount[];
  creatives: AdminAdCreative[];
  account_count: number;
  creative_count: number;
}

// ── Multi-Hop SSH Bastion (INFRA-011) ──────────────────────────────

export interface SshBastionHopIn {
  hostname: string;
  port?: number;
  username: string;
  ssh_key_id?: string;
  label?: string;
}

export interface SshBastionHopOut {
  hostname: string;
  port: number;
  username: string;
  ssh_key_id: string;
  label: string;
  is_bastion: boolean;
  hop_number: number;
}

export interface CreateSshBastionPathIn {
  label: string;
  description?: string;
  jump_hops: SshBastionHopIn[];
  target: SshBastionHopIn;
}

export interface UpdateSshBastionPathIn {
  label?: string;
  description?: string;
  jump_hops?: SshBastionHopIn[];
  target?: SshBastionHopIn;
}

export interface SshBastionPathOut {
  path_id: string;
  label: string;
  description: string;
  hops: SshBastionHopOut[];
  total_hops: number;
  created_at: number;
  updated_at: number;
}

export interface SshBastionPathListOut {
  paths: SshBastionPathOut[];
  total: number;
}

export interface SshBastionResolvedOut {
  path_id: string;
  label: string;
  chain: SshBastionHopOut[];
  jump_hops: SshBastionHopOut[];
  target: SshBastionHopOut;
  total_hops: number;
  proxy_jump: string;
  ssh_command: string;
  ssh_config: string;
}

// ─── Connection Profiles & Quick Connect (INFRA-006) ───────────────────────

export type ConnectionProtocol = "ssh" | "vnc";
export type ConnectionAuthMethod = "key" | "key_ref" | "password";
export type TerminalColorScheme =
  | "dark"
  | "light"
  | "monokai"
  | "solarized"
  | "dracula";

export interface ConnectionProfile {
  profile_id: string;
  label: string;
  protocol: ConnectionProtocol;
  hostname: string;
  instance_id: string;
  port: number;
  username: string;
  auth_method: ConnectionAuthMethod;
  ssh_key_id: string;
  bastion_path_id: string;
  terminal_cols: number;
  terminal_rows: number;
  terminal_font_size: number;
  terminal_color_scheme: TerminalColorScheme;
  is_favorite: boolean;
  auto_connect: boolean;
  use_count: number;
  created_at: number;
  updated_at: number;
  last_used_at: number;
}

export interface ConnectionProfileList {
  profiles: ConnectionProfile[];
  total: number;
}

export interface CreateConnectionProfileInput {
  label: string;
  protocol?: ConnectionProtocol;
  hostname?: string;
  instance_id?: string;
  port?: number;
  username?: string;
  auth_method?: ConnectionAuthMethod;
  ssh_key_id?: string;
  bastion_path_id?: string;
  terminal_cols?: number;
  terminal_rows?: number;
  terminal_font_size?: number;
  terminal_color_scheme?: TerminalColorScheme;
  is_favorite?: boolean;
  auto_connect?: boolean;
}

export interface UpdateConnectionProfileInput {
  label?: string;
  hostname?: string;
  instance_id?: string;
  port?: number;
  username?: string;
  auth_method?: ConnectionAuthMethod;
  ssh_key_id?: string;
  bastion_path_id?: string;
  terminal_cols?: number;
  terminal_rows?: number;
  terminal_font_size?: number;
  terminal_color_scheme?: TerminalColorScheme;
  is_favorite?: boolean;
  auto_connect?: boolean;
}

export interface QuickConnectBastion {
  path_id: string;
  proxy_jump: string;
  ssh_command: string;
  total_hops: number;
}

export interface QuickConnectResult {
  profile_id: string;
  label: string;
  protocol: ConnectionProtocol;
  hostname: string;
  port: number;
  username: string;
  auth_method: ConnectionAuthMethod;
  ssh_key_id: string;
  bastion_path_id: string;
  bastion: QuickConnectBastion | null;
  terminal_cols: number;
  terminal_rows: number;
  terminal_font_size: number;
  terminal_color_scheme: TerminalColorScheme;
  auto_connect: boolean;
  connected_at: number;
}

// ─── License Compliance (LICENSE-006) ──────────────────────────────────────

export interface ComplianceStatusOut {
  content_id: string;
  content_type: string;
  creator_id: string;
  compliance_status: string;
  issues: Array<Record<string, unknown>>;
  last_checked_at: number | null;
  resolved_at: number | null;
  resolved_by: string | null;
}

export interface LicenseRefOut {
  license_id: string;
  license_type: string;
  license_status: string;
  expires_at: number | null;
  verified_at: number | null;
}

export interface LicenseRefListOut {
  items: LicenseRefOut[];
}

export interface ComplianceFlagOut {
  flag_id: string;
  content_id: string;
  reporter_id: string;
  reporter_type: string;
  reason: string;
  evidence: string;
  status: string;
  created_at: number;
  resolved_at: number | null;
  resolved_by: string | null;
  resolution_notes: string;
}

export interface ComplianceFlagListOut {
  items: ComplianceFlagOut[];
  next_cursor?: string | null;
}

export interface ComplianceCheckResultOut {
  content_id: string;
  compliance_status: string;
  issues: Array<Record<string, unknown>>;
  checked_at: number;
}

export interface CreatorComplianceItemOut {
  content_id: string;
  content_type: string;
  compliance_status: string;
  issue_count: number;
  last_checked_at: number | null;
}

export interface ComplianceSummaryOut {
  total: number;
  compliant: number;
  expiring_soon: number;
  issues: number;
  flagged: number;
}

export interface CreatorComplianceListOut {
  items: CreatorComplianceItemOut[];
  summary: ComplianceSummaryOut;
  next_cursor?: string | null;
}

export interface AdminComplianceIssueOut {
  content_id: string;
  creator_id: string;
  creator_display_name: string;
  compliance_status: string;
  issue_type: string;
  severity: string;
  created_at: number;
}

export interface AdminComplianceIssueListOut {
  items: AdminComplianceIssueOut[];
  next_cursor?: string | null;
}

export interface ComplianceScanResultOut {
  checked: number;
  issues_found: number;
  alerts_sent: number;
}

// ─── Background Job Dashboard (PLATFORM-008) ─────────────────────────

export interface JobRegistryEntry {
  name: string;
  label: string;
  source: string;
  description: string;
  poll_interval_seconds: number;
  run_now_safe: boolean;
}

export interface JobRegistryOut {
  jobs: JobRegistryEntry[];
}

export interface JobRunOut {
  job_name: string;
  run_id: string;
  status: string;
  started_at: number;
  finished_at: number;
  duration_ms: number;
  items_processed: number;
  items_failed: number;
  error?: string | null;
  triggered_by: string;
}

export interface JobRunsOut {
  items: JobRunOut[];
  count: number;
}

export interface JobHealthEntry {
  name: string;
  label: string;
  description: string;
  poll_interval_seconds: number;
  run_now_safe: boolean;
  health: "ok" | "degraded" | "failed" | "unknown";
  last_status?: string | null;
  last_run_at?: number | null;
  last_finished_at?: number | null;
  last_duration_ms?: number | null;
  last_error?: string | null;
  last_items_processed: number;
  last_items_failed: number;
  next_run_at?: number | null;
}

export interface JobHealthOut {
  jobs: JobHealthEntry[];
  timestamp: number;
}

export interface JobRunNowOut {
  ok: boolean;
  job_name: string;
  run: JobRunOut;
}

// GROUP-003: Group Advertising & Fundraising
export interface GroupFundraiser {
  fundraiser_id: string;
  group_id: string;
  title: string;
  description: string;
  goal_cents?: number | null;
  raised_cents: number;
  donation_count: number;
  currency: string;
  status: "active" | "paused" | "completed" | "cancelled";
  cover_image_url?: string | null;
  created_at: number;
  ends_at?: number | null;
}

export interface GroupFundraiserListResponse {
  fundraisers: GroupFundraiser[];
}

export interface GroupPublicFundraiser extends GroupFundraiser {
  group_name: string;
}

export interface GroupDonation {
  donation_id: string;
  amount_cents: number;
  donor_name?: string | null;
  status: "pending" | "completed" | "failed" | "refunded";
  created_at: number;
  is_external: boolean;
  checkout_url?: string | null;
}

export interface GroupDonationListResponse {
  donations: GroupDonation[];
  cursor?: string | null;
  has_more: boolean;
}

export interface GroupDonationReceipt {
  donation_id: string;
  amount_cents: number;
  currency: string;
  donor_name?: string | null;
  group_name: string;
  fundraiser_title: string;
  created_at: number;
  status: string;
}

export interface GroupCampaign {
  campaign_id: string;
  group_id: string;
  name: string;
  status: "active" | "paused" | "completed" | "draft";
  daily_budget_cents: number;
  lifetime_budget_cents: number;
  spent_cents: number;
  impressions: number;
  clicks: number;
  creative_text?: string | null;
  creative_image_url?: string | null;
  created_at: number;
}

export interface GroupCampaignListResponse {
  campaigns: GroupCampaign[];
}

export interface GroupCampaignStats {
  campaign_id: string;
  impressions: number;
  clicks: number;
  ctr: number;
  spent_cents: number;
  remaining_cents: number;
  daily_spent_cents: number;
  daily_budget_cents: number;
  status: string;
}



// --- Content Boost (ADS-012) ---

export interface ContentBoost {
  boost_id: string;
  owner_sub: string;
  content_type: string;
  content_id: string;
  budget_cents: number;
  spent_cents: number;
  remaining_cents: number;
  duration_seconds: number;
  starts_at: number;
  ends_at: number;
  status: string;
  created_at: number;
}

export interface ContentBoostListResponse {
  boosts: ContentBoost[];
}

export interface ContentBoostSpend {
  boost_id: string;
  budget_cents: number;
  spent_cents: number;
  remaining_cents: number;
  status: string;
}

export interface ContentBoostCancelResponse {
  boost_id: string;
  status: string;
  refunded_cents: number;
}

export interface ContentBoostCreateInput {
  content_type: string;
  content_id: string;
  budget_cents: number;
  duration_seconds: number;
}
// ── PLATFORM-013: Theme Customization ────────────────────────────────────────

export type ThemeMode = "light" | "dark" | "system";
export type ThemeAccentColor =
  | "blue"
  | "purple"
  | "green"
  | "orange"
  | "pink"
  | "red"
  | "teal"
  | "custom";
export type ThemeFontScale = "small" | "default" | "large" | "xlarge";
export type ThemeDensity = "compact" | "comfortable" | "spacious";
export type ThemePreset = "default" | "midnight" | "sunrise" | "forest" | "ocean";

export interface ThemeConfig {
  mode: ThemeMode;
  accent_color: ThemeAccentColor;
  custom_accent_hex: string | null;
  font_scale: ThemeFontScale;
  density: ThemeDensity;
  preset: ThemePreset;
  high_contrast: boolean;
}

export interface ThemeConfigResponse {
  theme: ThemeConfig;
}

export type ThemeConfigPatch = Partial<ThemeConfig>;

// ── PLATFORM-005: SEO / OpenGraph metadata ──────────────────────────
export interface SeoOpenGraphTags {
  "og:title"?: string;
  "og:description"?: string;
  "og:type"?: string;
  "og:site_name"?: string;
  "og:locale"?: string;
  "og:url"?: string;
  "og:image"?: string;
  [key: string]: string | undefined;
}

export interface SeoTwitterTags {
  "twitter:card"?: string;
  "twitter:title"?: string;
  "twitter:description"?: string;
  "twitter:image"?: string;
  [key: string]: string | undefined;
}

export interface SeoMetadata {
  resource_type: string | null;
  resource_id: string | null;
  available: boolean;
  title: string;
  description: string;
  canonical_url: string;
  site_name: string;
  locale: string;
  og: SeoOpenGraphTags;
  twitter: SeoTwitterTags;
  image: string | null;
  json_ld: Record<string, unknown> | null;
}

// VOD-018: Ad-Supported Viewing Tier
export interface VodAdBreak {
  break_id: string;
  slot_type: "pre_roll" | "mid_roll" | "overlay";
  position_seconds: number;
  duration_seconds: number;
  creative_id: string;
  creative_url: string;
  creative_type: "video" | "image";
  skip_after_seconds: number;
  slot_index: number;
  completed: boolean;
}

export interface VodAdSupportedSession {
  session_id: string;
  video_id: string;
  status: "active" | "completed" | "abandoned";
  ad_schedule: VodAdBreak[];
  breaks_total: number;
  breaks_completed: number;
  next_required_break_id: string | null;
  playback_unlocked: boolean;
  ads_free: boolean;
  created_at: number;
  updated_at: number;
}

export interface VodAdSupportedStartResponse extends VodAdSupportedSession {
  playback_url: string;
  manifest_key: string;
  mode: string;
  thumbnail_url: string | null;
  token_expires_at: number;
}

export interface VodAdSupportedStartRequest {
  resume_position_seconds?: number;
}

export interface VodAdBreakReportRequest {
  break_id: string;
  event_type?: "impression" | "complete" | "skip";
}

export interface VodAdBreakReportResponse {
  ok: boolean;
  session_id: string;
  video_id: string;
  break_id: string;
  event_type: string;
  completed: boolean;
  breaks_completed: number;
  breaks_total: number;
  next_required_break_id: string | null;
  playback_unlocked: boolean;
  status: string;
}

// ─── VOD-020: Watermarked Downloads (per-viewer render) ──────────────────────

export interface VodWatermarkDownloadResponse {
  status: "ready" | "processing" | "failed";
  render_id: string;
  download_url?: string | null;
  cached?: boolean;
  watermark_payload?: string | null;
  output_size_bytes?: number | null;
}

export interface VodWatermarkDownloadStatusResponse {
  status: "ready" | "processing" | "failed" | "not_found";
  render_id?: string | null;
  download_url?: string | null;
  output_size_bytes?: number | null;
  created_at?: number | null;
  error?: string | null;
}

export interface VodWatermarkRenderItem {
  render_id: string;
  video_id: string;
  viewer_id: string;
  watermark_payload: string;
  status: string;
  created_at: number;
  output_size_bytes?: number | null;
}

export interface VodWatermarkRenderListResponse {
  items: VodWatermarkRenderItem[];
}

export interface VodWatermarkExtractResponse {
  found: boolean;
  payload?: string | null;
  decoded?: Record<string, unknown> | null;
}

// ── Sponsored Content & Creator Partnerships (ADS-013) ──────────────

export type SponsorshipDealStatus =
  | "proposed"
  | "negotiating"
  | "accepted"
  | "content_submitted"
  | "completed"
  | "rejected"
  | "cancelled";

export interface SponsorshipDealCreate {
  advertiser_account_id: string;
  creator_sub: string;
  content_type: "post" | "video" | "broadcast";
  brief: string;
  deliverables: string[];
  compensation_cents: number;
  cpm_bonus_cents?: number;
  deadline: string;
}

export interface SponsorshipPaymentDetails {
  total_cents?: number;
  commission_cents?: number;
  creator_cents?: number;
  advertiser_cents?: number;
}

export interface SponsorshipDeal {
  deal_id: string;
  advertiser_account_id: string;
  advertiser_sub: string;
  creator_sub: string;
  content_type: string;
  brief: string;
  deliverables: string[];
  compensation_cents: number;
  cpm_bonus_cents: number;
  platform_commission_bps: number;
  status: SponsorshipDealStatus;
  deadline: string;
  content_id?: string | null;
  dm_conversation_id?: string | null;
  escrow_hold_id?: string | null;
  created_at: number;
  updated_at: number;
  completed_at?: number | null;
  cancelled_at?: number | null;
  cancel_reason?: string | null;
  payment_details?: SponsorshipPaymentDetails | null;
}

export interface SponsorshipDealEvent {
  event_id: string;
  event_type: string;
  actor_sub: string;
  details: Record<string, unknown>;
  created_at: number;
}

// Image Optimization (PLATFORM-004) - on-demand optimization records
export interface ImageOptimizationVariant {
  url: string;
  width: number;
  height: number;
  size_bytes: number;
  format: string;
}

export interface ImageOptimizationRecord {
  optimization_id: string;
  owner_sub: string;
  source_key: string;
  source_url: string;
  output_format: string;
  variants: Record<string, ImageOptimizationVariant>;
  cached: boolean;
  created_at: number;
}

export interface ImageOptimizeRequest {
  source_key?: string;
  source_url?: string;
  format?: string;
  use_cache?: boolean;
}


// ── Syndicate Treasury / Fund Management (SYND-004) ──────────────────────────

export interface SyndicateTreasuryBalanceOut {
  syndicate_id: string;
  balance_cents: number;
  total_deposited_cents: number;
  total_disbursed_cents: number;
  currency: string;
  updated_at: number;
}

export interface SyndicateTreasuryDepositOut {
  ok: boolean;
  amount_cents: number;
  new_personal_balance_cents: number;
  new_treasury_balance_cents: number;
  treasury_entry_id: string;
  user_entry_id: string;
}

export interface SyndicateTreasuryDisburseOut {
  ok: boolean;
  amount_cents: number;
  recipient_user_id: string;
  new_treasury_balance_cents: number;
  new_recipient_balance_cents: number;
  treasury_entry_id: string;
  user_entry_id: string;
}

export interface SyndicateTreasuryLedgerEntryOut {
  entry_id: string;
  ts: number;
  direction: string;
  amount_cents: number;
  reason: string;
  actor_user_id: string;
  counterparty_user_id: string;
  currency: string;
}

export interface SyndicateTreasuryLedgerOut {
  entries: SyndicateTreasuryLedgerEntryOut[];
  cursor: string | null;
  has_more: boolean;
}

export interface SyndicateTreasuryContributorOut {
  user_id: string;
  total_contributed_cents: number;
  total_refunded_cents: number;
  net_contributed_cents: number;
  contribution_count: number;
  last_contribution_at: number;
}


// ── Syndicate Advertising (SYND-006) ────────────────────────────────────────

export interface SyndicateCampaignCreativeIn {
  headline: string;
  body: string;
  image_url?: string | null;
  cta_text: string;
  cta_url: string;
}

export interface SyndicateCampaignTargetingIn {
  audience?: string;
  interests?: string[];
  geo?: string | null;
  age_min?: number | null;
  age_max?: number | null;
}

export interface SyndicateCampaignCreateIn {
  name: string;
  description?: string;
  budget_cents: number;
  creative: SyndicateCampaignCreativeIn;
  targeting?: SyndicateCampaignTargetingIn | null;
  start_date?: string;
  end_date?: string | null;
}

export interface SyndicateCampaignOut {
  campaign_id: string;
  syndicate_id: string;
  name: string;
  description: string;
  status: string;
  budget_cents: number;
  spent_cents: number;
  remaining_cents: number;
  creative: Record<string, unknown>;
  targeting: Record<string, unknown>;
  start_date: string;
  end_date: string;
  created_by: string;
  created_at: number;
  updated_at: number;
  stats_summary: Record<string, unknown>;
}

export interface SyndicateCampaignDailyStatsOut {
  date: string;
  impressions: number;
  clicks: number;
  spend_cents: number;
  unique_viewers: number;
}

export interface SyndicateCampaignAnalyticsOut {
  campaign_id: string;
  daily: SyndicateCampaignDailyStatsOut[];
  totals: Record<string, unknown>;
}


// ── KYC-006: Sanctions / PEP Screening ──────────────────────────────────────

export type KycScreenType =
  | "sanctions_ofac"
  | "sanctions_eu"
  | "sanctions_un"
  | "pep_check"
  | "adverse_media";

export type KycScreeningResultStatus = "clear" | "potential_match" | "confirmed_match";
export type KycScreeningDecision = "clear" | "confirm" | "escalate";
export type KycScreeningTrigger =
  | "submission"
  | "profile_change"
  | "continuous_monitoring"
  | "manual";

export interface KycScreeningMatchDetail {
  list_name: string;
  matched_name: string;
  matched_dob?: string | null;
  match_score: number;
  entity_id: string;
  entity_type: "individual" | "entity" | "vessel" | "aircraft";
  listed_since?: string | null;
  source_url?: string | null;
}

export interface KycScreeningResultOut {
  screening_id: string;
  case_id?: string | null;
  screen_key?: string | null;
  screen_type: KycScreenType;
  user_sub?: string | null;
  result: KycScreeningResultStatus;
  match_details: KycScreeningMatchDetail[];
  reviewed_by?: string | null;
  review_decision?: KycScreeningDecision | null;
  review_note?: string | null;
  reviewed_at?: number | null;
  trigger: KycScreeningTrigger;
  provider: string;
  created_at: number;
}

export interface KycScreeningResultsListResponse {
  results: KycScreeningResultOut[];
}

export interface KycScreeningPendingReviewsResponse {
  items: KycScreeningResultOut[];
  cursor?: string | null;
}

export interface KycScreeningUserHistoryResponse {
  user_sub: string;
  results: KycScreeningResultOut[];
  total: number;
}

export interface KycScreeningRunRequest {
  user_sub: string;
  case_id?: string | null;
  name?: string | null;
  dob?: string | null;
  country?: string | null;
}

export interface KycScreeningRescreenResponse {
  ok: boolean;
  case_id: string;
  user_sub: string;
  results_count: number;
  trigger: KycScreeningTrigger;
  matches_found: number;
  results: KycScreeningResultOut[];
}

export interface KycScreeningReviewRequest {
  decision: KycScreeningDecision;
  note: string;
}

// ─── FIN-018: Billing Configuration UI ──────────────────────────────────────

export interface BillingConfigOut {
  fee_tips_bps: number;
  fee_unlocks_bps: number;
  fee_subscriptions_bps: number;
  fee_catalog_bps: number;
  fee_ad_revenue_bps: number;
  min_payout_cents: number;
  payout_fee_cents: number;
  payout_schedule: string;
  auto_payout_enabled: boolean;
  min_deposit_cents: number;
  max_deposit_cents: number;
  deposit_fee_bps: number;
  default_currency: string;
  supported_currencies: string[];
  tax_enabled: boolean;
  default_tax_rate_bps: number;
  updated_at: number | null;
  updated_by: string | null;
}

export interface BillingConfigUpdate {
  fee_tips_bps?: number;
  fee_unlocks_bps?: number;
  fee_subscriptions_bps?: number;
  fee_catalog_bps?: number;
  fee_ad_revenue_bps?: number;
  min_payout_cents?: number;
  payout_fee_cents?: number;
  payout_schedule?: string;
  auto_payout_enabled?: boolean;
  min_deposit_cents?: number;
  max_deposit_cents?: number;
  deposit_fee_bps?: number;
  default_currency?: string;
  supported_currencies?: string[];
  tax_enabled?: boolean;
  default_tax_rate_bps?: number;
}

export interface BillingConfigAuditChange {
  field: string;
  old_value: string | number | null;
  new_value: string | number | null;
}

export interface BillingConfigAuditEntry {
  admin_sub: string;
  changes: BillingConfigAuditChange[];
  created_at: number;
}

export interface BillingConfigAuditLog {
  entries: BillingConfigAuditEntry[];
  count: number;
  cursor: string | null;
}

export interface BillingConfigSample {
  amount_cents: number;
  fee_cents: number;
  net_cents: number;
}

export interface BillingConfigPreview {
  affected_tx_types: string[];
  projected_daily_delta_cents: number;
  sample_before: BillingConfigSample;
  sample_after: BillingConfigSample;
}


// ─── Ad Creative Affiliate Discounts (ADS-015) ─────────────────────
export interface AdAffiliateDiscount {
  creative_id: string;
  campaign_id: string;
  owner_sub: string;
  affiliate_code?: string | null;
  promo_code?: string | null;
  promo_value_display?: string | null;
  click_through_url?: string | null;
  click_count: number;
  redemption_count: number;
  created_at: number;
  updated_at: number;
}

export interface AdAffiliateDiscountList {
  items: AdAffiliateDiscount[];
}

export interface AdAffiliateClickResult {
  redirect_url: string;
  affiliate_code?: string | null;
  promo_code?: string | null;
  promo_value_display?: string | null;
}

export interface AdAffiliateRedeemResult {
  valid: boolean;
  creative_id: string;
  promo_code?: string | null;
  affiliate_code?: string | null;
  discount_type?: string | null;
  discount_cents: number;
  final_price_cents: number;
  message?: string | null;
}

export interface AdAffiliateStats {
  creative_id: string;
  click_count: number;
  redemption_count: number;
  total_discount_cents: number;
}

// ── Content-Provider Ad Controls (ADS-010) ──────────────────────────────────

export interface ContentAdOverride {
  content_id: string;
  content_type: string;
  owner_sub?: string | null;
  ad_enabled: boolean;
  ad_density: "low" | "standard" | "high";
  pre_roll_enabled: boolean;
  mid_roll_enabled: boolean;
  ads_free_for_subscribers: boolean;
  updated_at?: number | null;
}

export interface ContentAdOverrideInput {
  content_type?: string;
  ad_enabled?: boolean;
  ad_density?: "low" | "standard" | "high";
  pre_roll_enabled?: boolean;
  mid_roll_enabled?: boolean;
  ads_free_for_subscribers?: boolean;
}

export interface AdRevenueBreakdownContent {
  content_id: string;
  revenue_cents: number;
}

export interface AdRevenueBreakdown {
  total_ad_revenue_cents: number;
  entry_count: number;
  days: number;
  revenue_share_bps: number;
  top_content: AdRevenueBreakdownContent[];
}

export interface AdvertiserTransparency {
  account_id: string;
  company_name: string;
  total_impressions: number;
  total_clicks: number;
  total_revenue_cents: number;
}

export interface RevenueShare {
  revenue_share_bps: number;
}


// -- Syndicate Page & Newsfeed (SYND-005) --

export interface SyndicateFeedMember {
  user_id: string;
  display_name: string;
  role: string;
  joined_at: number;
}

export interface SyndicateBundlePlan {
  plan_id: string;
  plan_type: string;
  syndicate_id: string;
  name: string;
  description: string;
  price_cents: number;
  interval: string;
  status: string;
  included_creator_ids: string[];
  created_at: number;
}

export interface SyndicateProfile {
  syndicate_id: string;
  name: string;
  description: string;
  avatar_url: string;
  banner_url: string;
  website_url: string;
  tags: string[];
  admin_user_id: string;
  status: string;
  member_count: number;
  post_count: number;
  members: SyndicateFeedMember[];
  bundle_plans: SyndicateBundlePlan[];
  is_member: boolean;
  created_at: number;
}

export interface SyndicateProfileUpdate {
  avatar_url?: string;
  banner_url?: string;
  website_url?: string;
  tags?: string[];
  description?: string;
}

export interface SyndicatePost {
  post_id: string;
  author_id: string;
  author_name: string;
  author_avatar: string;
  text: string;
  image_url: string;
  syndicate_id: string;
  visibility: "public" | "members_only";
  created_at: number;
  comment_count: number;
  reaction_counts: Record<string, number>;
  tip_total_cents: number;
}

export interface SyndicatePostCreate {
  text: string;
  visibility: "public" | "members_only";
  image_url?: string | null;
}

export interface SyndicateFeed {
  posts: SyndicatePost[];
  next_cursor: string | null;
  is_member: boolean;
}

// ── Ad Performance Optimization (ADS-017) ──────────────────────────────

export interface OptimizationCreativeStat {
  creative_id: string;
  impressions: number;
  clicks: number;
  ctr: number;
  weight: number;
}

export interface OptimizationRecommendation {
  recommendation_id: string;
  campaign_id: string;
  account_id: string;
  action: "pause_creative" | "reallocate_budget" | "adjust_bid" | string;
  creative_id?: string | null;
  title: string;
  description: string;
  impact: string;
  severity: string;
  details: Record<string, unknown>;
  status: "open" | "applied" | "dismissed" | string;
  created_at: number;
  updated_at: number;
  applied_at?: number | null;
  dismissed_at?: number | null;
}

export interface OptimizationGenerateResult {
  campaign_id: string;
  creative_weights: Record<string, number>;
  creative_stats: OptimizationCreativeStat[];
  underperformers: Array<{
    creative_id: string;
    impressions: number;
    clicks: number;
    ctr: number;
    reason: string;
  }>;
  alerts: Array<{
    alert_type: string;
    severity: string;
    message: string;
  }>;
  recommendations: OptimizationRecommendation[];
  generated_at: number;
}

export interface OptimizationRecommendationList {
  recommendations: OptimizationRecommendation[];
}

export interface ABTestResult {
  variant_a_ctr: number;
  variant_b_ctr: number;
  lift_percent: number;
  z_score: number;
  p_value: number;
  significant: boolean;
  confidence_level: number;
  winner: string | null;
  sample_size_sufficient: boolean;
}

export interface SuggestedBid {
  min_bid_cpm_cents: number;
  suggested_bid_cpm_cents: number;
  max_bid_cpm_cents: number;
  estimated_fill_rate: number;
  competition_level: string;
}

export interface BudgetRecommendation {
  estimated_daily_reach: number;
  recommended_daily_budget_cents: number;
  estimated_cpm_cents: number;
  reach_per_dollar: number;
}

export interface OptimizationConfigUpdate {
  auto_optimize_enabled?: boolean;
  ctr_threshold?: number;
  auto_pause_min_impressions?: number;
  roas_threshold?: number;
  budget_pace_alert_ratio?: number;
}

export interface OptimizationConfigResult {
  ok: boolean;
  auto_optimize_enabled: boolean;
  optimization_config: Record<string, number>;
}

export interface ApplyRecommendationResult {
  ok: boolean;
  status: string;
  action?: string;
  creative_id?: string;
  new_creative_status?: string;
  creative_weights?: Record<string, number>;
  suggested_bid_cpm_cents?: number;
}

// -- Syndicate Open Licensing (LICENSE-005) --

export interface SyndicateOpenLicensingTerms {
  profit_share_pct: number;
  fixed_cost_cents: number;
  revenue_share_pct: number;
  currency: string;
}

export interface SyndicateOpenLicensingConfig {
  syndicate_id: string;
  open_licensing_enabled: boolean;
  open_licensing_terms: SyndicateOpenLicensingTerms | null;
  enabled_at: number | null;
  disabled_at: number | null;
  licenses_created?: number;
}

export interface SyndicateOpenLicensingContent {
  content_id: string;
  content_type: string;
  creator_id: string;
  registered_at: number;
  exempt: boolean;
}

export interface SyndicateOpenLicensingRegistration {
  content_id: string;
  syndicate_id: string;
  licenses_created: number;
}

export interface SyndicateOpenLicensingExemption {
  content_id: string;
  syndicate_id: string;
  exempt: boolean;
  revoked_count: number;
  licenses_created: number;
}
