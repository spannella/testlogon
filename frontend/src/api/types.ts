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
}

export interface ApiKeyCreated extends ApiKey {
  key_secret: string;
}

export interface CreateApiKeyReq {
  label?: string;
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
  details?: string;
  delivered?: Record<string, boolean>;
  read_at?: number;
  ts: number;
  ttl_epoch?: number;
}

export interface AlertsResp {
  alerts: Alert[];
  next_cursor?: string;
}

export interface MarkReadReq {
  alert_ids: string[];
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
  participants: Participant[];
  created_at: string;
  updated_at: string;
  last_message?: Message;
  unread_count?: number;
  muted?: boolean;
}

export interface Participant {
  user_id: string;
  role?: string;
  display_name?: string;
  joined_at?: string;
}

export interface Message {
  message_id: string;
  conversation_id: string;
  sender_id: string;
  kind: "text" | "image" | "file" | "audio" | "video";
  body?: string;
  image_url?: string;
  file_url?: string;
  file_name?: string;
  duration_seconds?: number;
  link_preview?: LinkPreview;
  reactions?: Record<string, string[]>;
  edited?: boolean;
  revoked?: boolean;
  created_at: string;
  updated_at?: string;
}

export interface LinkPreview {
  url?: string;
  title?: string;
  description?: string;
  image?: string;
  site_name?: string;
}

export interface SendTextMessageReq {
  body: string;
  link_preview?: LinkPreview;
}

export interface StartConversationReq {
  participant_id: string;
}

export interface StartGroupConversationReq {
  title?: string;
  participant_ids: string[];
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

export interface MessageViewer {
  user_id: string;
  last_viewed_at: number;
  view_count: number;
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

export interface FileEntry {
  name: string;
  path: string;
  type: "file" | "folder";
  size?: number;
  content_type?: string;
  updated_at?: string;
  created_at?: string;
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
}

export interface SharedItem {
  owner: string;
  path: string;
  shared_at: string;
  permission: "read" | "write";
  expires_at?: string | null;
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
  created_at_utc: string;
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

// ─── Shopping Cart ───────────────────────────────────────────────

export interface CartSummary {
  cart_id: string;
  status: string;
  created_at: string;
  purchased_at?: string;
  purchased_total_cents?: number;
  currency: string;
}

export interface CartItemIn {
  sku: string;
  name: string;
  quantity?: number;
  unit_price_cents: number;
}

export interface CartItem {
  sku: string;
  name: string;
  quantity: number;
  unit_price_cents: number;
  line_total_cents: number;
  updated_at: string;
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

export interface FeedPost {
  post_id: string;
  author_id: string;
  body: string;
  image_url?: string;
  unlock_price_cents?: number;
  like_count: number;
  comment_count: number;
  tip_total_cents?: number;
  liked_by_me?: boolean;
  unlocked?: boolean;
  created_at: string;
  updated_at?: string;
}

export interface FeedComment {
  comment_id: string;
  post_id: string;
  author_id: string;
  body: string;
  created_at: string;
  updated_at?: string;
  deleted?: boolean;
  version?: number;
}

export interface CreatePostReq {
  body: string;
  image_url?: string;
  unlock_price_cents?: number;
}

export interface CreateCommentReq {
  body: string;
}

export interface EditPostReq {
  body: string;
}

export interface EditCommentReq {
  body: string;
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

export interface PurchaseShipping {
  carrier?: string;
  tracking_number?: string;
  shipped_at?: number;
  delivered_at?: number;
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
