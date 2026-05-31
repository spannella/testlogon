from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from .aws import ddb
from .settings import S

@dataclass(frozen=True)
class Tables:
    sessions: Any
    totp: Any
    sms: Any
    recovery: Any
    email: Any
    users: Any
    role_audit: Any
    api_keys: Any
    alerts: Any
    alert_prefs: Any
    push_devices: Any
    billing: Any
    payment_incidents: Any
    payment_incident_events: Any
    payment_dispute_evidence: Any
    payment_retry_attempts: Any
    payment_incident_ticket_links: Any
    account_state: Any
    profile: Any
    addresses: Any
    calendar: Any
    purchase_transactions: Any
    purchase_events: Any
    shopping_cart: Any
    catalog: Any
    subscriptions: Any
    projects: Any
    contacts: Any
    broadcast_profiles: Any
    broadcast_sessions: Any
    broadcast_outputs: Any
    broadcast_session_transitions: Any
    broadcast_action_audit: Any
    message_visibility_overrides: Any
    conversation_pins: Any
    message_threads: Any
    message_reports: Any
    mass_message_campaigns: Any
    mass_message_campaign_destinations: Any
    message_report_context: Any
    message_call_sessions: Any
    content_reports: Any
    moderation_tickets: Any
    moderation_actions: Any
    moderation_audit_log: Any
    user_enforcement_history: Any
    dmca_claims: Any
    message_legal_holds: Any
    message_archive_chain_heads: Any
    message_compliance_exports: Any
    catalog_products: Any
    catalog_product_versions: Any
    orders: Any
    order_items: Any
    payments: Any
    entitlements: Any
    entitlement_usage_events: Any
    signature_packets: Any
    signature_packet_signers: Any
    signature_packet_fields: Any
    signature_packet_events: Any
    signature_packet_artifacts: Any
    tickets: Any
    questionnaires: Any
    kyc_cases: Any
    video_metadata: Any
    transcode_jobs: Any
    broadcast_viewers: Any
    broadcast_health_snapshots: Any
    broadcast_chat_messages: Any
    broadcast_chat_mutes: Any
    broadcast_recordings: Any
    broadcast_product_shelf: Any
    vod_entitlements: Any
    appeals: Any
    creator_payouts: Any
    broadcast_reminders: Any
    broadcast_private_sessions: Any
    broadcast_inputs: Any
    broadcast_tip_goals: Any
    video_views: Any
    video_likes: Any
    ad_impressions: Any
    call_billing_ledger: Any
    rate_limits: Any
    rate_limit_events: Any
    analytics_rollups: Any
    data_requests: Any
    data_request_audit: Any
    webhook_endpoints: Any
    webhook_deliveries: Any
    webhook_stats: Any
    promo_codes: Any
    scheduled_actions: Any
    watermark_jobs: Any
    recommendations: Any
    refund_requests: Any
    translations: Any
    group_call_sessions: Any
    sms_delivery: Any
    email_delivery: Any
    affiliate_links: Any
    affiliate_clicks: Any
    audit_exports: Any
    achievements: Any
    user_achievements: Any
    user_achievement_progress: Any
    achievement_leaderboard: Any
    broadcast_qa_questions: Any
    collaboration_agreements: Any
    fan_club_channels: Any
    fan_club_messages: Any
    organizations: Any
    watch_parties: Any
    watch_party_participants: Any
    tenants: Any
    tenant_domains: Any
    tenant_members: Any
    sso_providers: Any
    sso_sessions: Any
    sso_assertion_cache: Any
    broadcast_clips: Any
    kyc_risk_scores: Any

T = Tables(
    sessions=ddb.Table(S.ddb_sessions_table),
    totp=ddb.Table(S.ddb_totp_table),
    sms=ddb.Table(S.ddb_sms_table),
    recovery=ddb.Table(S.ddb_recovery_table),
    email=ddb.Table(S.ddb_email_table),
    users=ddb.Table(S.users_table_name),
    role_audit=ddb.Table(S.role_audit_table_name),
    api_keys=ddb.Table(S.api_keys_table_name),
    alerts=ddb.Table(S.alerts_table_name),
    alert_prefs=ddb.Table(S.alert_prefs_table_name),
    push_devices=ddb.Table(S.push_devices_table_name),
    billing=ddb.Table(S.billing_table_name),
    payment_incidents=ddb.Table(S.payment_incidents_table_name),
    payment_incident_events=ddb.Table(S.payment_incident_events_table_name),
    payment_dispute_evidence=ddb.Table(S.payment_dispute_evidence_table_name),
    payment_retry_attempts=ddb.Table(S.payment_retry_attempts_table_name),
    payment_incident_ticket_links=ddb.Table(S.payment_incident_ticket_links_table_name),
    account_state=ddb.Table(S.account_state_table_name),
    profile=ddb.Table(S.profile_table_name),
    addresses=ddb.Table(S.addresses_table_name),
    calendar=ddb.Table(S.calendar_table_name),
    purchase_transactions=ddb.Table(S.purchase_transactions_table_name),
    purchase_events=ddb.Table(S.purchase_events_table_name),
    shopping_cart=ddb.Table(S.shopping_cart_table_name),
    catalog=ddb.Table(S.catalog_table_name),
    subscriptions=ddb.Table(S.subscriptions_table_name),
    projects=ddb.Table(S.projects_table_name),
    contacts=ddb.Table(S.contacts_table_name),
    broadcast_profiles=ddb.Table(S.broadcast_profiles_table_name),
    broadcast_sessions=ddb.Table(S.broadcast_sessions_table_name),
    broadcast_outputs=ddb.Table(S.broadcast_outputs_table_name),
    broadcast_session_transitions=ddb.Table(S.broadcast_session_transitions_table_name),
    broadcast_action_audit=ddb.Table(S.broadcast_action_audit_table_name),
    message_visibility_overrides=ddb.Table(S.message_visibility_overrides_table_name),
    conversation_pins=ddb.Table(S.conversation_pins_table_name),
    message_threads=ddb.Table(S.message_threads_table_name),
    message_reports=ddb.Table(S.message_reports_table_name),
    mass_message_campaigns=ddb.Table(S.mass_message_campaigns_table_name),
    mass_message_campaign_destinations=ddb.Table(S.mass_message_campaign_destinations_table_name),
    message_report_context=ddb.Table(S.message_report_context_table_name),
    message_call_sessions=ddb.Table(S.message_call_sessions_table_name),
    content_reports=ddb.Table(S.content_reports_table_name),
    moderation_tickets=ddb.Table(S.moderation_tickets_table_name),
    moderation_actions=ddb.Table(S.moderation_actions_table_name),
    moderation_audit_log=ddb.Table(S.moderation_audit_log_table_name),
    user_enforcement_history=ddb.Table(S.user_enforcement_history_table_name),
    dmca_claims=ddb.Table(S.dmca_claims_table_name),
    message_legal_holds=ddb.Table(S.message_legal_holds_table_name),
    message_archive_chain_heads=ddb.Table(S.message_archive_chain_heads_table_name),
    message_compliance_exports=ddb.Table(S.message_compliance_exports_table_name),
    catalog_products=ddb.Table(S.catalog_products_table_name),
    catalog_product_versions=ddb.Table(S.catalog_product_versions_table_name),
    orders=ddb.Table(S.orders_table_name),
    order_items=ddb.Table(S.order_items_table_name),
    payments=ddb.Table(S.payments_table_name),
    entitlements=ddb.Table(S.entitlements_table_name),
    entitlement_usage_events=ddb.Table(S.entitlement_usage_events_table_name),
    signature_packets=ddb.Table(S.signature_packets_table_name),
    signature_packet_signers=ddb.Table(S.signature_packet_signers_table_name),
    signature_packet_fields=ddb.Table(S.signature_packet_fields_table_name),
    signature_packet_events=ddb.Table(S.signature_packet_events_table_name),
    signature_packet_artifacts=ddb.Table(S.signature_packet_artifacts_table_name),
    tickets=ddb.Table(S.tickets_table_name),
    questionnaires=ddb.Table(S.questionnaire_table_name),
    kyc_cases=ddb.Table(S.kyc_cases_table_name),
    video_metadata=ddb.Table(S.video_metadata_table_name),
    transcode_jobs=ddb.Table(S.transcode_jobs_table_name),
    broadcast_viewers=ddb.Table(S.broadcast_viewers_table_name),
    broadcast_health_snapshots=ddb.Table(S.broadcast_health_snapshots_table_name),
    broadcast_chat_messages=ddb.Table(S.broadcast_chat_messages_table_name),
    broadcast_chat_mutes=ddb.Table(S.broadcast_chat_mutes_table_name),
    broadcast_recordings=ddb.Table(S.broadcast_recordings_table_name),
    broadcast_product_shelf=ddb.Table(S.broadcast_product_shelf_table_name),
    vod_entitlements=ddb.Table(S.vod_entitlements_table_name),
    appeals=ddb.Table(S.appeals_table_name),
    creator_payouts=ddb.Table(S.creator_payouts_table_name),
    broadcast_reminders=ddb.Table(S.broadcast_reminders_table_name),
    broadcast_private_sessions=ddb.Table(S.broadcast_private_sessions_table_name),
    broadcast_inputs=ddb.Table(S.broadcast_inputs_table_name),
    broadcast_tip_goals=ddb.Table(S.broadcast_tip_goals_table_name),
    video_views=ddb.Table(S.video_views_table_name),
    video_likes=ddb.Table(S.video_likes_table_name),
    ad_impressions=ddb.Table(S.ad_impressions_table_name),
    call_billing_ledger=ddb.Table(S.call_billing_ledger_table_name),
    rate_limits=ddb.Table(S.rate_limits_table_name),
    rate_limit_events=ddb.Table(S.rate_limit_events_table_name),
    analytics_rollups=ddb.Table(S.analytics_rollups_table_name),
    data_requests=ddb.Table(S.data_requests_table_name),
    data_request_audit=ddb.Table(S.data_request_audit_table_name),
    webhook_endpoints=ddb.Table(S.webhook_endpoints_table_name),
    webhook_deliveries=ddb.Table(S.webhook_deliveries_table_name),
    webhook_stats=ddb.Table(S.webhooks_stats_table_name),
    promo_codes=ddb.Table(S.promo_codes_table_name),
    scheduled_actions=ddb.Table(S.scheduled_actions_table_name),
    watermark_jobs=ddb.Table(S.watermark_jobs_table_name),
    recommendations=ddb.Table(S.recommendations_table_name),
    refund_requests=ddb.Table(S.refund_requests_table_name),
    translations=ddb.Table(S.translations_table_name),
    group_call_sessions=ddb.Table(S.group_call_sessions_table_name),
    sms_delivery=ddb.Table(S.sms_delivery_table_name),
    email_delivery=ddb.Table(S.email_delivery_table_name),
    affiliate_links=ddb.Table(S.affiliate_links_table_name),
    affiliate_clicks=ddb.Table(S.affiliate_clicks_table_name),
    audit_exports=ddb.Table(S.audit_export_table_name),
    achievements=ddb.Table(S.achievements_table_name),
    user_achievements=ddb.Table(S.user_achievements_table_name),
    user_achievement_progress=ddb.Table(S.user_achievement_progress_table_name),
    achievement_leaderboard=ddb.Table(S.achievement_leaderboard_table_name),
    broadcast_qa_questions=ddb.Table(S.broadcast_qa_questions_table_name),
    collaboration_agreements=ddb.Table(S.collaboration_agreements_table_name),
    fan_club_channels=ddb.Table(S.fan_club_channels_table_name),
    fan_club_messages=ddb.Table(S.fan_club_messages_table_name),
    organizations=ddb.Table(S.organizations_table_name),
    watch_parties=ddb.Table(S.watch_parties_table_name),
    watch_party_participants=ddb.Table(S.watch_party_participants_table_name),
    tenants=ddb.Table(S.tenants_table_name),
    tenant_domains=ddb.Table(S.tenant_domains_table_name),
    tenant_members=ddb.Table(S.tenant_members_table_name),
    sso_providers=ddb.Table(S.sso_providers_table_name),
    sso_sessions=ddb.Table(S.sso_sessions_table_name),
    sso_assertion_cache=ddb.Table(S.sso_assertion_cache_table_name),
    broadcast_clips=ddb.Table(S.broadcast_clips_table_name),
    kyc_risk_scores=ddb.Table(S.kyc_risk_scores_table_name),
)
