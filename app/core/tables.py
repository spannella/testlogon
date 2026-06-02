from __future__ import annotations

from dataclasses import dataclass
from decimal import Decimal
from typing import Any

from .aws import ddb
from .settings import S


def _to_decimal(obj: Any) -> Any:
    """Recursively convert Python floats to Decimal for DynamoDB.

    DynamoDB's boto3 serializer rejects ``float`` ("Float types are not
    supported. Use Decimal types instead."). Many services compute float
    values (rates, scores, thresholds, averages) and write them directly;
    coercing here makes every ``put_item``/``update_item`` float-safe without
    each call site having to remember to wrap its numbers.
    """
    if isinstance(obj, float):
        return Decimal(str(obj))
    if isinstance(obj, dict):
        return {k: _to_decimal(v) for k, v in obj.items()}
    if isinstance(obj, (list, tuple)):
        return [_to_decimal(v) for v in obj]
    return obj


class _FloatSafeTable:
    """Thin proxy over a boto3 Table that coerces floats to Decimal on write.

    Delegates every other attribute/method (query, scan, get_item,
    delete_item, meta, ...) to the wrapped table unchanged.
    """

    __slots__ = ("_t",)

    def __init__(self, table: Any) -> None:
        object.__setattr__(self, "_t", table)

    def put_item(self, **kwargs: Any) -> Any:
        if "Item" in kwargs:
            kwargs["Item"] = _to_decimal(kwargs["Item"])
        return self._t.put_item(**kwargs)

    def update_item(self, **kwargs: Any) -> Any:
        if "ExpressionAttributeValues" in kwargs:
            kwargs["ExpressionAttributeValues"] = _to_decimal(kwargs["ExpressionAttributeValues"])
        return self._t.update_item(**kwargs)

    def batch_writer(self, *args: Any, **kwargs: Any) -> Any:
        bw = self._t.batch_writer(*args, **kwargs)
        orig_put = bw.put_item

        def _safe_put(Item: Any, **kw: Any) -> Any:
            return orig_put(Item=_to_decimal(Item), **kw)

        bw.put_item = _safe_put
        return bw

    def __getattr__(self, name: str) -> Any:
        return getattr(self._t, name)


def _safe_table(name: str) -> Any:
    return _FloatSafeTable(ddb.Table(name))

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
    billing_config: Any
    sticker_collections: Any
    custom_emojis: Any
    fraud_cases: Any
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
    broadcast_promo_posts: Any
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
    moderation_video_queue: Any
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
    signature_templates: Any
    tickets: Any
    questionnaires: Any
    kyc_cases: Any
    kyc_business_cases: Any
    kyc_documents: Any
    kyc_id_scans: Any
    kyc_residency_documents: Any
    kyc_liveness_calls: Any
    kyc_screening_results: Any
    kyc_proof_of_funds: Any
    video_metadata: Any
    transcode_jobs: Any
    broadcast_viewers: Any
    broadcast_health_snapshots: Any
    broadcast_chat_messages: Any
    broadcast_chat_mutes: Any
    broadcast_recordings: Any
    broadcast_product_shelf: Any
    vod_entitlements: Any
    vod_rentals: Any
    vod_ad_sessions: Any
    appeals: Any
    creator_payouts: Any
    bulk_payout_batches: Any
    broadcast_reminders: Any
    broadcast_private_sessions: Any
    broadcast_allowlist: Any
    broadcast_inputs: Any
    broadcast_tip_goals: Any
    video_views: Any
    video_likes: Any
    ad_impressions: Any
    ad_accounts: Any
    ad_campaigns: Any
    content_boosts: Any
    ad_creatives: Any
    ad_moderation_log: Any
    ad_targeting: Any
    content_ad_controls: Any
    ad_frequency_caps: Any
    ad_billing: Any
    ad_analytics_rollups: Any
    ad_fraud_events: Any
    ad_optimization_recommendations: Any
    call_billing_ledger: Any
    rate_limits: Any
    rate_limit_events: Any
    analytics_rollups: Any
    data_requests: Any
    data_request_audit: Any
    account_deletion_requests: Any
    webhook_endpoints: Any
    webhook_deliveries: Any
    webhook_stats: Any
    promo_codes: Any
    scheduled_actions: Any
    watermark_jobs: Any
    vod_watermark_downloads: Any
    recommendations: Any
    refund_requests: Any
    billing_disputes: Any
    translations: Any
    group_call_sessions: Any
    sms_delivery: Any
    email_delivery: Any
    admin_messaging_templates: Any
    affiliate_links: Any
    affiliate_clicks: Any
    ad_creative_affiliates: Any
    audit_exports: Any
    achievements: Any
    user_achievements: Any
    user_achievement_progress: Any
    achievement_leaderboard: Any
    broadcast_qa_questions: Any
    live_qa_questions: Any
    collaboration_agreements: Any
    fan_club_channels: Any
    fan_club_messages: Any
    organizations: Any
    user_groups: Any
    watch_parties: Any
    watch_party_participants: Any
    tenants: Any
    tenant_domains: Any
    tenant_members: Any
    sso_providers: Any
    sso_sessions: Any
    sso_assertion_cache: Any
    broadcast_clips: Any
    llm_provider_keys: Any
    delegates: Any
    delegation_api_keys: Any
    syndicates: Any
    syndicate_revenue_split: Any
    syndicate_treasury: Any
    syndicate_posts: Any
    syndicate_ad_campaigns: Any
    syndicate_open_licensing: Any
    chat_bots: Any
    bot_assignments: Any
    ssh_keys: Any
    issued_licenses: Any
    license_agreements: Any
    license_compliance: Any
    bot_templates: Any
    bot_scheduled_sends: Any
    media_preferences: Any
    ec2_instances: Any
    instance_metrics: Any
    security_groups: Any
    license_revenue: Any
    activity_feed: Any
    notifications_engine: Any
    call_history: Any
    kyc_risk_scores: Any
    kyc_translations: Any
    kyc_review_schedule: Any
    kyc_document_templates: Any
    broadcast_moderation: Any
    k8s_pods: Any
    agent_workers: Any
    compute_billing: Any
    compute_quotas: Any
    instance_templates: Any
    agent_memory: Any
    agent_feedback: Any
    agent_types: Any
    agent_runs: Any
    agent_doc_coverage: Any
    agent_doc_templates: Any
    stylist_ui_reviews: Any
    stylist_design_rules: Any
    deployment_log: Any
    feature_decompositions: Any
    agent_feature_ideas: Any
    agent_preference_learning: Any
    product_ideas: Any
    project_sprints: Any
    project_reports: Any
    marketing_content: Any
    marketing_engagement: Any
    compliance_findings: Any
    compliance_audits: Any
    admin_subscription_tiers: Any
    agent_costs: Any
    agent_ticket_costs: Any
    agent_cost_budgets: Any
    agent_cost_alerts: Any
    invoices: Any
    tax_documents: Any
    tax_forms_1099: Any
    financial_rollups: Any
    payment_provider_health: Any
    ssh_session_recordings: Any
    ssh_bastion_paths: Any
    connection_profiles: Any
    job_runs: Any
    group_fundraising_campaigns: Any
    user_themes: Any
    sponsorship_deals: Any
    image_optimizations: Any
    file_share_links: Any
    host_inventory: Any

T = Tables(
    sessions=_safe_table(S.ddb_sessions_table),
    totp=_safe_table(S.ddb_totp_table),
    sms=_safe_table(S.ddb_sms_table),
    recovery=_safe_table(S.ddb_recovery_table),
    email=_safe_table(S.ddb_email_table),
    users=_safe_table(S.users_table_name),
    role_audit=_safe_table(S.role_audit_table_name),
    api_keys=_safe_table(S.api_keys_table_name),
    alerts=_safe_table(S.alerts_table_name),
    alert_prefs=_safe_table(S.alert_prefs_table_name),
    push_devices=_safe_table(S.push_devices_table_name),
    billing=_safe_table(S.billing_table_name),
    billing_config=_safe_table(S.billing_config_table_name),
    sticker_collections=_safe_table(S.ddb_sticker_collections_table),
    custom_emojis=_safe_table(S.ddb_custom_emojis_table),
    fraud_cases=_safe_table(S.ddb_fraud_cases_table),
    payment_incidents=_safe_table(S.payment_incidents_table_name),
    payment_incident_events=_safe_table(S.payment_incident_events_table_name),
    payment_dispute_evidence=_safe_table(S.payment_dispute_evidence_table_name),
    payment_retry_attempts=_safe_table(S.payment_retry_attempts_table_name),
    payment_incident_ticket_links=_safe_table(S.payment_incident_ticket_links_table_name),
    account_state=_safe_table(S.account_state_table_name),
    profile=_safe_table(S.profile_table_name),
    addresses=_safe_table(S.addresses_table_name),
    calendar=_safe_table(S.calendar_table_name),
    purchase_transactions=_safe_table(S.purchase_transactions_table_name),
    purchase_events=_safe_table(S.purchase_events_table_name),
    shopping_cart=_safe_table(S.shopping_cart_table_name),
    catalog=_safe_table(S.catalog_table_name),
    subscriptions=_safe_table(S.subscriptions_table_name),
    projects=_safe_table(S.projects_table_name),
    contacts=_safe_table(S.contacts_table_name),
    broadcast_profiles=_safe_table(S.broadcast_profiles_table_name),
    broadcast_promo_posts=_safe_table(S.broadcast_promo_posts_table_name),
    broadcast_sessions=_safe_table(S.broadcast_sessions_table_name),
    broadcast_outputs=_safe_table(S.broadcast_outputs_table_name),
    broadcast_session_transitions=_safe_table(S.broadcast_session_transitions_table_name),
    broadcast_action_audit=_safe_table(S.broadcast_action_audit_table_name),
    message_visibility_overrides=_safe_table(S.message_visibility_overrides_table_name),
    conversation_pins=_safe_table(S.conversation_pins_table_name),
    message_threads=_safe_table(S.message_threads_table_name),
    message_reports=_safe_table(S.message_reports_table_name),
    mass_message_campaigns=_safe_table(S.mass_message_campaigns_table_name),
    mass_message_campaign_destinations=_safe_table(S.mass_message_campaign_destinations_table_name),
    message_report_context=_safe_table(S.message_report_context_table_name),
    message_call_sessions=_safe_table(S.message_call_sessions_table_name),
    content_reports=_safe_table(S.content_reports_table_name),
    moderation_tickets=_safe_table(S.moderation_tickets_table_name),
    moderation_actions=_safe_table(S.moderation_actions_table_name),
    moderation_audit_log=_safe_table(S.moderation_audit_log_table_name),
    moderation_video_queue=_safe_table(S.moderation_video_queue_table_name),
    user_enforcement_history=_safe_table(S.user_enforcement_history_table_name),
    dmca_claims=_safe_table(S.dmca_claims_table_name),
    message_legal_holds=_safe_table(S.message_legal_holds_table_name),
    message_archive_chain_heads=_safe_table(S.message_archive_chain_heads_table_name),
    message_compliance_exports=_safe_table(S.message_compliance_exports_table_name),
    catalog_products=_safe_table(S.catalog_products_table_name),
    catalog_product_versions=_safe_table(S.catalog_product_versions_table_name),
    orders=_safe_table(S.orders_table_name),
    order_items=_safe_table(S.order_items_table_name),
    payments=_safe_table(S.payments_table_name),
    entitlements=_safe_table(S.entitlements_table_name),
    entitlement_usage_events=_safe_table(S.entitlement_usage_events_table_name),
    signature_packets=_safe_table(S.signature_packets_table_name),
    signature_packet_signers=_safe_table(S.signature_packet_signers_table_name),
    signature_packet_fields=_safe_table(S.signature_packet_fields_table_name),
    signature_packet_events=_safe_table(S.signature_packet_events_table_name),
    signature_packet_artifacts=_safe_table(S.signature_packet_artifacts_table_name),
    signature_templates=_safe_table(S.signature_templates_table_name),
    tickets=_safe_table(S.tickets_table_name),
    questionnaires=_safe_table(S.questionnaire_table_name),
    kyc_cases=_safe_table(S.kyc_cases_table_name),
    kyc_business_cases=_safe_table(S.kyc_business_cases_table_name),
    kyc_documents=_safe_table(S.kyc_documents_table_name),
    kyc_id_scans=_safe_table(S.kyc_id_scans_table_name),
    kyc_residency_documents=_safe_table(S.kyc_residency_documents_table_name),
    kyc_liveness_calls=_safe_table(S.kyc_liveness_calls_table_name),
    kyc_screening_results=_safe_table(S.kyc_screening_results_table_name),
    kyc_proof_of_funds=_safe_table(S.kyc_proof_of_funds_table_name),
    video_metadata=_safe_table(S.video_metadata_table_name),
    transcode_jobs=_safe_table(S.transcode_jobs_table_name),
    broadcast_viewers=_safe_table(S.broadcast_viewers_table_name),
    broadcast_health_snapshots=_safe_table(S.broadcast_health_snapshots_table_name),
    broadcast_chat_messages=_safe_table(S.broadcast_chat_messages_table_name),
    broadcast_chat_mutes=_safe_table(S.broadcast_chat_mutes_table_name),
    broadcast_recordings=_safe_table(S.broadcast_recordings_table_name),
    broadcast_product_shelf=_safe_table(S.broadcast_product_shelf_table_name),
    vod_entitlements=_safe_table(S.vod_entitlements_table_name),
    vod_rentals=_safe_table(S.vod_rentals_table_name),
    vod_ad_sessions=_safe_table(S.vod_ad_sessions_table_name),
    appeals=_safe_table(S.appeals_table_name),
    creator_payouts=_safe_table(S.creator_payouts_table_name),
    bulk_payout_batches=_safe_table(S.bulk_payout_batches_table_name),
    broadcast_reminders=_safe_table(S.broadcast_reminders_table_name),
    broadcast_private_sessions=_safe_table(S.broadcast_private_sessions_table_name),
    broadcast_allowlist=_safe_table(S.broadcast_allowlist_table_name),
    broadcast_inputs=_safe_table(S.broadcast_inputs_table_name),
    broadcast_tip_goals=_safe_table(S.broadcast_tip_goals_table_name),
    video_views=_safe_table(S.video_views_table_name),
    video_likes=_safe_table(S.video_likes_table_name),
    ad_impressions=_safe_table(S.ad_impressions_table_name),
    ad_accounts=_safe_table(S.ad_accounts_table_name),
    ad_campaigns=_safe_table(S.ad_campaigns_table_name),
    content_boosts=_safe_table(S.content_boosts_table_name),
    ad_creatives=_safe_table(S.ad_creatives_table_name),
    ad_moderation_log=_safe_table(S.ad_moderation_log_table_name),
    ad_targeting=_safe_table(S.ad_targeting_table_name),
    content_ad_controls=_safe_table(S.content_ad_controls_table_name),
    ad_frequency_caps=_safe_table(S.ad_frequency_caps_table_name),
    ad_billing=_safe_table(S.ad_billing_table_name),
    ad_analytics_rollups=_safe_table(S.ad_analytics_rollups_table_name),
    ad_fraud_events=_safe_table(S.ad_fraud_events_table_name),
    ad_optimization_recommendations=_safe_table(S.ad_optimization_recommendations_table_name),
    call_billing_ledger=_safe_table(S.call_billing_ledger_table_name),
    rate_limits=_safe_table(S.rate_limits_table_name),
    rate_limit_events=_safe_table(S.rate_limit_events_table_name),
    analytics_rollups=_safe_table(S.analytics_rollups_table_name),
    data_requests=_safe_table(S.data_requests_table_name),
    data_request_audit=_safe_table(S.data_request_audit_table_name),
    account_deletion_requests=_safe_table(S.account_deletion_requests_table_name),
    webhook_endpoints=_safe_table(S.webhook_endpoints_table_name),
    webhook_deliveries=_safe_table(S.webhook_deliveries_table_name),
    webhook_stats=_safe_table(S.webhooks_stats_table_name),
    promo_codes=_safe_table(S.promo_codes_table_name),
    scheduled_actions=_safe_table(S.scheduled_actions_table_name),
    watermark_jobs=_safe_table(S.watermark_jobs_table_name),
    vod_watermark_downloads=_safe_table(S.vod_watermark_downloads_table_name),
    recommendations=_safe_table(S.recommendations_table_name),
    refund_requests=_safe_table(S.refund_requests_table_name),
    billing_disputes=_safe_table(S.billing_disputes_table_name),
    translations=_safe_table(S.translations_table_name),
    group_call_sessions=_safe_table(S.group_call_sessions_table_name),
    sms_delivery=_safe_table(S.sms_delivery_table_name),
    email_delivery=_safe_table(S.email_delivery_table_name),
    admin_messaging_templates=_safe_table(S.admin_messaging_templates_table_name),
    affiliate_links=_safe_table(S.affiliate_links_table_name),
    affiliate_clicks=_safe_table(S.affiliate_clicks_table_name),
    ad_creative_affiliates=_safe_table(S.ad_creative_affiliates_table_name),
    audit_exports=_safe_table(S.audit_export_table_name),
    achievements=_safe_table(S.achievements_table_name),
    user_achievements=_safe_table(S.user_achievements_table_name),
    user_achievement_progress=_safe_table(S.user_achievement_progress_table_name),
    achievement_leaderboard=_safe_table(S.achievement_leaderboard_table_name),
    broadcast_qa_questions=_safe_table(S.broadcast_qa_questions_table_name),
    live_qa_questions=_safe_table(S.live_qa_questions_table_name),
    collaboration_agreements=_safe_table(S.collaboration_agreements_table_name),
    fan_club_channels=_safe_table(S.fan_club_channels_table_name),
    fan_club_messages=_safe_table(S.fan_club_messages_table_name),
    organizations=_safe_table(S.organizations_table_name),
    user_groups=_safe_table(S.ddb_user_groups_table),
    watch_parties=_safe_table(S.watch_parties_table_name),
    watch_party_participants=_safe_table(S.watch_party_participants_table_name),
    tenants=_safe_table(S.tenants_table_name),
    tenant_domains=_safe_table(S.tenant_domains_table_name),
    tenant_members=_safe_table(S.tenant_members_table_name),
    sso_providers=_safe_table(S.sso_providers_table_name),
    sso_sessions=_safe_table(S.sso_sessions_table_name),
    sso_assertion_cache=_safe_table(S.sso_assertion_cache_table_name),
    broadcast_clips=_safe_table(S.broadcast_clips_table_name),
    llm_provider_keys=_safe_table(S.llm_provider_keys_table_name),
    delegates=_safe_table(S.delegates_table_name),
    delegation_api_keys=_safe_table(S.delegation_api_keys_table_name),
    syndicates=_safe_table(S.syndicates_table_name),
    syndicate_revenue_split=_safe_table(S.syndicate_revenue_split_table_name),
    syndicate_treasury=_safe_table(S.syndicate_treasury_table_name),
    syndicate_posts=_safe_table(S.syndicate_posts_table_name),
    syndicate_ad_campaigns=_safe_table(S.syndicate_ad_campaigns_table_name),
    syndicate_open_licensing=_safe_table(S.syndicate_open_licensing_table_name),
    chat_bots=_safe_table(S.chat_bots_table_name),
    bot_assignments=_safe_table(S.bot_assignments_table_name),
    ssh_keys=_safe_table(S.ssh_keys_table_name),
    issued_licenses=_safe_table(S.issued_licenses_table_name),
    license_agreements=_safe_table(S.license_agreements_table_name),
    license_compliance=_safe_table(S.license_compliance_checks_table_name),
    bot_templates=_safe_table(S.bot_templates_table_name),
    bot_scheduled_sends=_safe_table(S.bot_scheduled_sends_table_name),
    media_preferences=_safe_table(S.media_preferences_table_name),
    ec2_instances=_safe_table(S.ec2_instances_table_name),
    instance_metrics=_safe_table(S.instance_metrics_table_name),
    security_groups=_safe_table(S.security_groups_table_name),
    license_revenue=_safe_table(S.license_revenue_table_name),
    activity_feed=_safe_table(S.activity_feed_table_name),
    notifications_engine=_safe_table(S.notifications_engine_table_name),
    call_history=_safe_table(S.call_history_table_name),
    kyc_risk_scores=_safe_table(S.kyc_risk_scores_table_name),
    kyc_translations=_safe_table(S.kyc_translations_table_name),
    kyc_review_schedule=_safe_table(S.kyc_review_schedule_table_name),
    broadcast_moderation=_safe_table(S.broadcast_moderation_table_name),
    k8s_pods=_safe_table(S.k8s_pods_table_name),
    agent_workers=_safe_table(S.agent_workers_table_name),
    compute_billing=_safe_table(S.compute_billing_table_name),
    compute_quotas=_safe_table(S.compute_quotas_table_name),
    instance_templates=_safe_table(S.instance_templates_table_name),
    agent_memory=_safe_table(S.agent_memory_table_name),
    agent_feedback=_safe_table(S.agent_feedback_table_name),
    agent_types=_safe_table(S.agent_types_table_name),
    agent_runs=_safe_table(S.agent_runs_table_name),
    agent_doc_coverage=_safe_table(S.agent_doc_coverage_table_name),
    agent_doc_templates=_safe_table(S.agent_doc_templates_table_name),
    stylist_ui_reviews=_safe_table(S.stylist_ui_reviews_table_name),
    stylist_design_rules=_safe_table(S.stylist_design_rules_table_name),
    deployment_log=_safe_table(S.deployment_log_table_name),
    feature_decompositions=_safe_table(S.feature_decompositions_table_name),
    agent_feature_ideas=_safe_table(S.agent_feature_ideas_table_name),
    agent_preference_learning=_safe_table(S.agent_preference_learning_table_name),
    product_ideas=_safe_table(S.product_ideas_table_name),
    project_sprints=_safe_table(S.project_sprints_table_name),
    project_reports=_safe_table(S.project_reports_table_name),
    marketing_content=_safe_table(S.marketing_content_table_name),
    marketing_engagement=_safe_table(S.marketing_engagement_table_name),
    compliance_findings=_safe_table(S.compliance_security_findings_table_name),
    compliance_audits=_safe_table(S.compliance_security_audits_table_name),
    admin_subscription_tiers=_safe_table(S.admin_subscription_tiers_table_name),
    agent_costs=_safe_table(S.agent_costs_table_name),
    agent_ticket_costs=_safe_table(S.agent_ticket_costs_table_name),
    agent_cost_budgets=_safe_table(S.agent_cost_budgets_table_name),
    agent_cost_alerts=_safe_table(S.agent_cost_alerts_table_name),
    invoices=_safe_table(S.invoices_table_name),
    tax_documents=_safe_table(S.tax_documents_table_name),
    tax_forms_1099=_safe_table(S.tax_forms_1099_table_name),
    financial_rollups=_safe_table(S.platform_financial_dashboard_rollups_table_name),
    payment_provider_health=_safe_table(S.payment_provider_health_table_name),
    ssh_session_recordings=_safe_table(S.ssh_session_recordings_table_name),
    ssh_bastion_paths=_safe_table(S.ssh_bastion_paths_table_name),
    connection_profiles=_safe_table(S.connection_profiles_table_name),
    job_runs=_safe_table(S.job_runs_table_name),
    group_fundraising_campaigns=_safe_table(S.group_fundraising_campaigns_table_name),
    user_themes=_safe_table(S.user_themes_table_name),
    sponsorship_deals=_safe_table(S.sponsorship_deals_table_name),
    image_optimizations=_safe_table(S.image_optimizations_table_name),
    file_share_links=_safe_table(S.ddb_file_share_links_table),
    host_inventory=_safe_table(S.ddb_host_inventory_table),
    kyc_document_templates=_safe_table(S.kyc_document_templates_table_name),
)
