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
    billing_config: Any
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
    broadcast_moderation: Any
    k8s_pods: Any
    agent_workers: Any
    compute_billing: Any
    compute_quotas: Any
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
    billing_config=ddb.Table(S.billing_config_table_name),
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
    broadcast_promo_posts=ddb.Table(S.broadcast_promo_posts_table_name),
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
    moderation_video_queue=ddb.Table(S.moderation_video_queue_table_name),
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
    signature_templates=ddb.Table(S.signature_templates_table_name),
    tickets=ddb.Table(S.tickets_table_name),
    questionnaires=ddb.Table(S.questionnaire_table_name),
    kyc_cases=ddb.Table(S.kyc_cases_table_name),
    kyc_documents=ddb.Table(S.kyc_documents_table_name),
    kyc_id_scans=ddb.Table(S.kyc_id_scans_table_name),
    kyc_residency_documents=ddb.Table(S.kyc_residency_documents_table_name),
    kyc_liveness_calls=ddb.Table(S.kyc_liveness_calls_table_name),
    kyc_screening_results=ddb.Table(S.kyc_screening_results_table_name),
    kyc_proof_of_funds=ddb.Table(S.kyc_proof_of_funds_table_name),
    video_metadata=ddb.Table(S.video_metadata_table_name),
    transcode_jobs=ddb.Table(S.transcode_jobs_table_name),
    broadcast_viewers=ddb.Table(S.broadcast_viewers_table_name),
    broadcast_health_snapshots=ddb.Table(S.broadcast_health_snapshots_table_name),
    broadcast_chat_messages=ddb.Table(S.broadcast_chat_messages_table_name),
    broadcast_chat_mutes=ddb.Table(S.broadcast_chat_mutes_table_name),
    broadcast_recordings=ddb.Table(S.broadcast_recordings_table_name),
    broadcast_product_shelf=ddb.Table(S.broadcast_product_shelf_table_name),
    vod_entitlements=ddb.Table(S.vod_entitlements_table_name),
    vod_rentals=ddb.Table(S.vod_rentals_table_name),
    vod_ad_sessions=ddb.Table(S.vod_ad_sessions_table_name),
    appeals=ddb.Table(S.appeals_table_name),
    creator_payouts=ddb.Table(S.creator_payouts_table_name),
    bulk_payout_batches=ddb.Table(S.bulk_payout_batches_table_name),
    broadcast_reminders=ddb.Table(S.broadcast_reminders_table_name),
    broadcast_private_sessions=ddb.Table(S.broadcast_private_sessions_table_name),
    broadcast_allowlist=ddb.Table(S.broadcast_allowlist_table_name),
    broadcast_inputs=ddb.Table(S.broadcast_inputs_table_name),
    broadcast_tip_goals=ddb.Table(S.broadcast_tip_goals_table_name),
    video_views=ddb.Table(S.video_views_table_name),
    video_likes=ddb.Table(S.video_likes_table_name),
    ad_impressions=ddb.Table(S.ad_impressions_table_name),
    ad_accounts=ddb.Table(S.ad_accounts_table_name),
    ad_campaigns=ddb.Table(S.ad_campaigns_table_name),
    content_boosts=ddb.Table(S.content_boosts_table_name),
    ad_creatives=ddb.Table(S.ad_creatives_table_name),
    ad_moderation_log=ddb.Table(S.ad_moderation_log_table_name),
    ad_targeting=ddb.Table(S.ad_targeting_table_name),
    content_ad_controls=ddb.Table(S.content_ad_controls_table_name),
    ad_frequency_caps=ddb.Table(S.ad_frequency_caps_table_name),
    ad_billing=ddb.Table(S.ad_billing_table_name),
    ad_analytics_rollups=ddb.Table(S.ad_analytics_rollups_table_name),
    ad_fraud_events=ddb.Table(S.ad_fraud_events_table_name),
    ad_optimization_recommendations=ddb.Table(S.ad_optimization_recommendations_table_name),
    call_billing_ledger=ddb.Table(S.call_billing_ledger_table_name),
    rate_limits=ddb.Table(S.rate_limits_table_name),
    rate_limit_events=ddb.Table(S.rate_limit_events_table_name),
    analytics_rollups=ddb.Table(S.analytics_rollups_table_name),
    data_requests=ddb.Table(S.data_requests_table_name),
    data_request_audit=ddb.Table(S.data_request_audit_table_name),
    account_deletion_requests=ddb.Table(S.account_deletion_requests_table_name),
    webhook_endpoints=ddb.Table(S.webhook_endpoints_table_name),
    webhook_deliveries=ddb.Table(S.webhook_deliveries_table_name),
    webhook_stats=ddb.Table(S.webhooks_stats_table_name),
    promo_codes=ddb.Table(S.promo_codes_table_name),
    scheduled_actions=ddb.Table(S.scheduled_actions_table_name),
    watermark_jobs=ddb.Table(S.watermark_jobs_table_name),
    vod_watermark_downloads=ddb.Table(S.vod_watermark_downloads_table_name),
    recommendations=ddb.Table(S.recommendations_table_name),
    refund_requests=ddb.Table(S.refund_requests_table_name),
    billing_disputes=ddb.Table(S.billing_disputes_table_name),
    translations=ddb.Table(S.translations_table_name),
    group_call_sessions=ddb.Table(S.group_call_sessions_table_name),
    sms_delivery=ddb.Table(S.sms_delivery_table_name),
    email_delivery=ddb.Table(S.email_delivery_table_name),
    admin_messaging_templates=ddb.Table(S.admin_messaging_templates_table_name),
    affiliate_links=ddb.Table(S.affiliate_links_table_name),
    affiliate_clicks=ddb.Table(S.affiliate_clicks_table_name),
    ad_creative_affiliates=ddb.Table(S.ad_creative_affiliates_table_name),
    audit_exports=ddb.Table(S.audit_export_table_name),
    achievements=ddb.Table(S.achievements_table_name),
    user_achievements=ddb.Table(S.user_achievements_table_name),
    user_achievement_progress=ddb.Table(S.user_achievement_progress_table_name),
    achievement_leaderboard=ddb.Table(S.achievement_leaderboard_table_name),
    broadcast_qa_questions=ddb.Table(S.broadcast_qa_questions_table_name),
    live_qa_questions=ddb.Table(S.live_qa_questions_table_name),
    collaboration_agreements=ddb.Table(S.collaboration_agreements_table_name),
    fan_club_channels=ddb.Table(S.fan_club_channels_table_name),
    fan_club_messages=ddb.Table(S.fan_club_messages_table_name),
    organizations=ddb.Table(S.organizations_table_name),
    user_groups=ddb.Table(S.ddb_user_groups_table),
    watch_parties=ddb.Table(S.watch_parties_table_name),
    watch_party_participants=ddb.Table(S.watch_party_participants_table_name),
    tenants=ddb.Table(S.tenants_table_name),
    tenant_domains=ddb.Table(S.tenant_domains_table_name),
    tenant_members=ddb.Table(S.tenant_members_table_name),
    sso_providers=ddb.Table(S.sso_providers_table_name),
    sso_sessions=ddb.Table(S.sso_sessions_table_name),
    sso_assertion_cache=ddb.Table(S.sso_assertion_cache_table_name),
    broadcast_clips=ddb.Table(S.broadcast_clips_table_name),
    llm_provider_keys=ddb.Table(S.llm_provider_keys_table_name),
    delegates=ddb.Table(S.delegates_table_name),
    delegation_api_keys=ddb.Table(S.delegation_api_keys_table_name),
    syndicates=ddb.Table(S.syndicates_table_name),
    syndicate_revenue_split=ddb.Table(S.syndicate_revenue_split_table_name),
    syndicate_treasury=ddb.Table(S.syndicate_treasury_table_name),
    syndicate_posts=ddb.Table(S.syndicate_posts_table_name),
    syndicate_ad_campaigns=ddb.Table(S.syndicate_ad_campaigns_table_name),
    chat_bots=ddb.Table(S.chat_bots_table_name),
    bot_assignments=ddb.Table(S.bot_assignments_table_name),
    ssh_keys=ddb.Table(S.ssh_keys_table_name),
    issued_licenses=ddb.Table(S.issued_licenses_table_name),
    license_agreements=ddb.Table(S.license_agreements_table_name),
    license_compliance=ddb.Table(S.license_compliance_checks_table_name),
    bot_templates=ddb.Table(S.bot_templates_table_name),
    bot_scheduled_sends=ddb.Table(S.bot_scheduled_sends_table_name),
    media_preferences=ddb.Table(S.media_preferences_table_name),
    ec2_instances=ddb.Table(S.ec2_instances_table_name),
    instance_metrics=ddb.Table(S.instance_metrics_table_name),
    security_groups=ddb.Table(S.security_groups_table_name),
    license_revenue=ddb.Table(S.license_revenue_table_name),
    activity_feed=ddb.Table(S.activity_feed_table_name),
    notifications_engine=ddb.Table(S.notifications_engine_table_name),
    call_history=ddb.Table(S.call_history_table_name),
    kyc_risk_scores=ddb.Table(S.kyc_risk_scores_table_name),
    broadcast_moderation=ddb.Table(S.broadcast_moderation_table_name),
    k8s_pods=ddb.Table(S.k8s_pods_table_name),
    agent_workers=ddb.Table(S.agent_workers_table_name),
    compute_billing=ddb.Table(S.compute_billing_table_name),
    compute_quotas=ddb.Table(S.compute_quotas_table_name),
    agent_memory=ddb.Table(S.agent_memory_table_name),
    agent_feedback=ddb.Table(S.agent_feedback_table_name),
    agent_types=ddb.Table(S.agent_types_table_name),
    agent_runs=ddb.Table(S.agent_runs_table_name),
    agent_doc_coverage=ddb.Table(S.agent_doc_coverage_table_name),
    agent_doc_templates=ddb.Table(S.agent_doc_templates_table_name),
    stylist_ui_reviews=ddb.Table(S.stylist_ui_reviews_table_name),
    stylist_design_rules=ddb.Table(S.stylist_design_rules_table_name),
    deployment_log=ddb.Table(S.deployment_log_table_name),
    feature_decompositions=ddb.Table(S.feature_decompositions_table_name),
    agent_feature_ideas=ddb.Table(S.agent_feature_ideas_table_name),
    agent_preference_learning=ddb.Table(S.agent_preference_learning_table_name),
    product_ideas=ddb.Table(S.product_ideas_table_name),
    project_sprints=ddb.Table(S.project_sprints_table_name),
    project_reports=ddb.Table(S.project_reports_table_name),
    marketing_content=ddb.Table(S.marketing_content_table_name),
    marketing_engagement=ddb.Table(S.marketing_engagement_table_name),
    compliance_findings=ddb.Table(S.compliance_security_findings_table_name),
    compliance_audits=ddb.Table(S.compliance_security_audits_table_name),
    admin_subscription_tiers=ddb.Table(S.admin_subscription_tiers_table_name),
    agent_costs=ddb.Table(S.agent_costs_table_name),
    agent_ticket_costs=ddb.Table(S.agent_ticket_costs_table_name),
    agent_cost_budgets=ddb.Table(S.agent_cost_budgets_table_name),
    agent_cost_alerts=ddb.Table(S.agent_cost_alerts_table_name),
    invoices=ddb.Table(S.invoices_table_name),
    tax_documents=ddb.Table(S.tax_documents_table_name),
    tax_forms_1099=ddb.Table(S.tax_forms_1099_table_name),
    financial_rollups=ddb.Table(S.platform_financial_dashboard_rollups_table_name),
    payment_provider_health=ddb.Table(S.payment_provider_health_table_name),
    ssh_session_recordings=ddb.Table(S.ssh_session_recordings_table_name),
    ssh_bastion_paths=ddb.Table(S.ssh_bastion_paths_table_name),
    connection_profiles=ddb.Table(S.connection_profiles_table_name),
    job_runs=ddb.Table(S.job_runs_table_name),
    group_fundraising_campaigns=ddb.Table(S.group_fundraising_campaigns_table_name),
    user_themes=ddb.Table(S.user_themes_table_name),
    sponsorship_deals=ddb.Table(S.sponsorship_deals_table_name),
    image_optimizations=ddb.Table(S.image_optimizations_table_name),
)
