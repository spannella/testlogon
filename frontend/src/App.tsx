import { lazy, Suspense } from "react";
import { SeoHead } from "@/components/shared/SeoHead";

import { Routes, Route, Navigate, useParams } from "react-router-dom";
import { Helmet } from "react-helmet-async";
import { Loader2 } from "lucide-react";

import ProtectedRoute from "@/components/ProtectedRoute";
import AppShell from "@/components/layout/AppShell";
import { ErrorPage } from "@/components/shared/ErrorPage";
import { isBroadcastNavigationEnabled, isCanonicalProfileNavigationEnabled, isVncRemoteDesktopEnabled, isBrowserSshEnabled, isAgentSshQaEnabled } from "@/lib/featureFlags";

// ─── Lazy-loaded pages (code-split per route) ───────────────────
const Login = lazy(() => import("@/pages/Login"));
const Register = lazy(() => import("@/pages/Register"));
const PasswordRecovery = lazy(() => import("@/pages/PasswordRecovery"));
const MagicLinkVerify = lazy(() => import("@/pages/MagicLinkVerify"));
const Dashboard = lazy(() => import("@/pages/Dashboard"));
const BotManagerPage = lazy(() => import("@/pages/bots/BotManagerPage"));
const TemplateEditorPage = lazy(() => import("@/pages/bots/TemplateEditorPage"));
const BotAutoReplyPage = lazy(() => import("@/pages/bots/BotAutoReplyPage"));
const MessagesPage = lazy(() => import("@/pages/messages/MessagesPage"));
const LicensesPage = lazy(() => import("@/pages/licenses/LicensesPage"));
const AdminReviewPage = lazy(() => import("@/pages/licenses/AdminReviewPage"));
const LicenseCompliancePage = lazy(
  () => import("@/pages/licenses/LicenseCompliancePage"),
);
const AdminLicenseCompliancePage = lazy(
  () => import("@/pages/licenses/AdminLicenseCompliancePage"),
);
const FilesPage = lazy(() => import("@/pages/files/FilesPage"));
const KycWorkloadPage = lazy(() => import("@/pages/admin/KycWorkloadPage"));
const KycDocumentTemplatesPage = lazy(() => import("@/pages/admin/KycDocumentTemplatesPage"));
const KycTranslationsPage = lazy(() => import("@/pages/admin/KycTranslationsPage"));
const ShareLinksPage = lazy(() => import("@/pages/files/ShareLinksPage"));
const PublicDownloadPage = lazy(() => import("@/pages/files/PublicDownloadPage"));
const ProjectsPage = lazy(() => import("@/pages/projects/ProjectsPage"));
const ProjectDetailPage = lazy(() => import("@/pages/projects/ProjectDetailPage"));
const BillingPage = lazy(() => import("@/pages/billing/BillingPage"));
const CalendarPage = lazy(() => import("@/pages/calendar/CalendarPage"));
const CatalogPage = lazy(() => import("@/pages/shop/CatalogPage"));
const ProductDetail = lazy(() => import("@/pages/shop/ProductDetail"));
const CartPage = lazy(() => import("@/pages/shop/CartPage"));
const Checkout = lazy(() => import("@/pages/shop/Checkout"));
const InventoryAdmin = lazy(() => import("@/pages/shop/admin/InventoryAdmin"));
const ShopCatalogDepthPage = lazy(() => import("@/pages/shop/admin/CatalogDepthPage"));
const ShopOrderLifecyclePage = lazy(() => import("@/pages/shop/admin/OrderLifecyclePage"));
const ShopShippingAdminPage = lazy(() => import("@/pages/shop/admin/ShippingAdminPage"));
const FeedPage = lazy(() => import("@/pages/feed/FeedPage"));
const PostDetailPage = lazy(() => import("@/pages/feed/PostDetailPage"));
const DelegateFeedPage = lazy(() => import("@/pages/feed/DelegateFeedPage"));
const SyndicatesPage = lazy(() => import("@/pages/syndicates/SyndicatesPage"));
const SyndicateProfilePage = lazy(() => import("@/pages/syndicates/SyndicateProfilePage"));
const SyndicateDetailPage = lazy(() => import("@/pages/syndicates/SyndicateDetailPage"));
const SyndicateAdvertisingDetailPage = lazy(() => import("@/pages/syndicates/SyndicateAdvertisingDetailPage"));
const DelegatesPage = lazy(
  () => import("@/pages/delegates/DelegatesPage"),
);
const DelegationApiKeysPage = lazy(
  () => import("@/pages/delegates/DelegationApiKeysPage"),
);
const AlertsPage = lazy(() => import("@/pages/alerts/AlertsPage"));
const ActivityFeedPage = lazy(() => import("@/pages/activity/ActivityFeedPage"));
const NotificationsPage = lazy(() => import("@/pages/notifications/NotificationsPage"));
const SecurityPage = lazy(() => import("@/pages/security/SecurityPage"));
const ProfilePage = lazy(() => import("@/pages/settings/ProfilePage"));
const SettingsPage = lazy(() => import("@/pages/settings/SettingsPage"));
const ThemeCustomizationPage = lazy(() => import("@/pages/settings/ThemeCustomizationPage"));
const PurchasesPage = lazy(() => import("@/pages/purchases/PurchasesPage"));
const SubscriptionsPage = lazy(() => import("@/pages/subscriptions/SubscriptionsPage"));
const TierManager = lazy(() => import("@/pages/subscriptions/TierManager"));
const MySubscriptionsPage = lazy(() =>
  import("@/pages/subscriptions/MySubscriptions").then((m) => ({ default: m.MySubscriptions })));
const CreatorSubscribersPage = lazy(() => import("@/pages/subscriptions/CreatorSubscribers"));
const RootRoleManagementPage = lazy(() => import("@/pages/admin/RootRoleManagementPage"));
const ModerationBoardPage = lazy(() => import("@/pages/admin/ModerationBoardPage"));
const PaymentIncidentQueuePage = lazy(() => import("@/pages/admin/PaymentIncidentQueuePage"));
const VideoReviewQueuePage = lazy(() => import("@/pages/admin/VideoReviewQueuePage"));
const VideoReviewQueueModerationPage = lazy(() => import("@/pages/admin/VideoReviewQueueModerationPage"));
const PublicEventPage = lazy(() => import("@/pages/calendar/PublicEventPage"));
const ContactsPage = lazy(() => import("@/pages/contacts/ContactsPage"));
const HelpdeskPage = lazy(() => import("@/pages/helpdesk/HelpdeskPage"));
const TicketsPage = lazy(() => import("@/pages/tickets/TicketsPage"));
const BoardsPage = lazy(() => import("@/pages/tickets/BoardsPage"));
const BoardDetailPage = lazy(() => import("@/pages/tickets/BoardDetailPage"));
const RemoteDesktopPage = lazy(() => import("@/pages/remote/RemoteDesktopPage"));
const K8sLauncherPage = lazy(() => import("@/pages/remote/K8sLauncherPage"));
const ComputeSpendingPage = lazy(() => import("@/pages/remote/ComputeSpendingPage"));
const SecurityGroupsPage = lazy(() => import("@/pages/remote/SecurityGroupsPage"));
const SshKeyManagerPage = lazy(() => import("@/pages/remote/SshKeyManagerPage"));
const BrowserSshPage = lazy(() => import("@/pages/remote/BrowserSshPage"));
const RemoteRdpPage = lazy(() => import("@/pages/remote/RemoteRdpPage"));
const Ec2LauncherPage = lazy(() => import("@/pages/remote/Ec2LauncherPage"));
const LlmKeysPage = lazy(() => import("@/pages/agents/LlmKeysPage"));
const MyBundlesPage = lazy(() => import("@/pages/syndicates/MyBundlesPage"));
const MediaSettingsPage = lazy(() => import("@/pages/calls/MediaSettingsPage"));
const TemplateBrowserPage = lazy(() => import("@/pages/remote/TemplateBrowserPage"));
const SshRecordingsPage = lazy(() => import("@/pages/remote/SshRecordingsPage"));
const InstanceMonitoringPage = lazy(() => import("@/pages/remote/InstanceMonitoringPage"));
const SshBastionPage = lazy(() => import("@/pages/remote/SshBastionPage"));
const ConnectionProfilesPage = lazy(() => import("@/pages/remote/ConnectionProfilesPage"));
const HostInventoryPage = lazy(() => import("@/pages/remote/HostInventoryPage"));
const SigningPage = lazy(() => import("@/pages/signing/SigningPage"));
const PublicSigningPage = lazy(() => import("@/pages/signing/PublicSigningPage"));
const SigningInboxPage = lazy(() => import("@/pages/signing/SigningInboxPage"));
const CreateSignatureRequestPage = lazy(() => import("@/pages/signing/CreateSignatureRequestPage"));
const QuestionnaireBuilderPage = lazy(() => import("@/pages/questionnaires/QuestionnaireBuilderPage"));
const QuestionnaireRespondentPage = lazy(() => import("@/pages/questionnaires/QuestionnaireRespondentPage"));
const PublicUserProfilePage = lazy(() => import("@/pages/profile/PublicUserProfilePage"));
const VideosPage = lazy(() => import("@/pages/videos/VideosPage"));
const DiscoverPage = lazy(() => import("@/pages/discover/DiscoverPage"));
const TagPage = lazy(() => import("@/pages/discover/TagPage"));
const SearchPage = lazy(() => import("@/pages/search/SearchPage"));
const VideoPlayerPage = lazy(() => import("@/pages/videos/VideoPlayerPage"));
const VodRentalsPage = lazy(() => import("@/pages/vod/VodRentalsPage"));
const VodAdSupportedPage = lazy(() => import("@/pages/vod/VodAdSupportedPage"));
const BroadcastPage = lazy(() => import("@/pages/broadcast/BroadcastPage"));
const BroadcastSchedulePage = lazy(() => import("@/pages/broadcast/BroadcastSchedulePage"));
const LivePlayer = lazy(() => import("@/pages/broadcast/LivePlayer"));
const LiveQaPage = lazy(() => import("@/pages/broadcast/LiveQaPage"));
const ClipGalleryPage = lazy(() => import("@/pages/clips/ClipGalleryPage"));
const ClipPlayerPage = lazy(() => import("@/pages/clips/ClipPlayerPage"));
const PublicClipPage = lazy(() => import("@/pages/clips/PublicClipPage"));
const DmcaClaimForm = lazy(() => import("@/pages/dmca/DmcaClaimForm"));
const DmcaDashboardPage = lazy(() => import("@/pages/admin/DmcaDashboardPage"));
const RateLimitDashboard = lazy(() => import("@/pages/admin/RateLimitDashboard"));
const KycMonitoringPage = lazy(() => import("@/pages/admin/KycMonitoringPage"));
const KycAddressVerificationPanel = lazy(() => import("@/pages/admin/KycAddressVerificationPanel"));
const EmailSmsDashboardPage = lazy(() => import("@/pages/admin/EmailSmsDashboardPage"));
const AdminComputeDashboard = lazy(() => import("@/pages/admin/AdminComputeDashboard"));
const JobDashboardPage = lazy(() => import("@/pages/admin/JobDashboardPage"));
const FinancialDashboard = lazy(() => import("@/pages/admin/financials/FinancialDashboard"));
const PaymentHealthDashboard = lazy(() => import("@/pages/admin/paymentHealth/PaymentHealthDashboard"));
const AdFraudDashboard = lazy(() => import("@/pages/admin/ads/AdFraudDashboard"));
const AdPlatformDashboard = lazy(() => import("@/pages/admin/AdPlatformDashboard"));
const GalleryPage = lazy(() => import("@/pages/gallery/GalleryPage"));
const GalleryVideoDetailPage = lazy(() => import("@/pages/gallery/VideoDetailPage"));
const AnalyticsPage = lazy(() => import("@/pages/analytics/AnalyticsPage"));
const ContentDetailPage = lazy(() => import("@/pages/analytics/ContentDetailPage"));
const ContentRevenuePage = lazy(() => import("@/pages/analytics/ContentRevenuePage"));
const PayoutDashboard = lazy(() => import("@/pages/payouts/PayoutDashboard"));
const PrivacyPage = lazy(() => import("@/pages/settings/PrivacyPage"));
const AccountDeletionPage = lazy(() => import("@/pages/settings/AccountDeletionPage"));
const BlockedUsersPage = lazy(() => import("@/pages/settings/BlockedUsersPage"));
const WebhooksPage = lazy(() => import("@/pages/settings/WebhooksPage"));
const CustomEmojisPage = lazy(() => import("@/pages/settings/CustomEmojisPage"));
const GeoRulesPage = lazy(() => import("@/pages/settings/GeoRulesPage"));
const CallRateSettings = lazy(() => import("@/pages/settings/CallRateSettings"));
const ReferralDashboard = lazy(() => import("@/pages/referrals/ReferralDashboard"));
const PromoCodesPage = lazy(() => import("@/pages/promo/PromoCodesPage"));
const SchedulerPage = lazy(() => import("@/pages/scheduler/SchedulerPage"));
const RefundRequestsPage = lazy(() => import("@/pages/billing/RefundRequestsPage"));
const InvoicesPage = lazy(() => import("@/pages/billing/InvoicesPage"));
const TaxDocumentsPage = lazy(() => import("@/pages/billing/TaxDocumentsPage"));
const TaxForm1099Page = lazy(() => import("@/pages/billing/TaxForm1099Page"));
const TaxForm1099AdminPage = lazy(() => import("@/pages/admin/TaxForm1099AdminPage"));
const AdminRefundQueuePage = lazy(() => import("@/pages/admin/AdminRefundQueuePage"));
const BulkPayoutConsole = lazy(() => import("@/pages/admin/BulkPayoutConsole"));
const DisputesPage = lazy(() => import("@/pages/billing/DisputesPage"));
const AdminDisputeQueuePage = lazy(() => import("@/pages/admin/AdminDisputeQueuePage"));
const AppealsPage = lazy(() => import("@/pages/appeals/AppealsPage"));
const AppealReviewQueuePage = lazy(() => import("@/pages/admin/AppealReviewQueuePage"));
const FraudReviewQueuePage = lazy(() => import("@/pages/admin/fraud/FraudReviewQueuePage"));
const SavedPage = lazy(() => import("@/pages/saved/SavedPage"));
const AffiliateDashboard = lazy(() => import("@/pages/affiliates/AffiliateDashboard"));
const CollaborationsPage = lazy(() => import("@/pages/collaborations/CollaborationsPage"));
const CollaborationRevenuePage = lazy(() => import("@/pages/collaborations/CollaborationRevenuePage"));
const FanClubPage = lazy(() => import("@/pages/fan-club/FanClubPage"));
const AchievementsPage = lazy(() => import("@/pages/achievements/AchievementsPage"));
const AuditExportPage = lazy(() => import("@/pages/admin/AuditExportPage"));
const LegalHoldPage = lazy(() => import("@/pages/admin/LegalHoldPage"));
const TenantAdmin = lazy(() => import("@/pages/admin/TenantAdmin"));
const SsoProvidersPage = lazy(() => import("@/pages/admin/SsoProvidersPage"));
const LicenseRevenuePage = lazy(() => import("@/pages/licenses/LicenseRevenuePage"));
const RiskDashboardPage = lazy(() => import("@/pages/admin/RiskDashboardPage"));
const SecurityDashboardPage = lazy(() => import("@/pages/admin/SecurityDashboardPage"));
const SubscriptionTierManagerPage = lazy(() => import("@/pages/admin/SubscriptionTierManagerPage"));
const BillingConfigPage = lazy(() => import("@/pages/admin/BillingConfigPage"));
const CreatorDashboard = lazy(() => import("@/pages/dashboard/CreatorDashboard"));
const OrgsPage = lazy(() => import("@/pages/orgs/OrgsPage"));
const OrgDashboard = lazy(() => import("@/pages/orgs/OrgDashboard"));
const GroupsListPage = lazy(() => import("@/pages/groups/GroupsListPage"));
const EarningsPage = lazy(() => import("@/pages/earnings/EarningsPage"));
const GroupSettingsPage = lazy(() => import("@/pages/groups/GroupSettingsPage"));
const TargetingEditor = lazy(() => import("@/pages/ads/TargetingEditor"));
const CreativeEditor = lazy(() => import("@/pages/ads/CreativeEditor"));
const CreativeListPage = lazy(() => import("@/pages/ads/CreativeListPage"));
const AdvertiserDashboard = lazy(() => import("@/pages/ads/AdvertiserDashboard"));
const CampaignList = lazy(() => import("@/pages/ads/CampaignList"));
const AdminCreativeReviewPage = lazy(() => import("@/pages/ads/AdminCreativeReviewPage"));
const GroupPage = lazy(() => import("@/pages/groups/GroupPage"));
const WebhookDashboard = lazy(() => import("@/pages/webhooks/WebhookDashboard"));
const WebhookEndpointDetail = lazy(() => import("@/pages/webhooks/WebhookEndpointDetail"));
const PartyListPage = lazy(() => import("@/pages/watch-parties/PartyListPage"));
const WatchPartyPage = lazy(() => import("@/pages/watch-parties/WatchPartyPage"));
const ContentCalendarPage = lazy(() => import("@/pages/content-calendar/ContentCalendarPage"));
const CallHistoryPage = lazy(() => import("@/pages/calls/CallHistoryPage"));
const LicenseRequestsPage = lazy(() => import("@/pages/licenses/LicenseRequestsPage"));
const KycTierProgress = lazy(() => import("@/pages/kyc/KycTierProgress"));
const BusinessKycPage = lazy(() => import("@/pages/kyc/BusinessKycPage"));
const BusinessKycReviewPage = lazy(() => import("@/pages/kyc/BusinessKycReviewPage"));
const KycDocumentVerificationPage = lazy(() => import("@/pages/kyc/KycDocumentVerificationPage"));
const KycDocumentReviewQueuePage = lazy(() => import("@/pages/kyc/KycDocumentReviewQueuePage"));
const KycResidencyVerificationPage = lazy(() => import("@/pages/kyc/KycResidencyVerificationPage"));
const KycResidencyReviewQueuePage = lazy(() => import("@/pages/kyc/KycResidencyReviewQueuePage"));
const KycProofOfFunds = lazy(() => import("@/pages/kyc/KycProofOfFunds"));
const KycProofOfFundsReviewQueue = lazy(() => import("@/pages/kyc/KycProofOfFundsReviewQueue"));
const KycLivenessCallSchedulePage = lazy(() => import("@/pages/kyc/KycLivenessCallSchedulePage"));
const KycLivenessCallVerifierPage = lazy(() => import("@/pages/kyc/KycLivenessCallVerifierPage"));
const KycScreeningReviewQueuePage = lazy(() => import("@/pages/kyc/KycScreeningReviewQueuePage"));
const KycIdScannerPage = lazy(() => import("@/pages/kyc/KycIdScannerPage"));
const KycWebhookSettingsPage = lazy(() => import("@/pages/kyc/KycWebhookSettingsPage"));
const KycComplianceReportsPage = lazy(() => import("@/pages/kyc/KycComplianceReportsPage"));
const KycIdScannerReviewQueuePage = lazy(() => import("@/pages/kyc/KycIdScannerReviewQueuePage"));
const KycWizardPage = lazy(() => import("@/pages/kyc/KycWizardPage"));
const KycStatusPage = lazy(() => import("@/pages/kyc/KycStatusPage"));
const WorkersPage = lazy(() => import("@/pages/agents/WorkersPage"));
const QaActionsPage = lazy(() => import("@/pages/agents/QaActionsPage"));
const AgentSessionPage = lazy(() => import("@/pages/agents/AgentSessionPage"));
const AdBillingPage = lazy(() => import("@/pages/ads/AdBillingPage"));
const GroupTreasuryPage = lazy(() => import("@/pages/groups/GroupTreasuryPage"));
const GroupFundraisingPage = lazy(() => import("@/pages/groups/GroupFundraisingPage"));
const GroupAdsPage = lazy(() => import("@/pages/groups/GroupAdsPage"));
const PublicDonationPage = lazy(() => import("@/pages/groups/PublicDonationPage"));
const AgentDashboard = lazy(() => import("@/pages/agents/AgentDashboard"));
const AdAnalyticsDashboard = lazy(() => import("@/pages/ads/AdAnalyticsDashboard"));
const AdSchedulePage = lazy(() => import("@/pages/ads/AdSchedulePage"));
const AdOptimizationPanel = lazy(() => import("@/pages/ads/AdOptimizationPanel"));
const ContentBoostPage = lazy(() => import("@/pages/ads/ContentBoostPage"));
const ContentBoostDetail = lazy(() => import("@/pages/ads/ContentBoostDetail"));
const SponsorshipInbox = lazy(() => import("@/pages/ads/SponsorshipInbox"));
const SponsorshipManager = lazy(() => import("@/pages/ads/SponsorshipManager"));
const SponsorshipDealDetail = lazy(() => import("@/pages/ads/SponsorshipDealDetail"));
const AdAffiliateDiscountPage = lazy(() => import("@/pages/ads/AdAffiliateDiscountPage"));
const ContentAdControlsPage = lazy(() => import("@/pages/ads/ContentAdControlsPage"));
const FleetDashboard = lazy(() => import("@/pages/agents/FleetDashboard"));
const AgentMemoryPage = lazy(() => import("@/pages/agents/AgentMemoryPage"));
const AgentFeedbackPage = lazy(() => import("@/pages/agents/AgentFeedbackPage"));
const AgentPrList = lazy(() => import("@/pages/agents/AgentPrList"));
const CoderAgentConfigPage = lazy(() => import("@/pages/agents/CoderAgentConfigPage"));
const QaAgentConfigPage = lazy(() => import("@/pages/agents/QaAgentConfigPage"));
const DevOpsAgentConfigPage = lazy(() => import("@/pages/agents/DevOpsAgentConfigPage"));
const ArchitectAgentConfigPage = lazy(() => import("@/pages/agents/ArchitectAgentConfigPage"));
const DocCoveragePage = lazy(() => import("@/pages/agents/DocCoveragePage"));
const DocTemplatesPage = lazy(() => import("@/pages/agents/DocTemplatesPage"));
const FeatureIdeasPage = lazy(() => import("@/pages/agents/FeatureIdeasPage"));
const PmAgentConfigPage = lazy(() => import("@/pages/agents/PmAgentConfigPage"));
const ProjectDashboardPage = lazy(() => import("@/pages/agents/ProjectDashboardPage"));
const IdeaSubmissionPage = lazy(() => import("@/pages/agents/IdeaSubmissionPage"));
const StylistDesignOverviewPage = lazy(() => import("@/pages/agents/StylistDesignOverviewPage"));
const StylistReviewDetailPage = lazy(() => import("@/pages/agents/StylistReviewDetailPage"));
const StylistDesignRulesPage = lazy(() => import("@/pages/agents/StylistDesignRulesPage"));
const MarketingContentDashboardPage = lazy(() => import("@/pages/agents/MarketingContentDashboardPage"));
const MarketingContentEditorPage = lazy(() => import("@/pages/agents/MarketingContentEditorPage"));
const MarketingContentCalendarPage = lazy(() => import("@/pages/agents/MarketingContentCalendarPage"));
const MarketingEngagementDashboardPage = lazy(() => import("@/pages/agents/MarketingEngagementDashboardPage"));
const ComplianceAgentConfigPage = lazy(() => import("@/pages/agents/ComplianceAgentConfigPage"));
const CostOverviewPage = lazy(() => import("@/pages/agents/CostOverviewPage"));
const CostBreakdownPage = lazy(() => import("@/pages/agents/CostBreakdownPage"));
const BudgetManagerPage = lazy(() => import("@/pages/agents/BudgetManagerPage"));
const CostAlertsPage = lazy(() => import("@/pages/agents/CostAlertsPage"));
const KycAnalyticsDashboard = lazy(() => import("@/pages/admin/KycAnalyticsDashboard"));
const KycQueuePage = lazy(() => import("@/pages/admin/KycQueuePage"));
const KycCaseDetailPage = lazy(() => import("@/pages/admin/KycCaseDetailPage"));
const KycMetricsDashboard = lazy(() => import("@/pages/admin/KycMetricsDashboard"));

// OFBiz frontend batch 1 (PRD, ORD, POS, MFG, FXA, PUR)
const CatalogDepthPage = lazy(() => import("@/pages/catalogDepth/CatalogDepthPage"));
const OrdersPage = lazy(() => import("@/pages/orders/OrdersPage"));
const OrderDetailPage = lazy(() => import("@/pages/orders/OrderDetailPage"));
const PosTerminalPage = lazy(() => import("@/pages/pos/PosTerminalPage"));
const PosReportsPage = lazy(() => import("@/pages/pos/PosReportsPage"));
const BomEditorPage = lazy(() => import("@/pages/manufacturing/BomEditorPage"));
const WorkOrderQueuePage = lazy(() => import("@/pages/manufacturing/WorkOrderQueuePage"));
const MrpPage = lazy(() => import("@/pages/manufacturing/MrpPage"));
const WorkCentersPage = lazy(() => import("@/pages/manufacturing/WorkCentersPage"));
const FixedAssetsPage = lazy(() => import("@/pages/fixedAssets/FixedAssetsPage"));
const MaintenanceQueuePage = lazy(() => import("@/pages/fixedAssets/MaintenanceQueuePage"));
const PurchasingPage = lazy(() => import("@/pages/purchasing/PurchasingPage"));
const PurchaseOrderDetailPage = lazy(() => import("@/pages/purchasing/PurchaseOrderDetailPage"));
const SupplierDetailPage = lazy(() => import("@/pages/purchasing/SupplierDetailPage"));

// OFBiz frontend batch 2 (SHP, MKT, HRM, ECM, FAC, OFB-core)
const ShippingPage = lazy(() => import("@/pages/shipping/ShippingPage"));
const MarketingPage = lazy(() => import("@/pages/marketing/MarketingPage"));
const HrPage = lazy(() => import("@/pages/hr/HrPage"));
const StorefrontPage = lazy(() => import("@/pages/storeIntegration/StorefrontPage"));
const CartPricingPage = lazy(() => import("@/pages/storeIntegration/CartPricingPage"));
const OrderFulfillmentPage = lazy(() => import("@/pages/storeIntegration/OrderFulfillmentPage"));
const FacilitiesPage = lazy(() => import("@/pages/facility/FacilitiesPage"));
const FulfillmentPage = lazy(() => import("@/pages/facility/FulfillmentPage"));
const ErpOverviewPage = lazy(() => import("@/pages/erp/ErpOverviewPage"));
const ErpInventoryPage = lazy(() => import("@/pages/erp/InventoryPage"));
const ErpReturnsPage = lazy(() => import("@/pages/erp/ReturnsPage"));

// SuiteCRM frontend batch 1 (LED, OPP, CAS, QUO, ACT, RPT)
const LeadsListPage = lazy(() => import("@/pages/crm/leads/LeadsListPage"));
const CreateLeadPage = lazy(() => import("@/pages/crm/leads/CreateLeadPage"));
const LeadDetailPage = lazy(() => import("@/pages/crm/leads/LeadDetailPage"));
const OpportunitiesPage = lazy(() => import("@/pages/opportunities/OpportunitiesPage"));
const PipelineReportPage = lazy(() => import("@/pages/opportunities/PipelineReportPage"));
const OpportunityDetailPage = lazy(() => import("@/pages/opportunities/OpportunityDetailPage"));
const CasesPage = lazy(() => import("@/pages/crm/cases/CasesPage"));
const CaseDetailPage = lazy(() => import("@/pages/crm/cases/CaseDetailPage"));
const QuotesPage = lazy(() => import("@/pages/quotes/QuotesPage"));
const QuoteDetailPage = lazy(() => import("@/pages/quotes/QuoteDetailPage"));
const ContractsPage = lazy(() => import("@/pages/quotes/ContractsPage"));
const ContractDetailPage = lazy(() => import("@/pages/quotes/ContractDetailPage"));
const MyActivitiesPage = lazy(() => import("@/pages/crmActivities/MyActivitiesPage"));
const ActivityTimelinePage = lazy(() => import("@/pages/crmActivities/ActivityTimelinePage"));
const CrmReportsListPage = lazy(() => import("@/pages/crm/reports/ReportsListPage"));
const CrmReportViewerPage = lazy(() => import("@/pages/crm/reports/ReportViewerPage"));
const CrmDashboardPage = lazy(() => import("@/pages/crm/reports/DashboardPage"));

// SuiteCRM frontend batch 2 (KB, EML, INV, WFL, STU, PRJ)
const KnowledgeBasePage = lazy(() => import("@/pages/knowledge-base/KnowledgeBasePage"));
const KbManagePage = lazy(() => import("@/pages/knowledge-base/KbManagePage"));
const KbArticleEditorPage = lazy(() => import("@/pages/knowledge-base/KbArticleEditorPage"));
const KbArticlePage = lazy(() => import("@/pages/knowledge-base/KbArticlePage"));
const KbTagPage = lazy(() => import("@/pages/knowledge-base/KbTagPage"));
const KbPortalPage = lazy(() => import("@/pages/knowledge-base/KbPortalPage"));
const KbPortalArticlePage = lazy(() => import("@/pages/knowledge-base/KbPortalArticlePage"));
const EmailTemplatesPage = lazy(() => import("@/pages/crmEmail/EmailTemplatesPage"));
const EmailComposePage = lazy(() => import("@/pages/crmEmail/EmailComposePage"));
const EmailLogPage = lazy(() => import("@/pages/crmEmail/EmailLogPage"));
const CrmInvoicesPage = lazy(() => import("@/pages/crmInvoices/CrmInvoicesPage"));
const CrmConvertQuotePage = lazy(() => import("@/pages/crmInvoices/CrmConvertQuotePage"));
const CrmInvoiceDetailPage = lazy(() => import("@/pages/crmInvoices/CrmInvoiceDetailPage"));
const CrmBillingSettingsPage = lazy(() => import("@/pages/crmInvoices/CrmBillingSettingsPage"));
const WorkflowRulesPage = lazy(() => import("@/pages/crmWorkflow/WorkflowRulesPage"));
const WorkflowDripSequencesPage = lazy(() => import("@/pages/crmWorkflow/WorkflowDripSequencesPage"));
const CrmSecurityPage = lazy(() => import("@/pages/crmStudio/CrmSecurityPage"));
const CrmStudioPage = lazy(() => import("@/pages/crmStudio/CrmStudioPage"));
const CrmProjectsListPage = lazy(() => import("@/pages/crmProjects/ProjectsPage"));
const CrmProjectDetailPage = lazy(() => import("@/pages/crmProjects/ProjectDetailPage"));

// SuiteCRM frontend batch 3 (EVT subs, CCT, CMP)
const CrmEventsPage = lazy(() => import("@/pages/crmEvents/CrmEventsPage"));
const CrmEventCreatePage = lazy(() => import("@/pages/crmEvents/CrmEventCreatePage"));
const CrmEventDetailPage = lazy(() => import("@/pages/crmEvents/CrmEventDetailPage"));
const CrmSurveysPage = lazy(() => import("@/pages/crmSurveys/CrmSurveysPage"));
const CrmSurveyBuilderPage = lazy(() => import("@/pages/crmSurveys/CrmSurveyBuilderPage"));
const CrmSurveyResultsPage = lazy(() => import("@/pages/crmSurveys/CrmSurveyResultsPage"));
const CrmDocumentsListPage = lazy(() => import("@/pages/crmDocuments/CrmDocumentsListPage"));
const CrmDocumentUploadPage = lazy(() => import("@/pages/crmDocuments/CrmDocumentUploadPage"));
const CrmDocumentDetailPage = lazy(() => import("@/pages/crmDocuments/CrmDocumentDetailPage"));
const CrmMapsPage = lazy(() => import("@/pages/crm-maps/CrmMapsPage"));
const CrmSmsPage = lazy(() => import("@/pages/crmSms/CrmSmsPage"));
const CrmAuditLogPage = lazy(() => import("@/pages/crmAuditLog/CrmAuditLogPage"));
const OrgAccountsPage = lazy(() => import("@/pages/crm/OrgAccountsPage"));
const ManagerChainPage = lazy(() => import("@/pages/crm/ManagerChainPage"));
const PartyDedupPage = lazy(() => import("@/pages/crm/PartyDedupPage"));
const VcardImportPage = lazy(() => import("@/pages/crm/VcardImportPage"));
const CampaignsPage = lazy(() => import("@/pages/crmCampaigns/CampaignsPage"));
const WebLeadsPage = lazy(() => import("@/pages/crmCampaigns/WebLeadsPage"));
const LeadCaptureFormPage = lazy(() => import("@/pages/crmCampaigns/LeadCaptureFormPage"));

// OpenCATS frontend (JOB, CND, PIP, PRT, RSK, ATI)
const JobOrdersPage = lazy(() => import("@/pages/ats/JobOrdersPage"));
const JobOrderDetailPage = lazy(() => import("@/pages/ats/JobOrderDetailPage"));
const CandidatesListPage = lazy(() => import("@/pages/ats/candidates/CandidatesListPage"));
const CreateCandidatePage = lazy(() => import("@/pages/ats/candidates/CreateCandidatePage"));
const CandidateDetailPage = lazy(() => import("@/pages/ats/candidates/CandidateDetailPage"));
const PipelineBoardPage = lazy(() => import("@/pages/ats/pipeline/PipelineBoardPage"));
const PipelineDetailPage = lazy(() => import("@/pages/ats/pipeline/PipelineDetailPage"));
const CandidatePipelinePage = lazy(() => import("@/pages/ats/pipeline/CandidatePipelinePage"));
const JobBoardPage = lazy(() => import("@/pages/ats/portal/JobBoardPage"));
const PortalJobDetailPage = lazy(() => import("@/pages/ats/portal/JobDetailPage"));
const ApplicationConfirmationPage = lazy(() => import("@/pages/ats/portal/ApplicationConfirmationPage"));
const AdminPortalConfigPage = lazy(() => import("@/pages/ats/portal/AdminPortalConfigPage"));
const SkillsRegistryPage = lazy(() => import("@/pages/ats/skills/SkillsRegistryPage"));
const CandidateSkillProfilePage = lazy(() => import("@/pages/ats/skills/CandidateSkillProfilePage"));
const ResumeSkillSearchPage = lazy(() => import("@/pages/ats/search/ResumeSkillSearchPage"));
const AtsIntegrationPage = lazy(() => import("@/pages/ats/integration/AtsIntegrationPage"));

// OBP (Open Bank Project) frontend — ACC, OAU, PLT, VEW, CUS, TXR, CSN, PAY
const BankAccountsPage = lazy(() => import("@/pages/bankAccounts/BankAccountsPage"));
const BankAccountDetailPage = lazy(() => import("@/pages/bankAccounts/BankAccountDetailPage"));
const OAuthClientsPage = lazy(() => import("@/pages/oauthClients/OAuthClientsPage"));
const OAuthClientDetailPage = lazy(() => import("@/pages/oauthClients/OAuthClientDetailPage"));
const BankPlatformPage = lazy(() => import("@/pages/bankPlatform/BankPlatformPage"));
const AccountViewsPage = lazy(() => import("@/pages/accountViews/AccountViewsPage"));
const ViewResourcePage = lazy(() => import("@/pages/accountViews/ViewResourcePage"));
const PublicViewPage = lazy(() => import("@/pages/accountViews/PublicViewPage"));
const BankCustomersPage = lazy(() => import("@/pages/bankCustomers/BankCustomersPage"));
const BankCardsPage = lazy(() => import("@/pages/bankCustomers/BankCardsPage"));
const BankProductsPage = lazy(() => import("@/pages/bankCustomers/BankProductsPage"));
const TransfersPage = lazy(() => import("@/pages/bankTransfers/TransfersPage"));
const CreateTransferPage = lazy(() => import("@/pages/bankTransfers/CreateTransferPage"));
const TransferDetailPage = lazy(() => import("@/pages/bankTransfers/TransferDetailPage"));
const ConsentsPage = lazy(() => import("@/pages/bankConsents/ConsentsPage"));
const CreateConsentPage = lazy(() => import("@/pages/bankConsents/CreateConsentPage"));
const ConsentDetailPage = lazy(() => import("@/pages/bankConsents/ConsentDetailPage"));
const CounterpartiesPage = lazy(() => import("@/pages/bankPayments/CounterpartiesPage"));
const StandingOrdersPage = lazy(() => import("@/pages/bankPayments/StandingOrdersPage"));
const MandatesPage = lazy(() => import("@/pages/bankPayments/MandatesPage"));
const FxRatesPage = lazy(() => import("@/pages/bankPayments/FxRatesPage"));

// QloApps (hotel PMS) frontend
const HotelsListPage = lazy(() => import("@/pages/hotels/setup/HotelsListPage"));
const HotelDetailPage = lazy(() => import("@/pages/hotels/setup/HotelDetailPage"));
const HotelAmenitiesPage = lazy(() => import("@/pages/hotels/setup/AmenitiesPage"));
const RoomTypesPage = lazy(() => import("@/pages/hotels/setup/RoomTypesPage"));
const RoomsPage = lazy(() => import("@/pages/hotels/setup/RoomsPage"));
const HousekeepingBoardPage = lazy(() => import("@/pages/hotels/setup/HousekeepingBoardPage"));
const AvailabilityCalendarPage = lazy(() => import("@/pages/hotels/inventory/AvailabilityCalendarPage"));
const RatePlansPage = lazy(() => import("@/pages/hotels/rate-plans/RatePlansPage"));
const HotelBookingPage = lazy(() => import("@/pages/hotels/booking/HotelBookingPage"));
const HotelReservationsPage = lazy(() => import("@/pages/hotels/booking/HotelReservationsPage"));
const HotelReservationDetailPage = lazy(() => import("@/pages/hotels/booking/ReservationDetailPage"));
const FrontDeskDashboard = lazy(() => import("@/pages/hotels/frontdesk/FrontDeskDashboard"));
const CheckInPage = lazy(() => import("@/pages/hotels/frontdesk/CheckInPage"));
const CheckOutPage = lazy(() => import("@/pages/hotels/frontdesk/CheckOutPage"));
const WalkInPage = lazy(() => import("@/pages/hotels/frontdesk/WalkInPage"));
const ManageReservationPage = lazy(() => import("@/pages/hotels/frontdesk/ManageReservationPage"));
const FolioListPage = lazy(() => import("@/pages/hotels/folios/FolioListPage"));
const FolioDetailPage = lazy(() => import("@/pages/hotels/folios/FolioDetailPage"));
const CancellationPolicyPage = lazy(() => import("@/pages/hotels/reports/CancellationPolicyPage"));
const HotelKpiDashboard = lazy(() => import("@/pages/hotels/reports/HotelKpiDashboard"));

// open-property + ticket-bounty frontend
const PropertiesPage = lazy(() => import("@/pages/properties/PropertiesPage"));
const PropertyDetailPage = lazy(() => import("@/pages/properties/PropertyDetailPage"));
const PropTenantsPage = lazy(() => import("@/pages/property/tenants/TenantsPage"));
const TenantProfilePage = lazy(() => import("@/pages/property/tenants/TenantProfilePage"));
const LeasesPage = lazy(() => import("@/pages/property/leases/LeasesPage"));
const LeaseDetailPage = lazy(() => import("@/pages/property/leases/LeaseDetailPage"));
const RentLedgerPage = lazy(() => import("@/pages/property/rent/RentLedgerPage"));
const LeaseRentPage = lazy(() => import("@/pages/property/rent/LeaseRentPage"));
const RentAgingPage = lazy(() => import("@/pages/property/rent/RentAgingPage"));
const WorkOrdersPage = lazy(() => import("@/pages/property/workOrders/WorkOrdersPage"));
const WorkOrderDetailPage = lazy(() => import("@/pages/property/workOrders/WorkOrderDetailPage"));
const VendorsPage = lazy(() => import("@/pages/property/workOrders/VendorsPage"));
const PortfolioDashboardPage = lazy(() => import("@/pages/property/dashboard/PortfolioDashboardPage"));
const RentPolicyPage = lazy(() => import("@/pages/property/policies/RentPolicyPage"));
const PropertyDocumentsPage = lazy(() => import("@/pages/property/dashboard/PropertyDocumentsPage"));
const BountyBoardPage = lazy(() => import("@/pages/bounties/BountyBoardPage"));

// TKB-014: legacy /tickets/spaces/:spaceId → /tickets/boards/:boardId
// (board_id == space_id), preserving bookmarks/links during the rename.
function LegacySpaceRedirect() {
  const { spaceId = "" } = useParams();
  return <Navigate to={`/tickets/boards/${spaceId}`} replace />;
}

function PageSpinner() {
  return (
    <div className="flex h-full items-center justify-center py-32">
      <Loader2 className="h-8 w-8 animate-spin text-muted-foreground" />
    </div>
  );
}

export default function App() {
  const showVncRemoteDesktop = isVncRemoteDesktopEnabled();
  const showBrowserSsh = isBrowserSshEnabled();
  const showAgentSshQa = isAgentSshQaEnabled();
  const showBroadcastNavigation = isBroadcastNavigationEnabled();
  const showCanonicalProfileRoute = isCanonicalProfileNavigationEnabled();

  return (
    <>
    <SeoHead
      title="Control Panel"
      description="Your all-in-one platform for messaging, commerce, and content creation."
      ogType="website"
    />
      <Helmet>
        <title>Control Panel</title>
        <meta name="description" content="Your all-in-one platform for messaging, commerce, and content creation." />
        <meta property="og:type" content="website" />
        <meta property="og:site_name" content="Control Panel" />
        <meta property="og:locale" content="en_US" />
        <meta name="twitter:card" content="summary" />
      </Helmet>
      <Suspense fallback={<PageSpinner />}>
        <Routes>
        {/* Public routes (no shell) */}
        <Route path="/login" element={<Login />} />
        <Route path="/register" element={<Register />} />
        <Route path="/password-recovery" element={<PasswordRecovery />} />
        <Route path="/magic-link-verify" element={<MagicLinkVerify />} />
        {showCanonicalProfileRoute && <Route path="/u/:identifier" element={<PublicUserProfilePage />} />}
        <Route path="/event/:calendarId/:eventId" element={<PublicEventPage />} />
        <Route path="/bank/views/public/:token" element={<PublicViewPage />} />
        <Route path="/sign/:token" element={<PublicSigningPage />} />
        <Route path="/share/:linkId" element={<PublicDownloadPage />} />
        <Route path="/donate/:fundraiserId" element={<PublicDonationPage />} />
        <Route path="/c/:clipId" element={<PublicClipPage />} />
        <Route path="/questionnaires/published/:publishedSlug/respond" element={<QuestionnaireRespondentPage />} />
        <Route path="live/:sessionId" element={<LivePlayer />} />
        <Route path="party/:inviteCode" element={<PartyListPage />} />

        {/* Protected routes inside AppShell layout */}
        <Route element={<ProtectedRoute><AppShell /></ProtectedRoute>}>
          <Route index element={<Dashboard />} />
          <Route path="messages" element={<MessagesPage />} />
          <Route path="messages/:conversationId" element={<MessagesPage />} />
          <Route path="calls/history" element={<CallHistoryPage />} />
          <Route path="calls/settings" element={<MediaSettingsPage />} />
          <Route path="contacts" element={<ContactsPage />} />
          <Route path="helpdesk" element={<HelpdeskPage />} />
          <Route path="files" element={<FilesPage />} />
          <Route path="files/share-links" element={<ShareLinksPage />} />
          <Route path="signing" element={<SigningPage />} />
          <Route path="signing/new" element={<CreateSignatureRequestPage />} />
          <Route path="signing/inbox" element={<SigningInboxPage />} />
          <Route path="signing/inbox/:packetId" element={<SigningInboxPage />} />
          <Route path="projects" element={<ProjectsPage />} />
          {/* OFBiz frontend batch 1 */}
          <Route path="orders" element={<OrdersPage />} />
          <Route path="orders/:orderId" element={<OrderDetailPage />} />
          <Route path="ofbiz/catalog-depth" element={<CatalogDepthPage />} />
          <Route path="ofbiz/pos" element={<PosTerminalPage />} />
          <Route path="ofbiz/pos/reports" element={<PosReportsPage />} />
          <Route path="ofbiz/fixed-assets" element={<FixedAssetsPage />} />
          <Route path="ofbiz/fixed-assets/maintenance" element={<MaintenanceQueuePage />} />
          <Route path="manufacturing/boms" element={<BomEditorPage />} />
          <Route path="manufacturing/work-orders" element={<WorkOrderQueuePage />} />
          <Route path="manufacturing/mrp" element={<MrpPage />} />
          <Route path="manufacturing/work-centers" element={<WorkCentersPage />} />
          <Route path="purchasing" element={<PurchasingPage />} />
          <Route path="purchasing/purchase-orders/:poId" element={<PurchaseOrderDetailPage />} />
          <Route path="purchasing/suppliers/:supplierId" element={<SupplierDetailPage />} />
          {/* OFBiz frontend batch 2 */}
          <Route path="ofbiz/shipping" element={<ShippingPage />} />
          <Route path="ofbiz/marketing" element={<MarketingPage />} />
          <Route path="ofbiz/hr" element={<HrPage />} />
          <Route path="ofbiz/storefront" element={<StorefrontPage />} />
          <Route path="ofbiz/cart-pricing" element={<CartPricingPage />} />
          <Route path="ofbiz/order-fulfillment" element={<OrderFulfillmentPage />} />
          <Route path="ofbiz/order-fulfillment/:orderId" element={<OrderFulfillmentPage />} />
          <Route path="ofbiz/facilities" element={<FacilitiesPage />} />
          <Route path="ofbiz/fulfillment" element={<FulfillmentPage />} />
          <Route path="erp" element={<ErpOverviewPage />} />
          <Route path="erp/inventory" element={<ErpInventoryPage />} />
          <Route path="erp/returns" element={<ErpReturnsPage />} />
          {/* SuiteCRM frontend batch 1 (literal routes before dynamic params) */}
          <Route path="crm/leads" element={<LeadsListPage />} />
          <Route path="crm/leads/new" element={<CreateLeadPage />} />
          <Route path="crm/leads/:leadId" element={<LeadDetailPage />} />
          <Route path="crm/opportunities" element={<OpportunitiesPage />} />
          <Route path="crm/opportunities/pipeline" element={<PipelineReportPage />} />
          <Route path="crm/opportunities/:oppId" element={<OpportunityDetailPage />} />
          <Route path="crm/cases" element={<CasesPage />} />
          <Route path="crm/cases/:caseId" element={<CaseDetailPage />} />
          <Route path="crm/quotes" element={<QuotesPage />} />
          <Route path="crm/quotes/:quoteId" element={<QuoteDetailPage />} />
          <Route path="crm/contracts" element={<ContractsPage />} />
          <Route path="crm/contracts/:contractId" element={<ContractDetailPage />} />
          <Route path="crm/activities" element={<MyActivitiesPage />} />
          <Route path="crm/timeline" element={<ActivityTimelinePage />} />
          <Route path="crm/timeline/:entityType/:entityId" element={<ActivityTimelinePage />} />
          <Route path="crm/reports" element={<CrmReportsListPage />} />
          <Route path="crm/reports/:reportId" element={<CrmReportViewerPage />} />
          <Route path="crm/dashboard" element={<CrmDashboardPage />} />
          {/* SuiteCRM frontend batch 2 (literals before dynamic params) */}
          <Route path="crm/knowledge-base" element={<KnowledgeBasePage />} />
          <Route path="crm/knowledge-base/manage" element={<KbManagePage />} />
          <Route path="crm/knowledge-base/articles/new" element={<KbArticleEditorPage />} />
          <Route path="crm/knowledge-base/articles/:articleId/edit" element={<KbArticleEditorPage />} />
          <Route path="crm/knowledge-base/articles/:articleId" element={<KbArticlePage />} />
          <Route path="crm/knowledge-base/tags/:tag" element={<KbTagPage />} />
          <Route path="crm/knowledge-base/portal" element={<KbPortalPage />} />
          <Route path="crm/knowledge-base/portal/articles/:articleId" element={<KbPortalArticlePage />} />
          <Route path="crm/email/templates" element={<EmailTemplatesPage />} />
          <Route path="crm/email/compose" element={<EmailComposePage />} />
          <Route path="crm/email/log" element={<EmailLogPage />} />
          <Route path="crm/invoices" element={<CrmInvoicesPage />} />
          <Route path="crm/invoices/convert" element={<CrmConvertQuotePage />} />
          <Route path="crm/invoices/:invoiceNumber" element={<CrmInvoiceDetailPage />} />
          <Route path="crm/billing-settings" element={<CrmBillingSettingsPage />} />
          <Route path="crm/workflow" element={<WorkflowRulesPage />} />
          <Route path="crm/workflow/drip-sequences" element={<WorkflowDripSequencesPage />} />
          <Route path="crm/security" element={<CrmSecurityPage />} />
          <Route path="crm/studio" element={<CrmStudioPage />} />
          <Route path="crm/projects" element={<CrmProjectsListPage />} />
          <Route path="crm/projects/:projectId" element={<CrmProjectDetailPage />} />
          {/* SuiteCRM frontend batch 3 (literals before dynamic params) */}
          <Route path="crm/events" element={<CrmEventsPage />} />
          <Route path="crm/events/new" element={<CrmEventCreatePage />} />
          <Route path="crm/events/:eventId" element={<CrmEventDetailPage />} />
          <Route path="crm/surveys" element={<CrmSurveysPage />} />
          <Route path="crm/surveys/:surveyId/build" element={<CrmSurveyBuilderPage />} />
          <Route path="crm/surveys/:surveyId/results" element={<CrmSurveyResultsPage />} />
          <Route path="crm/documents" element={<CrmDocumentsListPage />} />
          <Route path="crm/documents/upload" element={<CrmDocumentUploadPage />} />
          <Route path="crm/documents/detail/:docPath" element={<CrmDocumentDetailPage />} />
          <Route path="crm/maps" element={<CrmMapsPage />} />
          <Route path="crm/sms" element={<CrmSmsPage />} />
          <Route path="crm/audit-log" element={<CrmAuditLogPage />} />
          <Route path="crm/org-accounts" element={<OrgAccountsPage />} />
          <Route path="crm/reports-to" element={<ManagerChainPage />} />
          <Route path="crm/party-dedup" element={<PartyDedupPage />} />
          <Route path="crm/vcard-import" element={<VcardImportPage />} />
          <Route path="crm/campaigns" element={<CampaignsPage />} />
          <Route path="crm/web-leads" element={<WebLeadsPage />} />
          <Route path="crm/lead-capture" element={<LeadCaptureFormPage />} />
          {/* OpenCATS (ATS) — literals before dynamic params */}
          <Route path="ats/jobs" element={<JobOrdersPage />} />
          <Route path="ats/jobs/:jobId" element={<JobOrderDetailPage />} />
          <Route path="ats/candidates" element={<CandidatesListPage />} />
          <Route path="ats/candidates/new" element={<CreateCandidatePage />} />
          <Route path="ats/candidates/:candidateId" element={<CandidateDetailPage />} />
          <Route path="ats/pipeline" element={<PipelineBoardPage />} />
          <Route path="ats/pipeline/detail/:jobOrderId/:candidateId" element={<PipelineDetailPage />} />
          <Route path="ats/pipeline/candidate/:candidateId" element={<CandidatePipelinePage />} />
          <Route path="ats/portal/jobs" element={<JobBoardPage />} />
          <Route path="ats/portal/jobs/:slug" element={<PortalJobDetailPage />} />
          <Route path="ats/portal/confirmation/:applicationId" element={<ApplicationConfirmationPage />} />
          <Route path="ats/applications" element={<AdminPortalConfigPage />} />
          <Route path="ats/skills" element={<SkillsRegistryPage />} />
          <Route path="ats/skills/candidate/:candidateId" element={<CandidateSkillProfilePage />} />
          <Route path="ats/search" element={<ResumeSkillSearchPage />} />
          <Route path="ats/integration" element={<AtsIntegrationPage />} />
          {/* OBP (Open Bank Project) — literals before dynamic params */}
          <Route path="bank/accounts" element={<BankAccountsPage />} />
          <Route path="bank/accounts/:accountId" element={<BankAccountDetailPage />} />
          <Route path="bank/oauth-clients" element={<OAuthClientsPage />} />
          <Route path="bank/oauth-clients/:clientId" element={<OAuthClientDetailPage />} />
          <Route path="bank/platform" element={<BankPlatformPage />} />
          <Route path="bank/views" element={<AccountViewsPage />} />
          <Route path="bank/views/read/:resourceType/:resourceId/:viewId" element={<ViewResourcePage />} />
          <Route path="bank/customers" element={<BankCustomersPage />} />
          <Route path="bank/cards" element={<BankCardsPage />} />
          <Route path="bank/products" element={<BankProductsPage />} />
          <Route path="bank/transfers" element={<TransfersPage />} />
          <Route path="bank/transfers/new" element={<CreateTransferPage />} />
          <Route path="bank/transfers/:requestId" element={<TransferDetailPage />} />
          <Route path="bank/consents" element={<ConsentsPage />} />
          <Route path="bank/consents/new" element={<CreateConsentPage />} />
          <Route path="bank/consents/:consentId" element={<ConsentDetailPage />} />
          <Route path="bank/payments/counterparties" element={<CounterpartiesPage />} />
          <Route path="bank/payments/standing-orders" element={<StandingOrdersPage />} />
          <Route path="bank/payments/mandates" element={<MandatesPage />} />
          <Route path="bank/payments/fx" element={<FxRatesPage />} />
          {/* QloApps (hotel PMS) — static segments rank above dynamic in RR v6 */}
          <Route path="hotels/setup" element={<HotelsListPage />} />
          <Route path="hotels/setup/amenities" element={<HotelAmenitiesPage />} />
          <Route path="hotels/setup/:hotelId" element={<HotelDetailPage />} />
          <Route path="hotels/:hotelId/room-types" element={<RoomTypesPage />} />
          <Route path="hotels/:hotelId/rooms" element={<RoomsPage />} />
          <Route path="hotels/:hotelId/housekeeping" element={<HousekeepingBoardPage />} />
          <Route path="hotels/availability" element={<AvailabilityCalendarPage />} />
          <Route path="hotels/rate-plans" element={<RatePlansPage />} />
          <Route path="hotels/book" element={<HotelBookingPage />} />
          <Route path="hotels/reservations" element={<HotelReservationsPage />} />
          <Route path="hotels/reservations/:hotelId/:reservationId" element={<HotelReservationDetailPage />} />
          <Route path="hotels/front-desk" element={<FrontDeskDashboard />} />
          <Route path="hotels/front-desk/walk-in" element={<WalkInPage />} />
          <Route path="hotels/front-desk/check-in/:reservationId" element={<CheckInPage />} />
          <Route path="hotels/front-desk/check-out/:reservationId" element={<CheckOutPage />} />
          <Route path="hotels/front-desk/manage/:reservationId" element={<ManageReservationPage />} />
          <Route path="hotels/folios" element={<FolioListPage />} />
          <Route path="hotels/folios/:hotelId/:rid" element={<FolioDetailPage />} />
          <Route path="hotels/policies" element={<CancellationPolicyPage />} />
          <Route path="hotels/policies/:hotelId" element={<CancellationPolicyPage />} />
          <Route path="hotels/reports" element={<HotelKpiDashboard />} />
          <Route path="hotels/reports/:hotelId" element={<HotelKpiDashboard />} />
          {/* open-property + ticket-bounty */}
          <Route path="properties" element={<PropertiesPage />} />
          <Route path="properties/:propertyId" element={<PropertyDetailPage />} />
          <Route path="property/tenants" element={<PropTenantsPage />} />
          <Route path="property/tenants/:tenantId" element={<TenantProfilePage />} />
          <Route path="property/leases" element={<LeasesPage />} />
          <Route path="property/leases/:leaseId" element={<LeaseDetailPage />} />
          <Route path="property/rent" element={<RentLedgerPage />} />
          <Route path="property/rent/aging" element={<RentAgingPage />} />
          <Route path="property/rent/leases/:leaseId" element={<LeaseRentPage />} />
          <Route path="property/work-orders" element={<WorkOrdersPage />} />
          <Route path="property/work-orders/:propertyId/:workOrderId" element={<WorkOrderDetailPage />} />
          <Route path="property/vendors" element={<VendorsPage />} />
          <Route path="property/dashboard" element={<PortfolioDashboardPage />} />
          <Route path="property/dashboard/documents" element={<PropertyDocumentsPage />} />
          <Route path="property/policies" element={<RentPolicyPage />} />
          <Route path="bounties" element={<BountyBoardPage />} />
          <Route path="projects/:projectId" element={<ProjectDetailPage />} />
          <Route path="questionnaires/:questionnaireId/builder" element={<QuestionnaireBuilderPage />} />
          <Route path="billing" element={<BillingPage />} />
          <Route path="billing/refunds" element={<RefundRequestsPage />} />
          <Route path="billing/invoices" element={<InvoicesPage />} />
          <Route path="billing/tax-documents" element={<TaxDocumentsPage />} />
          <Route path="billing/tax-forms" element={<TaxForm1099Page />} />
          <Route path="billing/disputes" element={<DisputesPage />} />
          <Route path="ads/billing" element={<AdBillingPage />} />
          <Route path="ads/dashboard" element={<AdvertiserDashboard />} />
          <Route path="ads/campaigns" element={<CampaignList />} />
          <Route path="ads/targeting" element={<TargetingEditor />} />
          <Route path="ads/creatives" element={<CreativeListPage />} />
          <Route path="earnings" element={<EarningsPage />} />
          <Route path="ads/analytics" element={<AdAnalyticsDashboard />} />
          <Route path="ads/scheduling" element={<AdSchedulePage />} />
          <Route path="ads/optimization" element={<AdOptimizationPanel />} />
          <Route path="ads/boost" element={<ContentBoostPage />} />
          <Route path="ads/boost/:boostId" element={<ContentBoostDetail />} />
          <Route path="ads/sponsorships" element={<SponsorshipInbox />} />
          <Route path="ads/sponsorships/manage" element={<SponsorshipManager />} />
          <Route path="ads/sponsorships/:dealId" element={<SponsorshipDealDetail />} />
          <Route path="ads/affiliate-discounts" element={<AdAffiliateDiscountPage />} />
          <Route path="ads/content-controls" element={<ContentAdControlsPage />} />
          <Route path="calendar" element={<CalendarPage />} />
          <Route path="content-calendar" element={<ContentCalendarPage />} />
          <Route path="agents/memory/:workerId" element={<AgentMemoryPage />} />
          <Route path="agents/feedback" element={<AgentFeedbackPage />} />
          <Route path="scheduler" element={<SchedulerPage />} />
          <Route path="shop" element={<CatalogPage />} />
          <Route path="shop/:categoryId/:itemId" element={<ProductDetail />} />
          <Route path="shop/admin/catalog/depth/:itemId" element={<ShopCatalogDepthPage />} />
          <Route path="shop/admin/orders/:orderId/lifecycle" element={<ShopOrderLifecyclePage />} />
          <Route path="shop/admin/shipping" element={<ShopShippingAdminPage />} />
          <Route path="cart" element={<CartPage />} />
          <Route path="cart/checkout" element={<Checkout />} />
          <Route path="feed" element={<FeedPage />} />
          <Route path="discover" element={<DiscoverPage />} />
          <Route path="discover/tags/:tag" element={<TagPage />} />
          <Route path="search" element={<SearchPage />} />
          <Route path="saved" element={<SavedPage />} />
          <Route path="posts/:postId" element={<PostDetailPage />} />
          <Route path="feed/delegate/:creatorId" element={<DelegateFeedPage />} />
          <Route path="syndicates" element={<SyndicatesPage />} />
          <Route path="syndicates/my-bundles" element={<MyBundlesPage />} />
          <Route path="syndicates/:syndicateId" element={<SyndicateProfilePage />} />
          <Route path="syndicates/:syndicateId/manage" element={<SyndicateDetailPage />} />
          <Route path="syndicates/:syndicateId/campaigns/:campaignId" element={<SyndicateAdvertisingDetailPage />} />
          <Route path="delegates" element={<DelegatesPage />} />
          <Route path="delegation-api" element={<DelegationApiKeysPage />} />
          <Route path="alerts" element={<AlertsPage />} />
          <Route path="activity" element={<ActivityFeedPage />} />
          <Route path="notifications" element={<NotificationsPage />} />
          <Route path="appeals" element={<AppealsPage />} />
          <Route path="tickets" element={<TicketsPage />} />
          <Route path="tickets/boards" element={<BoardsPage />} />
          <Route path="tickets/boards/:boardId" element={<BoardDetailPage />} />
          {/* Legacy spaces routes redirect to the new boards experience (TKB-014). */}
          <Route path="tickets/spaces" element={<Navigate to="/tickets/boards" replace />} />
          <Route path="tickets/spaces/:spaceId" element={<LegacySpaceRedirect />} />
          <Route path="watch-parties" element={<PartyListPage />} />
          <Route path="watch-parties/:partyId" element={<WatchPartyPage />} />
          <Route path="gallery" element={<GalleryPage />} />
          <Route path="gallery/:videoId" element={<GalleryVideoDetailPage />} />
          <Route path="videos" element={<VideosPage />} />
          <Route path="videos/:videoId" element={<VideoPlayerPage />} />
          <Route path="vod/rentals" element={<VodRentalsPage />} />
          <Route path="vod/:videoId/free-with-ads" element={<VodAdSupportedPage />} />
          {showBroadcastNavigation && <Route path="broadcast" element={<BroadcastPage />} />}
          {showBroadcastNavigation && <Route path="broadcast/schedule" element={<BroadcastSchedulePage />} />}
          {showBroadcastNavigation && <Route path="broadcast/:sessionId/live-qa" element={<LiveQaPage />} />}
          <Route path="clips" element={<ClipGalleryPage />} />
          <Route path="clips/:clipId" element={<ClipPlayerPage />} />
          {showVncRemoteDesktop && <Route path="remote-desktop" element={<RemoteDesktopPage />} />}
          <Route path="remote/ec2" element={<Ec2LauncherPage />} />
          <Route path="remote/ssh-keys" element={<SshKeyManagerPage />} />
          {showBrowserSsh && <Route path="remote/ssh" element={<BrowserSshPage />} />}
          {/* ADR-004/CTI-005: RDP fallback surface is always reachable so Windows
              hosts never dead-end in the SSH form, regardless of the RDP flag. */}
          <Route path="remote/rdp" element={<RemoteRdpPage />} />
          <Route path="remote/k8s" element={<K8sLauncherPage />} />
          <Route path="remote/billing" element={<ComputeSpendingPage />} />
          <Route path="remote/security-groups" element={<SecurityGroupsPage />} />
          <Route path="remote/templates" element={<TemplateBrowserPage />} />
          <Route path="remote/recordings" element={<SshRecordingsPage />} />
          <Route path="remote/bastion" element={<SshBastionPage />} />
          <Route path="remote/connection-profiles" element={<ConnectionProfilesPage />} />
          <Route path="remote/hosts" element={<HostInventoryPage />} />
          <Route path="remote/instances/:instanceId/monitoring" element={<InstanceMonitoringPage />} />
          <Route path="bots" element={<BotManagerPage />} />
          <Route path="bots/:botId/templates" element={<TemplateEditorPage />} />
          <Route path="bots/:botId/auto-reply" element={<BotAutoReplyPage />} />
          <Route path="security" element={<SecurityPage />} />
          <Route path="profile" element={<ProfilePage />} />
          <Route path="settings" element={<SettingsPage />} />
          <Route path="settings/privacy" element={<PrivacyPage />} />
          <Route path="settings/theme" element={<ThemeCustomizationPage />} />
          <Route path="settings/account-deletion" element={<AccountDeletionPage />} />
          <Route path="settings/blocked" element={<BlockedUsersPage />} />
          <Route path="settings/webhooks" element={<WebhooksPage />} />
          <Route path="settings/emojis" element={<CustomEmojisPage />} />
          <Route path="settings/geo" element={<GeoRulesPage />} />
          <Route path="settings/call-rate" element={<CallRateSettings />} />
          <Route path="webhooks" element={<WebhookDashboard />} />
          <Route path="webhooks/:endpointId" element={<WebhookEndpointDetail />} />
          <Route path="purchases" element={<PurchasesPage />} />
          <Route path="purchases/:txnId" element={<PurchasesPage />} />
          <Route path="subscriptions" element={<SubscriptionsPage />} />
          <Route path="subscriptions/manage" element={<TierManager />} />
          <Route path="subscriptions/mine" element={<MySubscriptionsPage />} />
          <Route path="subscriptions/subscribers" element={<CreatorSubscribersPage />} />
          <Route path="creator-dashboard" element={<CreatorDashboard />} />
          <Route path="analytics" element={<AnalyticsPage />} />
          <Route path="analytics/content-revenue" element={<ContentRevenuePage />} />
          <Route path="analytics/content/:contentId" element={<ContentDetailPage />} />
          <Route path="payouts" element={<PayoutDashboard />} />
          <Route path="referrals" element={<ReferralDashboard />} />
          <Route path="promo" element={<PromoCodesPage />} />
          <Route path="affiliates" element={<AffiliateDashboard />} />
          <Route path="achievements" element={<AchievementsPage />} />
          <Route path="collaborations" element={<CollaborationsPage />} />
          <Route path="collaborations/:collabId/revenue" element={<CollaborationRevenuePage />} />
          <Route path="fan-club" element={<FanClubPage />} />
          <Route path="orgs" element={<OrgsPage />} />
          <Route path="orgs/:orgId" element={<OrgDashboard />} />
          <Route path="groups" element={<GroupsListPage />} />
          <Route path="groups/:groupId" element={<GroupPage />} />
          <Route path="groups/:groupId/treasury" element={<GroupTreasuryPage />} />
          <Route path="groups/:groupId/fundraising" element={<GroupFundraisingPage />} />
          <Route path="groups/:groupId/ads" element={<GroupAdsPage />} />
          <Route path="groups/:groupId/settings" element={<GroupSettingsPage />} />
          <Route path="root/roles" element={<RootRoleManagementPage />} />
          <Route path="admin/tax-forms-1099" element={<TaxForm1099AdminPage />} />
          <Route path="admin/moderation" element={<ModerationBoardPage />} />
          <Route path="admin/payment-incidents" element={<PaymentIncidentQueuePage />} />
          <Route path="admin/video-review" element={<VideoReviewQueuePage />} />
          <Route path="admin/video-review-queue" element={<VideoReviewQueueModerationPage />} />
          <Route path="dmca/submit" element={<DmcaClaimForm />} />
          <Route path="admin/dmca" element={<DmcaDashboardPage />} />
          <Route path="admin/refunds" element={<AdminRefundQueuePage />} />
          <Route path="admin/bulk-payouts" element={<BulkPayoutConsole />} />
          <Route path="admin/disputes" element={<AdminDisputeQueuePage />} />
          <Route path="admin/appeals" element={<AppealReviewQueuePage />} />
          <Route path="admin/fraud" element={<FraudReviewQueuePage />} />
          <Route path="admin/kyc-workload" element={<KycWorkloadPage />} />
          <Route path="admin/kyc" element={<KycQueuePage />} />
          <Route path="admin/kyc/metrics" element={<KycMetricsDashboard />} />
          <Route path="admin/kyc/cases/:caseId" element={<KycCaseDetailPage />} />
          <Route path="admin/rate-limits" element={<RateLimitDashboard />} />
          <Route path="admin/kyc/monitoring" element={<KycMonitoringPage />} />
          <Route path="admin/kyc/address-verification" element={<KycAddressVerificationPanel />} />
          <Route path="admin/kyc/templates" element={<KycDocumentTemplatesPage />} />
          <Route path="admin/kyc/translations" element={<KycTranslationsPage />} />
          <Route path="admin/communications" element={<EmailSmsDashboardPage />} />
          <Route path="admin/compute" element={<AdminComputeDashboard />} />
          <Route path="admin/inventory" element={<InventoryAdmin />} />
          <Route path="admin/jobs" element={<JobDashboardPage />} />
          <Route path="admin/financials" element={<FinancialDashboard />} />
          <Route path="admin/payment-health" element={<PaymentHealthDashboard />} />
          <Route path="admin/ads/creatives/review" element={<AdminCreativeReviewPage />} />
          <Route path="admin/ads/fraud" element={<AdFraudDashboard />} />
          <Route path="admin/ad-platform" element={<AdPlatformDashboard />} />
          <Route path="admin/audit-exports" element={<AuditExportPage />} />
          <Route path="admin/legal-holds" element={<LegalHoldPage />} />
          <Route path="admin/kyc/analytics" element={<KycAnalyticsDashboard />} />
          <Route path="admin/tenants" element={<TenantAdmin />} />
          <Route path="admin/sso" element={<SsoProvidersPage />} />
          <Route path="licenses/revenue" element={<LicenseRevenuePage />} />
          <Route path="admin/risk" element={<RiskDashboardPage />} />
          <Route path="admin/security" element={<SecurityDashboardPage />} />
          <Route path="admin/subscription-tiers" element={<SubscriptionTierManagerPage />} />
          <Route path="admin/billing-config" element={<BillingConfigPage />} />
          <Route path="licenses/requests" element={<LicenseRequestsPage />} />
          <Route path="kyc" element={<KycWizardPage />} />
          <Route path="kyc/status" element={<KycStatusPage />} />
          <Route path="kyc/tiers" element={<KycTierProgress />} />
          <Route path="kyc/business" element={<BusinessKycPage />} />
          <Route path="admin/kyc/business" element={<BusinessKycReviewPage />} />
          <Route path="kyc/documents" element={<KycDocumentVerificationPage />} />
          <Route path="admin/kyc/documents" element={<KycDocumentReviewQueuePage />} />
          <Route path="kyc/residency" element={<KycResidencyVerificationPage />} />
          <Route path="admin/kyc/residency" element={<KycResidencyReviewQueuePage />} />
          <Route path="kyc/proof-of-funds" element={<KycProofOfFunds />} />
          <Route path="admin/kyc/proof-of-funds" element={<KycProofOfFundsReviewQueue />} />
          <Route path="kyc/liveness-call" element={<KycLivenessCallSchedulePage />} />
          <Route path="admin/kyc/liveness-call" element={<KycLivenessCallVerifierPage />} />
          <Route path="admin/kyc/screening" element={<KycScreeningReviewQueuePage />} />
          <Route path="kyc/id-scanner" element={<KycIdScannerPage />} />
          <Route path="kyc/webhooks" element={<KycWebhookSettingsPage />} />
          <Route path="admin/kyc/id-scanner" element={<KycIdScannerReviewQueuePage />} />
          <Route path="admin/kyc/compliance" element={<KycComplianceReportsPage />} />
          <Route path="agents/workers" element={<WorkersPage />} />
          {showAgentSshQa && (
            <Route path="agents/qa-actions" element={<QaActionsPage />} />
          )}
          <Route path="agents/session" element={<AgentSessionPage />} />
          <Route path="agents/llm-keys" element={<LlmKeysPage />} />
          <Route path="agents/dashboard" element={<AgentDashboard />} />
          <Route path="agents/fleet" element={<FleetDashboard />} />
          <Route path="agents/prs" element={<AgentPrList />} />
          <Route path="agents/types/:typeId/coder" element={<CoderAgentConfigPage />} />
          <Route path="agents/types/:typeId/qa" element={<QaAgentConfigPage />} />
          <Route path="agents/types/:typeId/devops" element={<DevOpsAgentConfigPage />} />
          <Route path="agents/types/:typeId/architect" element={<ArchitectAgentConfigPage />} />
          <Route path="agents/docs" element={<DocCoveragePage />} />
          <Route path="agents/docs/templates" element={<DocTemplatesPage />} />
          <Route path="agents/pm/ideas" element={<FeatureIdeasPage />} />
          <Route path="agents/types/:typeId/pm" element={<PmAgentConfigPage />} />
          <Route path="agents/project-dashboard" element={<ProjectDashboardPage />} />
          <Route path="agents/stylist/rules" element={<StylistDesignRulesPage />} />
          <Route path="agents/stylist/reviews/:reviewId" element={<StylistReviewDetailPage />} />
          <Route path="agents/stylist" element={<StylistDesignOverviewPage />} />
          <Route path="agents/marketing" element={<MarketingContentDashboardPage />} />
          <Route path="agents/marketing/content/:contentId" element={<MarketingContentEditorPage />} />
          <Route path="agents/marketing/calendar" element={<MarketingContentCalendarPage />} />
          <Route path="agents/marketing/engagement" element={<MarketingEngagementDashboardPage />} />
          <Route path="agents/compliance" element={<ComplianceAgentConfigPage />} />
          <Route path="agents/security" element={<ComplianceAgentConfigPage />} />
          <Route path="agents/security/findings" element={<ComplianceAgentConfigPage />} />
          <Route path="agents/security/audits" element={<ComplianceAgentConfigPage />} />
          <Route path="agents/costs" element={<CostOverviewPage />} />
          <Route path="agents/costs/breakdown" element={<CostBreakdownPage />} />
          <Route path="agents/costs/budgets" element={<BudgetManagerPage />} />
          <Route path="agents/costs/alerts" element={<CostAlertsPage />} />
          <Route path="ideas/submit" element={<IdeaSubmissionPage />} />
          <Route path="licenses" element={<LicensesPage />} />
          <Route path="licenses/compliance" element={<LicenseCompliancePage />} />
          <Route
            path="admin/license-compliance"
            element={<AdminLicenseCompliancePage />}
          />
          <Route path="admin/license-review" element={<AdminReviewPage />} />
          <Route path="*" element={<ErrorPage status={404} />} />
        </Route>

        {/* Catch-all 404 for unmatched routes */}
        <Route path="*" element={<ErrorPage status={404} />} />
      </Routes>
    </Suspense>
    </>
  );
}
