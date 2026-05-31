import { lazy, Suspense } from "react";
import { Routes, Route } from "react-router-dom";
import { Helmet } from "react-helmet-async";
import { Loader2 } from "lucide-react";

import ProtectedRoute from "@/components/ProtectedRoute";
import AppShell from "@/components/layout/AppShell";
import { ErrorPage } from "@/components/shared/ErrorPage";
import { isBroadcastNavigationEnabled, isCanonicalProfileNavigationEnabled, isVncRemoteDesktopEnabled } from "@/lib/featureFlags";

// ─── Lazy-loaded pages (code-split per route) ───────────────────
const Login = lazy(() => import("@/pages/Login"));
const Register = lazy(() => import("@/pages/Register"));
const PasswordRecovery = lazy(() => import("@/pages/PasswordRecovery"));
const MagicLinkVerify = lazy(() => import("@/pages/MagicLinkVerify"));
const Dashboard = lazy(() => import("@/pages/Dashboard"));
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
const ProjectsPage = lazy(() => import("@/pages/projects/ProjectsPage"));
const ProjectDetailPage = lazy(() => import("@/pages/projects/ProjectDetailPage"));
const BillingPage = lazy(() => import("@/pages/billing/BillingPage"));
const CalendarPage = lazy(() => import("@/pages/calendar/CalendarPage"));
const CatalogPage = lazy(() => import("@/pages/shop/CatalogPage"));
const ProductDetail = lazy(() => import("@/pages/shop/ProductDetail"));
const CartPage = lazy(() => import("@/pages/shop/CartPage"));
const Checkout = lazy(() => import("@/pages/shop/Checkout"));
const FeedPage = lazy(() => import("@/pages/feed/FeedPage"));
const PostDetailPage = lazy(() => import("@/pages/feed/PostDetailPage"));
const DelegateFeedPage = lazy(() => import("@/pages/feed/DelegateFeedPage"));
const DelegationApiKeysPage = lazy(
  () => import("@/pages/delegates/DelegationApiKeysPage"),
);
const AlertsPage = lazy(() => import("@/pages/alerts/AlertsPage"));
const ActivityFeedPage = lazy(() => import("@/pages/activity/ActivityFeedPage"));
const NotificationsPage = lazy(() => import("@/pages/notifications/NotificationsPage"));
const SecurityPage = lazy(() => import("@/pages/security/SecurityPage"));
const ProfilePage = lazy(() => import("@/pages/settings/ProfilePage"));
const SettingsPage = lazy(() => import("@/pages/settings/SettingsPage"));
const PurchasesPage = lazy(() => import("@/pages/purchases/PurchasesPage"));
const SubscriptionsPage = lazy(() => import("@/pages/subscriptions/SubscriptionsPage"));
const TierManager = lazy(() => import("@/pages/subscriptions/TierManager"));
const RootRoleManagementPage = lazy(() => import("@/pages/admin/RootRoleManagementPage"));
const ModerationBoardPage = lazy(() => import("@/pages/admin/ModerationBoardPage"));
const PaymentIncidentQueuePage = lazy(() => import("@/pages/admin/PaymentIncidentQueuePage"));
const VideoReviewQueuePage = lazy(() => import("@/pages/admin/VideoReviewQueuePage"));
const VideoReviewQueueModerationPage = lazy(() => import("@/pages/admin/VideoReviewQueueModerationPage"));
const PublicEventPage = lazy(() => import("@/pages/calendar/PublicEventPage"));
const ContactsPage = lazy(() => import("@/pages/contacts/ContactsPage"));
const HelpdeskPage = lazy(() => import("@/pages/helpdesk/HelpdeskPage"));
const TicketsPage = lazy(() => import("@/pages/tickets/TicketsPage"));
const TicketSpacesPage = lazy(() => import("@/pages/tickets/TicketSpacesPage"));
const TicketSpaceDetailPage = lazy(() => import("@/pages/tickets/TicketSpaceDetailPage"));
const RemoteDesktopPage = lazy(() => import("@/pages/remote/RemoteDesktopPage"));
const K8sLauncherPage = lazy(() => import("@/pages/remote/K8sLauncherPage"));
const ComputeSpendingPage = lazy(() => import("@/pages/remote/ComputeSpendingPage"));
const SecurityGroupsPage = lazy(() => import("@/pages/remote/SecurityGroupsPage"));
const SshRecordingsPage = lazy(() => import("@/pages/remote/SshRecordingsPage"));
const InstanceMonitoringPage = lazy(() => import("@/pages/remote/InstanceMonitoringPage"));
const SshBastionPage = lazy(() => import("@/pages/remote/SshBastionPage"));
const ConnectionProfilesPage = lazy(() => import("@/pages/remote/ConnectionProfilesPage"));
const SigningPage = lazy(() => import("@/pages/signing/SigningPage"));
const QuestionnaireBuilderPage = lazy(() => import("@/pages/questionnaires/QuestionnaireBuilderPage"));
const QuestionnaireRespondentPage = lazy(() => import("@/pages/questionnaires/QuestionnaireRespondentPage"));
const PublicUserProfilePage = lazy(() => import("@/pages/profile/PublicUserProfilePage"));
const VideosPage = lazy(() => import("@/pages/videos/VideosPage"));
const DiscoverPage = lazy(() => import("@/pages/discover/DiscoverPage"));
const TagPage = lazy(() => import("@/pages/discover/TagPage"));
const SearchPage = lazy(() => import("@/pages/search/SearchPage"));
const VideoPlayerPage = lazy(() => import("@/pages/videos/VideoPlayerPage"));
const VodRentalsPage = lazy(() => import("@/pages/vod/VodRentalsPage"));
const BroadcastPage = lazy(() => import("@/pages/broadcast/BroadcastPage"));
const BroadcastSchedulePage = lazy(() => import("@/pages/broadcast/BroadcastSchedulePage"));
const LivePlayer = lazy(() => import("@/pages/broadcast/LivePlayer"));
const LiveQaPage = lazy(() => import("@/pages/broadcast/LiveQaPage"));
const ClipGalleryPage = lazy(() => import("@/pages/clips/ClipGalleryPage"));
const ClipPlayerPage = lazy(() => import("@/pages/clips/ClipPlayerPage"));
const DmcaClaimForm = lazy(() => import("@/pages/dmca/DmcaClaimForm"));
const DmcaDashboardPage = lazy(() => import("@/pages/admin/DmcaDashboardPage"));
const RateLimitDashboard = lazy(() => import("@/pages/admin/RateLimitDashboard"));
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
const GeoRulesPage = lazy(() => import("@/pages/settings/GeoRulesPage"));
const ReferralDashboard = lazy(() => import("@/pages/referrals/ReferralDashboard"));
const PromoCodesPage = lazy(() => import("@/pages/promo/PromoCodesPage"));
const SchedulerPage = lazy(() => import("@/pages/scheduler/SchedulerPage"));
const RefundRequestsPage = lazy(() => import("@/pages/billing/RefundRequestsPage"));
const InvoicesPage = lazy(() => import("@/pages/billing/InvoicesPage"));
const TaxDocumentsPage = lazy(() => import("@/pages/billing/TaxDocumentsPage"));
const AdminRefundQueuePage = lazy(() => import("@/pages/admin/AdminRefundQueuePage"));
const BulkPayoutConsole = lazy(() => import("@/pages/admin/BulkPayoutConsole"));
const DisputesPage = lazy(() => import("@/pages/billing/DisputesPage"));
const AdminDisputeQueuePage = lazy(() => import("@/pages/admin/AdminDisputeQueuePage"));
const SavedPage = lazy(() => import("@/pages/saved/SavedPage"));
const AffiliateDashboard = lazy(() => import("@/pages/affiliates/AffiliateDashboard"));
const CollaborationsPage = lazy(() => import("@/pages/collaborations/CollaborationsPage"));
const FanClubPage = lazy(() => import("@/pages/fan-club/FanClubPage"));
const AchievementsPage = lazy(() => import("@/pages/achievements/AchievementsPage"));
const AuditExportPage = lazy(() => import("@/pages/admin/AuditExportPage"));
const TenantAdmin = lazy(() => import("@/pages/admin/TenantAdmin"));
const SsoProvidersPage = lazy(() => import("@/pages/admin/SsoProvidersPage"));
const LicenseRevenuePage = lazy(() => import("@/pages/licenses/LicenseRevenuePage"));
const RiskDashboardPage = lazy(() => import("@/pages/admin/RiskDashboardPage"));
const SubscriptionTierManagerPage = lazy(() => import("@/pages/admin/SubscriptionTierManagerPage"));
const CreatorDashboard = lazy(() => import("@/pages/dashboard/CreatorDashboard"));
const OrgsPage = lazy(() => import("@/pages/orgs/OrgsPage"));
const OrgDashboard = lazy(() => import("@/pages/orgs/OrgDashboard"));
const GroupsListPage = lazy(() => import("@/pages/groups/GroupsListPage"));
const GroupPage = lazy(() => import("@/pages/groups/GroupPage"));
const WebhookDashboard = lazy(() => import("@/pages/webhooks/WebhookDashboard"));
const WebhookEndpointDetail = lazy(() => import("@/pages/webhooks/WebhookEndpointDetail"));
const PartyListPage = lazy(() => import("@/pages/watch-parties/PartyListPage"));
const WatchPartyPage = lazy(() => import("@/pages/watch-parties/WatchPartyPage"));
const ContentCalendarPage = lazy(() => import("@/pages/content-calendar/ContentCalendarPage"));
const CallHistoryPage = lazy(() => import("@/pages/calls/CallHistoryPage"));
const LicenseRequestsPage = lazy(() => import("@/pages/licenses/LicenseRequestsPage"));
const KycTierProgress = lazy(() => import("@/pages/kyc/KycTierProgress"));
const KycDocumentVerificationPage = lazy(() => import("@/pages/kyc/KycDocumentVerificationPage"));
const KycDocumentReviewQueuePage = lazy(() => import("@/pages/kyc/KycDocumentReviewQueuePage"));
const KycResidencyVerificationPage = lazy(() => import("@/pages/kyc/KycResidencyVerificationPage"));
const KycResidencyReviewQueuePage = lazy(() => import("@/pages/kyc/KycResidencyReviewQueuePage"));
const KycProofOfFunds = lazy(() => import("@/pages/kyc/KycProofOfFunds"));
const WorkersPage = lazy(() => import("@/pages/agents/WorkersPage"));
const AdBillingPage = lazy(() => import("@/pages/ads/AdBillingPage"));
const GroupTreasuryPage = lazy(() => import("@/pages/groups/GroupTreasuryPage"));
const GroupFundraisingPage = lazy(() => import("@/pages/groups/GroupFundraisingPage"));
const GroupAdsPage = lazy(() => import("@/pages/groups/GroupAdsPage"));
const PublicDonationPage = lazy(() => import("@/pages/groups/PublicDonationPage"));
const AgentDashboard = lazy(() => import("@/pages/agents/AgentDashboard"));
const AdAnalyticsDashboard = lazy(() => import("@/pages/ads/AdAnalyticsDashboard"));
const AdSchedulePage = lazy(() => import("@/pages/ads/AdSchedulePage"));
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

function PageSpinner() {
  return (
    <div className="flex h-full items-center justify-center py-32">
      <Loader2 className="h-8 w-8 animate-spin text-muted-foreground" />
    </div>
  );
}

export default function App() {
  const showVncRemoteDesktop = isVncRemoteDesktopEnabled();
  const showBroadcastNavigation = isBroadcastNavigationEnabled();
  const showCanonicalProfileRoute = isCanonicalProfileNavigationEnabled();

  return (
    <>
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
        <Route path="/donate/:fundraiserId" element={<PublicDonationPage />} />
        <Route path="/questionnaires/published/:publishedSlug/respond" element={<QuestionnaireRespondentPage />} />
        <Route path="live/:sessionId" element={<LivePlayer />} />
        <Route path="party/:inviteCode" element={<PartyListPage />} />

        {/* Protected routes inside AppShell layout */}
        <Route element={<ProtectedRoute><AppShell /></ProtectedRoute>}>
          <Route index element={<Dashboard />} />
          <Route path="messages" element={<MessagesPage />} />
          <Route path="calls/history" element={<CallHistoryPage />} />
          <Route path="contacts" element={<ContactsPage />} />
          <Route path="helpdesk" element={<HelpdeskPage />} />
          <Route path="files" element={<FilesPage />} />
          <Route path="signing" element={<SigningPage />} />
          <Route path="projects" element={<ProjectsPage />} />
          <Route path="projects/:projectId" element={<ProjectDetailPage />} />
          <Route path="questionnaires/:questionnaireId/builder" element={<QuestionnaireBuilderPage />} />
          <Route path="billing" element={<BillingPage />} />
          <Route path="billing/refunds" element={<RefundRequestsPage />} />
          <Route path="billing/invoices" element={<InvoicesPage />} />
          <Route path="billing/tax-documents" element={<TaxDocumentsPage />} />
          <Route path="billing/disputes" element={<DisputesPage />} />
          <Route path="ads/billing" element={<AdBillingPage />} />
          <Route path="ads/analytics" element={<AdAnalyticsDashboard />} />
          <Route path="ads/scheduling" element={<AdSchedulePage />} />
          <Route path="calendar" element={<CalendarPage />} />
          <Route path="content-calendar" element={<ContentCalendarPage />} />
          <Route path="agents/memory/:workerId" element={<AgentMemoryPage />} />
          <Route path="agents/feedback" element={<AgentFeedbackPage />} />
          <Route path="scheduler" element={<SchedulerPage />} />
          <Route path="shop" element={<CatalogPage />} />
          <Route path="shop/:categoryId/:itemId" element={<ProductDetail />} />
          <Route path="cart" element={<CartPage />} />
          <Route path="cart/checkout" element={<Checkout />} />
          <Route path="feed" element={<FeedPage />} />
          <Route path="discover" element={<DiscoverPage />} />
          <Route path="discover/tags/:tag" element={<TagPage />} />
          <Route path="search" element={<SearchPage />} />
          <Route path="saved" element={<SavedPage />} />
          <Route path="posts/:postId" element={<PostDetailPage />} />
          <Route path="feed/delegate/:creatorId" element={<DelegateFeedPage />} />
          <Route path="delegation-api" element={<DelegationApiKeysPage />} />
          <Route path="alerts" element={<AlertsPage />} />
          <Route path="activity" element={<ActivityFeedPage />} />
          <Route path="notifications" element={<NotificationsPage />} />
          <Route path="tickets" element={<TicketsPage />} />
          <Route path="tickets/spaces" element={<TicketSpacesPage />} />
          <Route path="tickets/spaces/:spaceId" element={<TicketSpaceDetailPage />} />
          <Route path="watch-parties" element={<PartyListPage />} />
          <Route path="watch-parties/:partyId" element={<WatchPartyPage />} />
          <Route path="gallery" element={<GalleryPage />} />
          <Route path="gallery/:videoId" element={<GalleryVideoDetailPage />} />
          <Route path="videos" element={<VideosPage />} />
          <Route path="videos/:videoId" element={<VideoPlayerPage />} />
          <Route path="vod/rentals" element={<VodRentalsPage />} />
          {showBroadcastNavigation && <Route path="broadcast" element={<BroadcastPage />} />}
          {showBroadcastNavigation && <Route path="broadcast/schedule" element={<BroadcastSchedulePage />} />}
          {showBroadcastNavigation && <Route path="broadcast/:sessionId/live-qa" element={<LiveQaPage />} />}
          <Route path="clips" element={<ClipGalleryPage />} />
          <Route path="clips/:clipId" element={<ClipPlayerPage />} />
          {showVncRemoteDesktop && <Route path="remote-desktop" element={<RemoteDesktopPage />} />}
          <Route path="remote/k8s" element={<K8sLauncherPage />} />
          <Route path="remote/billing" element={<ComputeSpendingPage />} />
          <Route path="remote/security-groups" element={<SecurityGroupsPage />} />
          <Route path="remote/recordings" element={<SshRecordingsPage />} />
          <Route path="remote/bastion" element={<SshBastionPage />} />
          <Route path="remote/connection-profiles" element={<ConnectionProfilesPage />} />
          <Route path="remote/instances/:instanceId/monitoring" element={<InstanceMonitoringPage />} />
          <Route path="security" element={<SecurityPage />} />
          <Route path="profile" element={<ProfilePage />} />
          <Route path="settings" element={<SettingsPage />} />
          <Route path="settings/privacy" element={<PrivacyPage />} />
          <Route path="settings/account-deletion" element={<AccountDeletionPage />} />
          <Route path="settings/blocked" element={<BlockedUsersPage />} />
          <Route path="settings/webhooks" element={<WebhooksPage />} />
          <Route path="settings/geo" element={<GeoRulesPage />} />
          <Route path="webhooks" element={<WebhookDashboard />} />
          <Route path="webhooks/:endpointId" element={<WebhookEndpointDetail />} />
          <Route path="purchases" element={<PurchasesPage />} />
          <Route path="purchases/:txnId" element={<PurchasesPage />} />
          <Route path="subscriptions" element={<SubscriptionsPage />} />
          <Route path="subscriptions/manage" element={<TierManager />} />
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
          <Route path="fan-club" element={<FanClubPage />} />
          <Route path="orgs" element={<OrgsPage />} />
          <Route path="orgs/:orgId" element={<OrgDashboard />} />
          <Route path="groups" element={<GroupsListPage />} />
          <Route path="groups/:groupId" element={<GroupPage />} />
          <Route path="groups/:groupId/treasury" element={<GroupTreasuryPage />} />
          <Route path="groups/:groupId/fundraising" element={<GroupFundraisingPage />} />
          <Route path="groups/:groupId/ads" element={<GroupAdsPage />} />
          <Route path="root/roles" element={<RootRoleManagementPage />} />
          <Route path="admin/moderation" element={<ModerationBoardPage />} />
          <Route path="admin/payment-incidents" element={<PaymentIncidentQueuePage />} />
          <Route path="admin/video-review" element={<VideoReviewQueuePage />} />
          <Route path="admin/video-review-queue" element={<VideoReviewQueueModerationPage />} />
          <Route path="dmca/submit" element={<DmcaClaimForm />} />
          <Route path="admin/dmca" element={<DmcaDashboardPage />} />
          <Route path="admin/refunds" element={<AdminRefundQueuePage />} />
          <Route path="admin/bulk-payouts" element={<BulkPayoutConsole />} />
          <Route path="admin/disputes" element={<AdminDisputeQueuePage />} />
          <Route path="admin/rate-limits" element={<RateLimitDashboard />} />
          <Route path="admin/communications" element={<EmailSmsDashboardPage />} />
          <Route path="admin/compute" element={<AdminComputeDashboard />} />
          <Route path="admin/jobs" element={<JobDashboardPage />} />
          <Route path="admin/financials" element={<FinancialDashboard />} />
          <Route path="admin/payment-health" element={<PaymentHealthDashboard />} />
          <Route path="admin/ads/fraud" element={<AdFraudDashboard />} />
          <Route path="admin/ad-platform" element={<AdPlatformDashboard />} />
          <Route path="admin/audit-exports" element={<AuditExportPage />} />
          <Route path="admin/tenants" element={<TenantAdmin />} />
          <Route path="admin/sso" element={<SsoProvidersPage />} />
          <Route path="licenses/revenue" element={<LicenseRevenuePage />} />
          <Route path="admin/risk" element={<RiskDashboardPage />} />
          <Route path="admin/subscription-tiers" element={<SubscriptionTierManagerPage />} />
          <Route path="licenses/requests" element={<LicenseRequestsPage />} />
          <Route path="kyc/tiers" element={<KycTierProgress />} />
          <Route path="kyc/documents" element={<KycDocumentVerificationPage />} />
          <Route path="admin/kyc/documents" element={<KycDocumentReviewQueuePage />} />
          <Route path="kyc/residency" element={<KycResidencyVerificationPage />} />
          <Route path="admin/kyc/residency" element={<KycResidencyReviewQueuePage />} />
          <Route path="kyc/proof-of-funds" element={<KycProofOfFunds />} />
          <Route path="agents/workers" element={<WorkersPage />} />
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
