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
const PublicEventPage = lazy(() => import("@/pages/calendar/PublicEventPage"));
const ContactsPage = lazy(() => import("@/pages/contacts/ContactsPage"));
const HelpdeskPage = lazy(() => import("@/pages/helpdesk/HelpdeskPage"));
const TicketsPage = lazy(() => import("@/pages/tickets/TicketsPage"));
const TicketSpacesPage = lazy(() => import("@/pages/tickets/TicketSpacesPage"));
const TicketSpaceDetailPage = lazy(() => import("@/pages/tickets/TicketSpaceDetailPage"));
const RemoteDesktopPage = lazy(() => import("@/pages/remote/RemoteDesktopPage"));
const SigningPage = lazy(() => import("@/pages/signing/SigningPage"));
const QuestionnaireBuilderPage = lazy(() => import("@/pages/questionnaires/QuestionnaireBuilderPage"));
const QuestionnaireRespondentPage = lazy(() => import("@/pages/questionnaires/QuestionnaireRespondentPage"));
const PublicUserProfilePage = lazy(() => import("@/pages/profile/PublicUserProfilePage"));
const VideosPage = lazy(() => import("@/pages/videos/VideosPage"));
const DiscoverPage = lazy(() => import("@/pages/discover/DiscoverPage"));
const TagPage = lazy(() => import("@/pages/discover/TagPage"));
const SearchPage = lazy(() => import("@/pages/search/SearchPage"));
const VideoPlayerPage = lazy(() => import("@/pages/videos/VideoPlayerPage"));
const BroadcastPage = lazy(() => import("@/pages/broadcast/BroadcastPage"));
const LivePlayer = lazy(() => import("@/pages/broadcast/LivePlayer"));
const ClipGalleryPage = lazy(() => import("@/pages/clips/ClipGalleryPage"));
const ClipPlayerPage = lazy(() => import("@/pages/clips/ClipPlayerPage"));
const DmcaClaimForm = lazy(() => import("@/pages/dmca/DmcaClaimForm"));
const DmcaDashboardPage = lazy(() => import("@/pages/admin/DmcaDashboardPage"));
const RateLimitDashboard = lazy(() => import("@/pages/admin/RateLimitDashboard"));
const GalleryPage = lazy(() => import("@/pages/gallery/GalleryPage"));
const GalleryVideoDetailPage = lazy(() => import("@/pages/gallery/VideoDetailPage"));
const AnalyticsPage = lazy(() => import("@/pages/analytics/AnalyticsPage"));
const ContentDetailPage = lazy(() => import("@/pages/analytics/ContentDetailPage"));
const PayoutDashboard = lazy(() => import("@/pages/payouts/PayoutDashboard"));
const PrivacyPage = lazy(() => import("@/pages/settings/PrivacyPage"));
const BlockedUsersPage = lazy(() => import("@/pages/settings/BlockedUsersPage"));
const WebhooksPage = lazy(() => import("@/pages/settings/WebhooksPage"));
const GeoRulesPage = lazy(() => import("@/pages/settings/GeoRulesPage"));
const ReferralDashboard = lazy(() => import("@/pages/referrals/ReferralDashboard"));
const PromoCodesPage = lazy(() => import("@/pages/promo/PromoCodesPage"));
const SchedulerPage = lazy(() => import("@/pages/scheduler/SchedulerPage"));
const RefundRequestsPage = lazy(() => import("@/pages/billing/RefundRequestsPage"));
const AdminRefundQueuePage = lazy(() => import("@/pages/admin/AdminRefundQueuePage"));
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
          <Route path="calendar" element={<CalendarPage />} />
          <Route path="content-calendar" element={<ContentCalendarPage />} />
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
          {showBroadcastNavigation && <Route path="broadcast" element={<BroadcastPage />} />}
          <Route path="clips" element={<ClipGalleryPage />} />
          <Route path="clips/:clipId" element={<ClipPlayerPage />} />
          {showVncRemoteDesktop && <Route path="remote-desktop" element={<RemoteDesktopPage />} />}
          <Route path="security" element={<SecurityPage />} />
          <Route path="profile" element={<ProfilePage />} />
          <Route path="settings" element={<SettingsPage />} />
          <Route path="settings/privacy" element={<PrivacyPage />} />
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
          <Route path="root/roles" element={<RootRoleManagementPage />} />
          <Route path="admin/moderation" element={<ModerationBoardPage />} />
          <Route path="admin/payment-incidents" element={<PaymentIncidentQueuePage />} />
          <Route path="admin/video-review" element={<VideoReviewQueuePage />} />
          <Route path="dmca/submit" element={<DmcaClaimForm />} />
          <Route path="admin/dmca" element={<DmcaDashboardPage />} />
          <Route path="admin/refunds" element={<AdminRefundQueuePage />} />
          <Route path="admin/rate-limits" element={<RateLimitDashboard />} />
          <Route path="admin/audit-exports" element={<AuditExportPage />} />
          <Route path="admin/tenants" element={<TenantAdmin />} />
          <Route path="admin/sso" element={<SsoProvidersPage />} />
          <Route path="licenses/revenue" element={<LicenseRevenuePage />} />
          <Route path="admin/risk" element={<RiskDashboardPage />} />
          <Route path="licenses/requests" element={<LicenseRequestsPage />} />
          <Route path="*" element={<ErrorPage status={404} />} />
        </Route>

        {/* Catch-all 404 for unmatched routes */}
        <Route path="*" element={<ErrorPage status={404} />} />
      </Routes>
    </Suspense>
    </>
  );
}
