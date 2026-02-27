import { lazy, Suspense } from "react";
import { Routes, Route } from "react-router-dom";
import { Loader2 } from "lucide-react";

import ProtectedRoute from "@/components/ProtectedRoute";
import AppShell from "@/components/layout/AppShell";
import { ErrorPage } from "@/components/shared/ErrorPage";

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
const AlertsPage = lazy(() => import("@/pages/alerts/AlertsPage"));
const SecurityPage = lazy(() => import("@/pages/security/SecurityPage"));
const ProfilePage = lazy(() => import("@/pages/settings/ProfilePage"));
const SettingsPage = lazy(() => import("@/pages/settings/SettingsPage"));
const PurchasesPage = lazy(() => import("@/pages/purchases/PurchasesPage"));
const SubscriptionsPage = lazy(() => import("@/pages/subscriptions/SubscriptionsPage"));
const RootRoleManagementPage = lazy(() => import("@/pages/admin/RootRoleManagementPage"));
const PublicEventPage = lazy(() => import("@/pages/calendar/PublicEventPage"));
const ContactsPage = lazy(() => import("@/pages/contacts/ContactsPage"));

function PageSpinner() {
  return (
    <div className="flex h-full items-center justify-center py-32">
      <Loader2 className="h-8 w-8 animate-spin text-muted-foreground" />
    </div>
  );
}

export default function App() {
  return (
    <Suspense fallback={<PageSpinner />}>
      <Routes>
        {/* Public routes (no shell) */}
        <Route path="/login" element={<Login />} />
        <Route path="/register" element={<Register />} />
        <Route path="/password-recovery" element={<PasswordRecovery />} />
        <Route path="/magic-link-verify" element={<MagicLinkVerify />} />
        <Route path="/event/:calendarId/:eventId" element={<PublicEventPage />} />

        {/* Protected routes inside AppShell layout */}
        <Route element={<ProtectedRoute><AppShell /></ProtectedRoute>}>
          <Route index element={<Dashboard />} />
          <Route path="messages" element={<MessagesPage />} />
          <Route path="contacts" element={<ContactsPage />} />
          <Route path="files" element={<FilesPage />} />
          <Route path="projects" element={<ProjectsPage />} />
          <Route path="projects/:projectId" element={<ProjectDetailPage />} />
          <Route path="billing" element={<BillingPage />} />
          <Route path="calendar" element={<CalendarPage />} />
          <Route path="shop" element={<CatalogPage />} />
          <Route path="shop/:categoryId/:itemId" element={<ProductDetail />} />
          <Route path="cart" element={<CartPage />} />
          <Route path="cart/checkout" element={<Checkout />} />
          <Route path="feed" element={<FeedPage />} />
          <Route path="posts/:postId" element={<PostDetailPage />} />
          <Route path="alerts" element={<AlertsPage />} />
          <Route path="security" element={<SecurityPage />} />
          <Route path="profile" element={<ProfilePage />} />
          <Route path="settings" element={<SettingsPage />} />
          <Route path="purchases" element={<PurchasesPage />} />
          <Route path="purchases/:txnId" element={<PurchasesPage />} />
          <Route path="subscriptions" element={<SubscriptionsPage />} />
          <Route path="root/roles" element={<RootRoleManagementPage />} />
          <Route path="*" element={<ErrorPage status={404} />} />
        </Route>

        {/* Catch-all 404 for unmatched routes */}
        <Route path="*" element={<ErrorPage status={404} />} />
      </Routes>
    </Suspense>
  );
}
