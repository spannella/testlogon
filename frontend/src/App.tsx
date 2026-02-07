import { Routes, Route } from "react-router-dom";

import Login from "@/pages/Login";
import PasswordRecovery from "@/pages/PasswordRecovery";
import ProtectedRoute from "@/components/ProtectedRoute";
import AppShell from "@/components/layout/AppShell";
import Dashboard from "@/pages/Dashboard";
import MessagesPage from "@/pages/messages/MessagesPage";
import FilesPage from "@/pages/files/FilesPage";
import BillingPage from "@/pages/billing/BillingPage";
import CalendarPage from "@/pages/calendar/CalendarPage";
import CatalogPage from "@/pages/shop/CatalogPage";
import ProductDetail from "@/pages/shop/ProductDetail";
import CartPage from "@/pages/shop/CartPage";
import Checkout from "@/pages/shop/Checkout";
import FeedPage from "@/pages/feed/FeedPage";
import AlertsPage from "@/pages/alerts/AlertsPage";
import SecurityPage from "@/pages/security/SecurityPage";
import ProfilePage from "@/pages/settings/ProfilePage";
import SettingsPage from "@/pages/settings/SettingsPage";

export default function App() {
  return (
    <Routes>
      {/* Public routes (no shell) */}
      <Route path="/login" element={<Login />} />
      <Route path="/password-recovery" element={<PasswordRecovery />} />

      {/* Protected routes inside AppShell layout */}
      <Route element={<ProtectedRoute><AppShell /></ProtectedRoute>}>
        <Route index element={<Dashboard />} />
        <Route path="messages" element={<MessagesPage />} />
        <Route path="files" element={<FilesPage />} />
        <Route path="billing" element={<BillingPage />} />
        <Route path="calendar" element={<CalendarPage />} />
        <Route path="shop" element={<CatalogPage />} />
        <Route path="shop/:categoryId/:itemId" element={<ProductDetail />} />
        <Route path="cart" element={<CartPage />} />
        <Route path="cart/checkout" element={<Checkout />} />
        <Route path="feed" element={<FeedPage />} />
        <Route path="alerts" element={<AlertsPage />} />
        <Route path="security" element={<SecurityPage />} />
        <Route path="profile" element={<ProfilePage />} />
        <Route path="settings" element={<SettingsPage />} />
      </Route>
    </Routes>
  );
}
