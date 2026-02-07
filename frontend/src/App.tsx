import { Routes, Route } from "react-router-dom";

import Login from "@/pages/Login";
import PasswordRecovery from "@/pages/PasswordRecovery";
import ProtectedRoute from "@/components/ProtectedRoute";
import Dashboard from "@/pages/Dashboard";
import MessagesPage from "@/pages/messages/MessagesPage";
import FilesPage from "@/pages/files/FilesPage";
import BillingPage from "@/pages/billing/BillingPage";
import CalendarPage from "@/pages/calendar/CalendarPage";
import CatalogPage from "@/pages/shop/CatalogPage";
import CartPage from "@/pages/shop/CartPage";
import FeedPage from "@/pages/feed/FeedPage";
import AlertsPage from "@/pages/alerts/AlertsPage";
import SecurityPage from "@/pages/security/SecurityPage";
import ProfilePage from "@/pages/settings/ProfilePage";
import SettingsPage from "@/pages/settings/SettingsPage";

export default function App() {
  return (
    <Routes>
      {/* Public routes */}
      <Route path="/login" element={<Login />} />
      <Route path="/password-recovery" element={<PasswordRecovery />} />

      {/* Protected app routes (will be wrapped in AppShell layout in Step 5) */}
      <Route path="/" element={<ProtectedRoute><Dashboard /></ProtectedRoute>} />
      <Route path="/messages" element={<ProtectedRoute><MessagesPage /></ProtectedRoute>} />
      <Route path="/files" element={<ProtectedRoute><FilesPage /></ProtectedRoute>} />
      <Route path="/billing" element={<ProtectedRoute><BillingPage /></ProtectedRoute>} />
      <Route path="/calendar" element={<ProtectedRoute><CalendarPage /></ProtectedRoute>} />
      <Route path="/shop" element={<ProtectedRoute><CatalogPage /></ProtectedRoute>} />
      <Route path="/cart" element={<ProtectedRoute><CartPage /></ProtectedRoute>} />
      <Route path="/feed" element={<ProtectedRoute><FeedPage /></ProtectedRoute>} />
      <Route path="/alerts" element={<ProtectedRoute><AlertsPage /></ProtectedRoute>} />
      <Route path="/security" element={<ProtectedRoute><SecurityPage /></ProtectedRoute>} />
      <Route path="/profile" element={<ProtectedRoute><ProfilePage /></ProtectedRoute>} />
      <Route path="/settings" element={<ProtectedRoute><SettingsPage /></ProtectedRoute>} />
    </Routes>
  );
}
