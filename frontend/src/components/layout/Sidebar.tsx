import { NavLink, useLocation } from "react-router-dom";
import {
  LayoutDashboard,
  MessageSquare,
  Rss,
  Store,
  ShoppingCart,
  CreditCard,
  ClipboardList,
  Megaphone,
  Repeat,
  FolderOpen,
  FolderKanban,
  FilePen,
  FileCheck,
  CalendarDays,
  User,
  Shield,
  Settings,
  Bell,
  Gavel,
  LifeBuoy,
  Users,
  UsersRound,
  BookUser,
  Headphones,
  PanelLeftClose,
  PanelLeft,
  MonitorSmartphone,
  Radio,
  Video,
  Scale,
  Wrench,
  Compass,
  Bookmark,
  PlaySquare,
  BarChart3,
  ShieldCheck,
  Network,
  Share2,
  Tag,
  Webhook,
  Globe,
  CalendarClock,
  Ban,
  Wallet,
  Layers,
  Link2,
  Handshake,
  Trophy,
  Building2,
  Tv,
  Scissors,
  Activity,
  Phone,
  ShieldAlert,
  Server,
  Boxes,
  Container,
  LayoutTemplate,
  Bot,
  LayoutGrid,
  GitPullRequest,
  BookOpen,
  Lightbulb,
  Palette,
  Gauge,
  Receipt,
  Terminal,
  Package,
  Factory,
  Hammer,
  Truck,
  Briefcase,
  ReceiptText,
  Target,
  UserPlus,
  FileText,
  FileSignature,
  FileBarChart,
  History,
  Mail,
  Coins,
  GitBranch,
  FileBox,
  MapPin,
  ScrollText,
  Copy,
  Contact,
  GitMerge,
  FileSearch,
  Landmark,
  KeyRound,
  Eye,
  ArrowLeftRight,
  UserCheck,
} from "lucide-react";
import { useTranslation } from "react-i18next";
import { cn } from "@/lib/utils";
import { Button } from "@/components/ui/button";
import { Tooltip, TooltipContent, TooltipTrigger } from "@/components/ui/tooltip";
import { Separator } from "@/components/ui/separator";
import { useUiStore } from "@/stores/uiStore";
import { useAuthStore } from "@/stores/authStore";
import { canAccessGeneralAdminControls, canAccessModerationBoard, canAccessPaymentIncidentQueue, canSeeRootRoleManagement } from "@/lib/adminCapabilities";
import { useQuery } from "@tanstack/react-query";
import { getConversations } from "@/api/endpoints/messaging";
import { isBroadcastNavigationEnabled, isVncRemoteDesktopEnabled, isDevtoolsLogUiEnabled, isAgentSshQaEnabled, isInventoryReservationsEnabled } from "@/lib/featureFlags";

// ─── Navigation Config ──────────────────────────────────────────

interface NavItem {
  label: string;
  i18nKey?: string;
  path: string;
  icon: React.ReactNode;
  badge?: number;
}

interface NavGroup {
  title: string;
  i18nKey?: string;
  items: NavItem[];
}

const NAV_GROUPS: NavGroup[] = [
  {
    title: "Main",
    i18nKey: "nav.main",
    items: [
      { label: "Dashboard", i18nKey: "nav.dashboard", path: "/", icon: <LayoutDashboard className="h-5 w-5" /> },
      { label: "Messages", i18nKey: "nav.messages", path: "/messages", icon: <MessageSquare className="h-5 w-5" /> },
      { label: "Call History", i18nKey: "nav.callHistory", path: "/calls/history", icon: <Phone className="h-5 w-5" /> },
      { label: "Contacts", i18nKey: "nav.contacts", path: "/contacts", icon: <BookUser className="h-5 w-5" /> },
      { label: "Helpdesk", i18nKey: "nav.helpdesk", path: "/helpdesk", icon: <Headphones className="h-5 w-5" /> },
      { label: "Feed", i18nKey: "nav.feed", path: "/feed", icon: <Rss className="h-5 w-5" /> },
      { label: "Activity", i18nKey: "nav.activity", path: "/activity", icon: <Activity className="h-5 w-5" /> },
      { label: "Discover", i18nKey: "nav.discover", path: "/discover", icon: <Compass className="h-5 w-5" /> },
      { label: "Saved", i18nKey: "nav.saved", path: "/saved", icon: <Bookmark className="h-5 w-5" /> },
      { label: "Achievements", i18nKey: "nav.achievements", path: "/achievements", icon: <Trophy className="h-5 w-5" /> },
    ],
  },
  {
    title: "Commerce",
    i18nKey: "nav.commerce",
    items: [
      { label: "Shop", i18nKey: "nav.shop", path: "/shop", icon: <Store className="h-5 w-5" /> },
      { label: "Cart", i18nKey: "nav.cart", path: "/cart", icon: <ShoppingCart className="h-5 w-5" /> },
      { label: "Billing", i18nKey: "nav.billing", path: "/billing", icon: <CreditCard className="h-5 w-5" /> },
      { label: "Invoices", i18nKey: "nav.invoices", path: "/billing/invoices", icon: <Receipt className="h-5 w-5" /> },
      { label: "Tax Documents", i18nKey: "nav.taxDocuments", path: "/billing/tax-documents", icon: <Receipt className="h-5 w-5" /> },
      { label: "Tax Forms (1099)", i18nKey: "nav.taxForms1099", path: "/billing/tax-forms", icon: <Receipt className="h-5 w-5" /> },
      { label: "Orders", i18nKey: "nav.orders", path: "/purchases", icon: <ClipboardList className="h-5 w-5" /> },
      { label: "My Rentals", i18nKey: "nav.vodRentals", path: "/vod/rentals", icon: <Video className="h-5 w-5" /> },
      { label: "Subscriptions", i18nKey: "nav.subscriptions", path: "/subscriptions", icon: <Repeat className="h-5 w-5" /> },
      { label: "Tier Manager", i18nKey: "nav.tierManager", path: "/subscriptions/manage", icon: <Layers className="h-5 w-5" /> },
      { label: "Creator Dashboard", i18nKey: "nav.creatorDashboard", path: "/creator-dashboard", icon: <BarChart3 className="h-5 w-5" /> },
      { label: "Analytics", i18nKey: "nav.analytics", path: "/analytics", icon: <BarChart3 className="h-5 w-5" /> },
      { label: "Content Revenue", i18nKey: "nav.contentRevenue", path: "/analytics/content-revenue", icon: <BarChart3 className="h-5 w-5" /> },
      { label: "Payouts", i18nKey: "nav.payouts", path: "/payouts", icon: <Wallet className="h-5 w-5" /> },
      { label: "Referrals", i18nKey: "nav.referrals", path: "/referrals", icon: <Share2 className="h-5 w-5" /> },
      { label: "Promo Codes", i18nKey: "nav.promoCodes", path: "/promo", icon: <Tag className="h-5 w-5" /> },
      { label: "Affiliates", i18nKey: "nav.affiliates", path: "/affiliates", icon: <Link2 className="h-5 w-5" /> },
      { label: "Collaborations", i18nKey: "nav.collaborations", path: "/collaborations", icon: <Handshake className="h-5 w-5" /> },
      { label: "Fan Club", i18nKey: "nav.fanClub", path: "/fan-club", icon: <UsersRound className="h-5 w-5" /> },
      { label: "Groups", i18nKey: "nav.groups", path: "/groups", icon: <Users className="h-5 w-5" /> },
    ],
  },
  {
    title: "Productivity",
    i18nKey: "nav.productivity",
    items: [
      { label: "Files", i18nKey: "nav.files", path: "/files", icon: <FolderOpen className="h-5 w-5" /> },
      { label: "Share Links", i18nKey: "nav.shareLinks", path: "/files/share-links", icon: <Link2 className="h-5 w-5" /> },
      { label: "Projects", i18nKey: "nav.projects", path: "/projects", icon: <FolderKanban className="h-5 w-5" /> },
      { label: "Calendar", i18nKey: "nav.calendar", path: "/calendar", icon: <CalendarDays className="h-5 w-5" /> },
      { label: "Content Calendar", i18nKey: "nav.contentCalendar", path: "/content-calendar", icon: <CalendarClock className="h-5 w-5" /> },
      { label: "Scheduled", i18nKey: "nav.scheduled", path: "/scheduler", icon: <CalendarClock className="h-5 w-5" /> },
      { label: "Signing", i18nKey: "nav.signing", path: "/signing", icon: <FilePen className="h-5 w-5" /> },
      { label: "Signing Inbox", i18nKey: "nav.signingInbox", path: "/signing/inbox", icon: <FilePen className="h-5 w-5" /> },
      { label: "Licenses", i18nKey: "nav.licenses", path: "/licenses", icon: <FileCheck className="h-5 w-5" /> },
      { label: "License Compliance", i18nKey: "nav.licenseCompliance", path: "/licenses/compliance", icon: <FileCheck className="h-5 w-5" /> },
      { label: "Organizations", i18nKey: "nav.organizations", path: "/orgs", icon: <Building2 className="h-5 w-5" /> },
    ],
  },
  {
    title: "Media",
    i18nKey: "nav.media",
    items: [
      { label: "Gallery", i18nKey: "nav.gallery", path: "/gallery", icon: <PlaySquare className="h-5 w-5" /> },
      { label: "Videos", i18nKey: "nav.videos", path: "/videos", icon: <Video className="h-5 w-5" /> },
      { label: "Broadcast", i18nKey: "nav.broadcast", path: "/broadcast", icon: <Radio className="h-5 w-5" /> },
      { label: "Scheduled Broadcasts", i18nKey: "nav.broadcastSchedule", path: "/broadcast/schedule", icon: <CalendarClock className="h-5 w-5" /> },
      { label: "Clips", i18nKey: "nav.clips", path: "/clips", icon: <Scissors className="h-5 w-5" /> },
      { label: "Watch Parties", i18nKey: "nav.watchParties", path: "/watch-parties", icon: <Tv className="h-5 w-5" /> },
    ],
  },
  {
    title: "AI Agents",
    i18nKey: "nav.aiAgents",
    items: [
      { label: "Workers", i18nKey: "nav.workers", path: "/agents/workers", icon: <Bot className="h-5 w-5" /> },
      { label: "QA Actions", i18nKey: "nav.qaActions", path: "/agents/qa-actions", icon: <Terminal className="h-5 w-5" /> },
      { label: "Fleet Dashboard", i18nKey: "nav.fleetDashboard", path: "/agents/fleet", icon: <LayoutGrid className="h-5 w-5" /> },
      { label: "Project Dashboard", i18nKey: "nav.projectDashboard", path: "/agents/project-dashboard", icon: <LayoutDashboard className="h-5 w-5" /> },
      { label: "Agent PRs", i18nKey: "nav.agentPrs", path: "/agents/prs", icon: <GitPullRequest className="h-5 w-5" /> },
      { label: "Doc Coverage", i18nKey: "nav.docCoverage", path: "/agents/docs", icon: <BookOpen className="h-5 w-5" /> },
      { label: "Feature Ideas", i18nKey: "nav.featureIdeas", path: "/agents/pm/ideas", icon: <Lightbulb className="h-5 w-5" /> },
      { label: "Design Review", i18nKey: "nav.designReview", path: "/agents/stylist", icon: <Palette className="h-5 w-5" /> },
      { label: "Submit Idea", i18nKey: "nav.submitIdea", path: "/ideas/submit", icon: <ClipboardList className="h-5 w-5" /> },
      { label: "Marketing", i18nKey: "nav.marketing", path: "/agents/marketing", icon: <Megaphone className="h-5 w-5" /> },
      { label: "Security & Compliance", i18nKey: "nav.securityCompliance", path: "/agents/compliance", icon: <ShieldAlert className="h-5 w-5" /> },
      { label: "Cost Tracking", i18nKey: "nav.costTracking", path: "/agents/costs", icon: <Wallet className="h-5 w-5" /> },
    ],
  },
  {
    title: "Account",
    i18nKey: "nav.account",
    items: [
      { label: "Profile", i18nKey: "nav.profile", path: "/profile", icon: <User className="h-5 w-5" /> },
      { label: "Security", i18nKey: "nav.security", path: "/security", icon: <Shield className="h-5 w-5" /> },
      { label: "Verify Your Identity", i18nKey: "nav.kycVerify", path: "/kyc", icon: <ShieldCheck className="h-5 w-5" /> },
      { label: "Verification Status", i18nKey: "nav.kycStatus", path: "/kyc/status", icon: <ShieldCheck className="h-5 w-5" /> },
      { label: "KYC Verification", i18nKey: "nav.kycVerification", path: "/kyc/tiers", icon: <ShieldCheck className="h-5 w-5" /> },
      { label: "ID Documents", i18nKey: "nav.kycDocuments", path: "/kyc/documents", icon: <ShieldCheck className="h-5 w-5" /> },
      { label: "Proof of Residency", i18nKey: "nav.kycResidency", path: "/kyc/residency", icon: <ShieldCheck className="h-5 w-5" /> },
      { label: "Verification Call", i18nKey: "nav.kycLivenessCall", path: "/kyc/liveness-call", icon: <Video className="h-5 w-5" /> },
      { label: "Alerts", i18nKey: "nav.alerts", path: "/alerts", icon: <Bell className="h-5 w-5" /> },
      { label: "Notifications", i18nKey: "nav.notifications", path: "/notifications", icon: <Bell className="h-5 w-5" /> },
      { label: "My Appeals", i18nKey: "nav.myAppeals", path: "/appeals", icon: <Scale className="h-5 w-5" /> },
      { label: "Tickets", i18nKey: "nav.tickets", path: "/tickets", icon: <LifeBuoy className="h-5 w-5" /> },
      { label: "Boards", i18nKey: "nav.boards", path: "/tickets/boards", icon: <LifeBuoy className="h-5 w-5" /> },
      { label: "Remote Desktop", i18nKey: "nav.remoteDesktop", path: "/remote-desktop", icon: <MonitorSmartphone className="h-5 w-5" /> },
      { label: "SSH Terminal", i18nKey: "nav.browserSsh", path: "/remote/ssh", icon: <Terminal className="h-5 w-5" /> },
      { label: "Containers", i18nKey: "nav.containers", path: "/remote/k8s", icon: <Container className="h-5 w-5" /> },
      { label: "Security Groups", i18nKey: "nav.securityGroups", path: "/remote/security-groups", icon: <Shield className="h-5 w-5" /> },
      { label: "Templates", i18nKey: "nav.instanceTemplates", path: "/remote/templates", icon: <LayoutTemplate className="h-5 w-5" /> },
      { label: "Session Recordings", i18nKey: "nav.sshRecordings", path: "/remote/recordings", icon: <Video className="h-5 w-5" /> },
      { label: "Bastion Paths", i18nKey: "nav.sshBastion", path: "/remote/bastion", icon: <Network className="h-5 w-5" /> },
      { label: "Host Inventory", i18nKey: "nav.hostInventory", path: "/remote/hosts", icon: <Server className="h-5 w-5" /> },
      { label: "Settings", i18nKey: "nav.settings", path: "/settings", icon: <Settings className="h-5 w-5" /> },
      { label: "Theme", i18nKey: "nav.theme", path: "/settings/theme", icon: <Palette className="h-5 w-5" /> },
      { label: "Privacy", i18nKey: "nav.privacy", path: "/settings/privacy", icon: <ShieldCheck className="h-5 w-5" /> },
      { label: "Account Deletion", i18nKey: "nav.accountDeletion", path: "/settings/account-deletion", icon: <ShieldCheck className="h-5 w-5" /> },
      { label: "Blocked Users", i18nKey: "nav.blockedUsers", path: "/settings/blocked", icon: <Ban className="h-5 w-5" /> },
      { label: "Webhooks", i18nKey: "nav.webhooks", path: "/settings/webhooks", icon: <Webhook className="h-5 w-5" /> },
      { label: "Geo Rules", i18nKey: "nav.geoRules", path: "/settings/geo", icon: <Globe className="h-5 w-5" /> },
      { label: "Role Management", i18nKey: "nav.roleManagement", path: "/root/roles", icon: <UsersRound className="h-5 w-5" /> },
      { label: "Moderation Board", i18nKey: "nav.moderationBoard", path: "/admin/moderation", icon: <Scale className="h-5 w-5" /> },
      { label: "Payment Incidents", i18nKey: "nav.paymentIncidents", path: "/admin/payment-incidents", icon: <CreditCard className="h-5 w-5" /> },
      { label: "Video Review", i18nKey: "nav.videoReview", path: "/admin/video-review", icon: <Video className="h-5 w-5" /> },
      { label: "Video Review Queue", i18nKey: "nav.videoReviewQueue", path: "/admin/video-review-queue", icon: <Video className="h-5 w-5" /> },
      { label: "DMCA Claims", i18nKey: "nav.dmcaClaims", path: "/admin/dmca", icon: <Scale className="h-5 w-5" /> },
      { label: "Refund Queue", i18nKey: "nav.refundQueue", path: "/admin/refunds", icon: <CreditCard className="h-5 w-5" /> },
      { label: "Bulk Payouts", path: "/admin/bulk-payouts", icon: <Wallet className="h-5 w-5" /> },
      { label: "Dispute Queue", i18nKey: "nav.disputeQueue", path: "/admin/disputes", icon: <ShieldAlert className="h-5 w-5" /> },
      { label: "Appeal Queue", i18nKey: "nav.appealQueue", path: "/admin/appeals", icon: <Gavel className="h-5 w-5" /> },
      { label: "Fraud Detection", i18nKey: "nav.fraudDetection", path: "/admin/fraud", icon: <ShieldAlert className="h-5 w-5" /> },
      { label: "Risk Scoring", i18nKey: "nav.riskScoring", path: "/admin/risk", icon: <ShieldAlert className="h-5 w-5" /> },
      { label: "Security Dashboard", i18nKey: "nav.securityDashboard", path: "/admin/security", icon: <ShieldAlert className="h-5 w-5" /> },
      { label: "Legal Holds", i18nKey: "nav.legalHolds", path: "/admin/legal-holds", icon: <Gavel className="h-5 w-5" /> },
      { label: "Subscription Tiers", i18nKey: "nav.subscriptionTiers", path: "/admin/subscription-tiers", icon: <Layers className="h-5 w-5" /> },
      { label: "Compute", i18nKey: "nav.compute", path: "/admin/compute", icon: <Server className="h-5 w-5" /> },
      { label: "Inventory", i18nKey: "nav.inventory", path: "/admin/inventory", icon: <Boxes className="h-5 w-5" /> },
      { label: "Financials", i18nKey: "nav.financials", path: "/admin/financials", icon: <BarChart3 className="h-5 w-5" /> },
      { label: "Billing Config", path: "/admin/billing-config", icon: <CreditCard className="h-5 w-5" /> },
      { label: "1099 Batch", path: "/admin/tax-forms-1099", icon: <Receipt className="h-5 w-5" /> },
      { label: "Payment Health", i18nKey: "nav.paymentHealth", path: "/admin/payment-health", icon: <Activity className="h-5 w-5" /> },
      { label: "Communications", i18nKey: "nav.communications", path: "/admin/communications", icon: <MessageSquare className="h-5 w-5" /> },
      { label: "Rate Limits", i18nKey: "nav.rateLimits", path: "/admin/rate-limits", icon: <Gauge className="h-5 w-5" /> },
      { label: "Background Jobs", i18nKey: "nav.backgroundJobs", path: "/admin/jobs", icon: <Activity className="h-5 w-5" /> },
      { label: "Ad Fraud", i18nKey: "nav.adFraud", path: "/admin/ads/fraud", icon: <ShieldAlert className="h-5 w-5" /> },
      { label: "Ad Platform", path: "/admin/ad-platform", icon: <Megaphone className="h-5 w-5" /> },
    ],
  },
  {
    title: "Operations (OFBiz)",
    items: [
      { label: "Order Lifecycle", path: "/orders", icon: <Package className="h-5 w-5" /> },
      { label: "POS Terminal", path: "/ofbiz/pos", icon: <Store className="h-5 w-5" /> },
      { label: "POS Reports", path: "/ofbiz/pos/reports", icon: <BarChart3 className="h-5 w-5" /> },
      { label: "Catalog Depth", path: "/ofbiz/catalog-depth", icon: <Boxes className="h-5 w-5" /> },
      { label: "Purchasing", path: "/purchasing", icon: <ShoppingCart className="h-5 w-5" /> },
      { label: "BOMs", path: "/manufacturing/boms", icon: <Layers className="h-5 w-5" /> },
      { label: "Work Orders", path: "/manufacturing/work-orders", icon: <Factory className="h-5 w-5" /> },
      { label: "MRP", path: "/manufacturing/mrp", icon: <ClipboardList className="h-5 w-5" /> },
      { label: "Work Centers", path: "/manufacturing/work-centers", icon: <Hammer className="h-5 w-5" /> },
      { label: "Fixed Assets", path: "/ofbiz/fixed-assets", icon: <Boxes className="h-5 w-5" /> },
      { label: "Maintenance Queue", path: "/ofbiz/fixed-assets/maintenance", icon: <Wrench className="h-5 w-5" /> },
      { label: "Shipping", path: "/ofbiz/shipping", icon: <Truck className="h-5 w-5" /> },
      { label: "Marketing", path: "/ofbiz/marketing", icon: <Megaphone className="h-5 w-5" /> },
      { label: "HR & Payroll", path: "/ofbiz/hr", icon: <Briefcase className="h-5 w-5" /> },
      { label: "Facilities", path: "/ofbiz/facilities", icon: <Building2 className="h-5 w-5" /> },
      { label: "Fulfillment", path: "/ofbiz/fulfillment", icon: <Truck className="h-5 w-5" /> },
      { label: "ERP", path: "/erp", icon: <Boxes className="h-5 w-5" /> },
      { label: "Storefront", path: "/ofbiz/storefront", icon: <Store className="h-5 w-5" /> },
      { label: "Cart Pricing", path: "/ofbiz/cart-pricing", icon: <ReceiptText className="h-5 w-5" /> },
      { label: "Order Tracking", path: "/ofbiz/order-fulfillment", icon: <Truck className="h-5 w-5" /> },
    ],
  },
  {
    title: "CRM (SuiteCRM)",
    items: [
      { label: "Leads", path: "/crm/leads", icon: <UserPlus className="h-5 w-5" /> },
      { label: "Opportunities", path: "/crm/opportunities", icon: <Target className="h-5 w-5" /> },
      { label: "Cases", path: "/crm/cases", icon: <LifeBuoy className="h-5 w-5" /> },
      { label: "Quotes", path: "/crm/quotes", icon: <FileText className="h-5 w-5" /> },
      { label: "Contracts", path: "/crm/contracts", icon: <FileSignature className="h-5 w-5" /> },
      { label: "Activities", path: "/crm/activities", icon: <Activity className="h-5 w-5" /> },
      { label: "Activity Timeline", path: "/crm/timeline", icon: <History className="h-5 w-5" /> },
      { label: "CRM Reports", path: "/crm/reports", icon: <FileBarChart className="h-5 w-5" /> },
      { label: "CRM Dashboard", path: "/crm/dashboard", icon: <LayoutDashboard className="h-5 w-5" /> },
      { label: "Knowledge Base", path: "/crm/knowledge-base", icon: <BookOpen className="h-5 w-5" /> },
      { label: "Email Templates", path: "/crm/email/templates", icon: <FileText className="h-5 w-5" /> },
      { label: "Email Compose", path: "/crm/email/compose", icon: <Mail className="h-5 w-5" /> },
      { label: "Email Log", path: "/crm/email/log", icon: <History className="h-5 w-5" /> },
      { label: "CRM Invoices", path: "/crm/invoices", icon: <Receipt className="h-5 w-5" /> },
      { label: "Currency & Tax", path: "/crm/billing-settings", icon: <Coins className="h-5 w-5" /> },
      { label: "Workflows", path: "/crm/workflow", icon: <GitBranch className="h-5 w-5" /> },
      { label: "CRM Security", path: "/crm/security", icon: <Shield className="h-5 w-5" /> },
      { label: "CRM Studio", path: "/crm/studio", icon: <Wrench className="h-5 w-5" /> },
      { label: "CRM Projects", path: "/crm/projects", icon: <FolderKanban className="h-5 w-5" /> },
      { label: "Events", path: "/crm/events", icon: <CalendarDays className="h-5 w-5" /> },
      { label: "Surveys", path: "/crm/surveys", icon: <ClipboardList className="h-5 w-5" /> },
      { label: "CRM Documents", path: "/crm/documents", icon: <FileBox className="h-5 w-5" /> },
      { label: "CRM Maps", path: "/crm/maps", icon: <MapPin className="h-5 w-5" /> },
      { label: "SMS Compose", path: "/crm/sms", icon: <MessageSquare className="h-5 w-5" /> },
      { label: "Audit Log", path: "/crm/audit-log", icon: <ScrollText className="h-5 w-5" /> },
      { label: "Campaigns", path: "/crm/campaigns", icon: <Megaphone className="h-5 w-5" /> },
      { label: "Web Leads", path: "/crm/web-leads", icon: <Users className="h-5 w-5" /> },
      { label: "Lead Capture", path: "/crm/lead-capture", icon: <Target className="h-5 w-5" /> },
      { label: "Org Accounts", path: "/crm/org-accounts", icon: <Building2 className="h-5 w-5" /> },
      { label: "Reports-To Chain", path: "/crm/reports-to", icon: <Users className="h-5 w-5" /> },
      { label: "Duplicate Contacts", path: "/crm/party-dedup", icon: <Copy className="h-5 w-5" /> },
      { label: "vCard Import", path: "/crm/vcard-import", icon: <Contact className="h-5 w-5" /> },
    ],
  },
  {
    title: "ATS (OpenCATS)",
    items: [
      { label: "Job Orders", path: "/ats/jobs", icon: <Briefcase className="h-5 w-5" /> },
      { label: "Candidates", path: "/ats/candidates", icon: <Users className="h-5 w-5" /> },
      { label: "Pipeline", path: "/ats/pipeline", icon: <GitMerge className="h-5 w-5" /> },
      { label: "Job Board", path: "/ats/portal/jobs", icon: <Globe className="h-5 w-5" /> },
      { label: "Career Portal Config", path: "/ats/applications", icon: <Briefcase className="h-5 w-5" /> },
      { label: "Skill Registry", path: "/ats/skills", icon: <Tag className="h-5 w-5" /> },
      { label: "Resume & Skill Search", path: "/ats/search", icon: <FileSearch className="h-5 w-5" /> },
      { label: "ATS Integration", path: "/ats/integration", icon: <GitMerge className="h-5 w-5" /> },
    ],
  },
  {
    title: "Banking (OBP)",
    items: [
      { label: "Bank Accounts", path: "/bank/accounts", icon: <Landmark className="h-5 w-5" /> },
      { label: "Transfers", path: "/bank/transfers", icon: <ArrowLeftRight className="h-5 w-5" /> },
      { label: "Counterparties", path: "/bank/payments/counterparties", icon: <UserCheck className="h-5 w-5" /> },
      { label: "Standing Orders", path: "/bank/payments/standing-orders", icon: <Repeat className="h-5 w-5" /> },
      { label: "Mandates", path: "/bank/payments/mandates", icon: <FileText className="h-5 w-5" /> },
      { label: "FX Rates", path: "/bank/payments/fx", icon: <ArrowLeftRight className="h-5 w-5" /> },
      { label: "Consents", path: "/bank/consents", icon: <ShieldCheck className="h-5 w-5" /> },
      { label: "Account Views", path: "/bank/views", icon: <Eye className="h-5 w-5" /> },
      { label: "My Cards", path: "/bank/cards", icon: <CreditCard className="h-5 w-5" /> },
      { label: "Customers", path: "/bank/customers", icon: <Users className="h-5 w-5" /> },
      { label: "Financial Products", path: "/bank/products", icon: <Landmark className="h-5 w-5" /> },
      { label: "OAuth Apps", path: "/bank/oauth-clients", icon: <KeyRound className="h-5 w-5" /> },
      { label: "Developer Platform", path: "/bank/platform", icon: <Gauge className="h-5 w-5" /> },
    ],
  },
];

// ─── Sidebar Component ──────────────────────────────────────────

export default function Sidebar() {
  const { t } = useTranslation();
  const collapsed = useUiStore((s) => s.sidebarCollapsed);
  const toggleSidebar = useUiStore((s) => s.toggleSidebar);
  const location = useLocation();
  const accessToken = useAuthStore((s) => s.accessToken);
  const showRootRoleManagement = canSeeRootRoleManagement(accessToken);
  const showModerationBoard = canAccessModerationBoard(accessToken);
  const showPaymentIncidents = canAccessPaymentIncidentQueue(accessToken);
  const showInventoryAdmin =
    isInventoryReservationsEnabled() && canAccessGeneralAdminControls(accessToken);

  const { data: convoData } = useQuery({
    queryKey: ["conversations"],
    queryFn: () => getConversations(),
    staleTime: 30_000,
    refetchOnWindowFocus: true,
  });
  const totalUnread = (convoData?.conversations ?? []).reduce(
    (sum, c) => sum + (c.unread_count ?? 0),
    0,
  );

  const isActive = (path: string) => {
    if (path === "/") return location.pathname === "/";
    return location.pathname.startsWith(path);
  };

  return (
    <aside
      className={cn(
        "hidden md:flex flex-col border-r border-border bg-card transition-all duration-200 ease-in-out",
        collapsed ? "w-16" : "w-60",
      )}
    >
      {/* Logo */}
      <div className={cn("flex h-14 items-center border-b border-border px-4", collapsed && "justify-center px-0")}>
        {collapsed ? (
          <div className="flex h-8 w-8 items-center justify-center rounded-lg bg-primary text-primary-foreground">
            <span className="text-sm font-bold">T</span>
          </div>
        ) : (
          <div className="flex items-center gap-2">
            <div className="flex h-8 w-8 items-center justify-center rounded-lg bg-primary text-primary-foreground">
              <span className="text-sm font-bold">T</span>
            </div>
            <span className="text-base font-semibold tracking-tight">TestLogon</span>
          </div>
        )}
      </div>

      {/* Navigation */}
      <nav className="flex-1 overflow-y-auto px-2 py-3">
        {NAV_GROUPS.map((group, gi) => {
          const items = group.items.filter((item) => {
            if (item.path === "/broadcast") return isBroadcastNavigationEnabled();
            if (item.path === "/broadcast/schedule") return isBroadcastNavigationEnabled();
            if (item.path === "/root/roles") return showRootRoleManagement;
            if (item.path === "/remote-desktop") return isVncRemoteDesktopEnabled();
            if (item.path === "/agents/qa-actions") return isAgentSshQaEnabled();
            if (item.path === "/admin/moderation") return showModerationBoard;
            if (item.path === "/admin/payment-incidents") return showPaymentIncidents;
            if (item.path === "/admin/video-review") return showModerationBoard;
            if (item.path === "/admin/video-review-queue") return showModerationBoard;
            if (item.path === "/admin/dmca") return showModerationBoard;
            if (item.path === "/admin/appeals") return showModerationBoard;
            if (item.path === "/admin/communications") return showModerationBoard;
            if (item.path === "/admin/rate-limits") return showRootRoleManagement;
            if (item.path === "/admin/security") return showRootRoleManagement;
            if (item.path === "/admin/legal-holds") return showRootRoleManagement;
            if (item.path === "/admin/jobs") return showModerationBoard;
            if (item.path === "/admin/ads/fraud") return showModerationBoard;
            if (item.path === "/admin/ad-platform") return showModerationBoard;
            if (item.path === "/admin/bulk-payouts") return showRootRoleManagement;
            if (item.path === "/admin/inventory") return showInventoryAdmin;
            return true;
          });
          if (items.length === 0) return null;
          return (
          <div key={group.title}>
            {gi > 0 && <Separator className="my-2" />}
            {!collapsed && (
              <span className="mb-1 block px-3 text-[11px] font-semibold uppercase tracking-wider text-muted-foreground">
                {group.i18nKey ? t(group.i18nKey) : group.title}
              </span>
            )}
            <ul className="space-y-0.5">
              {items.map((item) => {
                const active = isActive(item.path);
                const badge = item.path === "/messages" ? totalUnread : (item.badge ?? 0);
                const link = (
                  <NavLink
                    key={item.path}
                    to={item.path}
                    className={cn(
                      "group flex items-center gap-3 rounded-lg px-3 py-2 text-sm font-medium transition-colors",
                      active
                        ? "bg-primary/10 text-primary border-l-2 border-primary -ml-px"
                        : "text-muted-foreground hover:bg-accent hover:text-foreground",
                      collapsed && "justify-center px-0 gap-0",
                    )}
                  >
                    <span className={cn("relative shrink-0", active && "text-primary")}>
                      {item.icon}
                      {collapsed && badge > 0 && (
                        <span className="absolute -right-1 -top-1 flex h-4 min-w-4 items-center justify-center rounded-full bg-primary px-0.5 text-[9px] font-bold text-primary-foreground">
                          {badge > 9 ? "9+" : badge}
                        </span>
                      )}
                    </span>
                    {!collapsed && (
                      <span className="truncate">{item.i18nKey ? t(item.i18nKey) : item.label}</span>
                    )}
                    {!collapsed && badge > 0 && (
                      <span className="ml-auto flex h-5 min-w-5 items-center justify-center rounded-full bg-primary px-1.5 text-[10px] font-semibold text-primary-foreground">
                        {badge > 99 ? "99+" : badge}
                      </span>
                    )}
                  </NavLink>
                );

                if (collapsed) {
                  return (
                    <li key={item.path}>
                      <Tooltip>
                        <TooltipTrigger asChild>{link}</TooltipTrigger>
                        <TooltipContent side="right" sideOffset={8}>
                          {item.i18nKey ? t(item.i18nKey) : item.label}
                        </TooltipContent>
                      </Tooltip>
                    </li>
                  );
                }

                return <li key={item.path}>{link}</li>;
              })}
            </ul>
          </div>
          );
        })}
      </nav>

      {/* Dev Tools link (dev-mode only, gated by feature flag) */}
      {isDevtoolsLogUiEnabled() && (
        <div className="border-t border-border px-2 py-2">
          <Tooltip>
            <TooltipTrigger asChild>
              <a
                href="http://localhost:3001/devtools.html"
                target="_blank"
                rel="noopener noreferrer"
                className={cn(
                  "group flex items-center gap-3 rounded-lg px-3 py-2 text-sm font-medium transition-colors text-muted-foreground hover:bg-accent hover:text-foreground",
                  collapsed && "justify-center px-0 gap-0",
                )}
              >
                <Wrench className="h-5 w-5 shrink-0" />
                {!collapsed && <span className="truncate">Dev Tools</span>}
              </a>
            </TooltipTrigger>
            <TooltipContent side="right" sideOffset={8}>Dev Tools</TooltipContent>
          </Tooltip>
        </div>
      )}

      {/* Collapse toggle */}
      <div className="border-t border-border p-2">
        <Tooltip>
          <TooltipTrigger asChild>
            <Button
              variant="ghost"
              size="sm"
              className={cn("w-full", collapsed ? "justify-center" : "justify-start")}
              onClick={toggleSidebar}
              aria-label={collapsed ? "Expand sidebar" : "Collapse sidebar"}
            >
              {collapsed ? (
                <PanelLeft className="h-4 w-4" />
              ) : (
                <>
                  <PanelLeftClose className="h-4 w-4" />
                  <span className="ml-2">{t("nav.collapse")}</span>
                </>
              )}
            </Button>
          </TooltipTrigger>
          <TooltipContent side="right" sideOffset={8}>
            {collapsed ? "Expand sidebar" : "Collapse sidebar"}
          </TooltipContent>
        </Tooltip>
      </div>
    </aside>
  );
}
