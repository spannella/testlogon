import { api } from "@/api/client";
import type {
  BillingConfig,
  BillingSettings,
  BillingBalance,
  PaymentMethod,
  LedgerEntry,
  Subscription,
  SetAutopayReq,
  PayBalanceReq,
  StripeChargeReq,
  StripeRefundReq,
  SetPriorityReq,
  SetDefaultReq,
  BillingCheckoutReq,
  OkResp,
  WalletBalance,
  WalletDepositReq,
  WalletWithdrawReq,
} from "@/api/types";

export const getConfig = () =>
  api.get<BillingConfig>("/ui/billing/config");

export const getSettings = () =>
  api.get<BillingSettings>("/ui/billing/settings");

export const getBalance = () =>
  api.get<BillingBalance>("/ui/billing/balance");

export const setAutopay = (body: SetAutopayReq) =>
  api.post<OkResp>("/ui/billing/autopay", body);

export const getPaymentMethods = () =>
  api.get<PaymentMethod[]>("/ui/billing/payment-methods");

export const createCardSetupIntent = () =>
  api.post<{ client_secret: string }>("/ui/billing/setup-intent/card");

export const addCard = (body: {
  card_number: string;
  exp_month: number;
  exp_year: number;
  cvc: string;
  cardholder_name?: string;
}) =>
  api.post<{ payment_method_id: string; brand?: string; last4?: string; label?: string }>(
    "/ui/billing/payment-methods/card",
    body,
  );

export const createBankSetupIntent = () =>
  api.post<{ client_secret: string }>("/ui/billing/setup-intent/us-bank");

export const verifyMicrodeposits = (body: { setup_intent_id: string; amounts: [number, number] }) =>
  api.post<{ status: string }>("/ui/billing/us-bank/verify-microdeposits", body);

export const setPriority = (body: SetPriorityReq) =>
  api.post<OkResp>("/ui/billing/payment-methods/priority", body);

export const setDefault = (body: SetDefaultReq) =>
  api.post<OkResp>("/ui/billing/payment-methods/default", body);

export const removePaymentMethod = (id: string) =>
  api.del<OkResp>(`/ui/billing/payment-methods/${id}`);

export const payBalance = (body: PayBalanceReq) =>
  api.post<{ status: string; payment_intent_id?: string }>("/ui/billing/pay-balance", body);

export const chargeOnce = (body: StripeChargeReq) =>
  api.post<{ status: string; payment_intent_id: string }>("/ui/billing/charge-once", body);

export const refund = (body: StripeRefundReq) =>
  api.post<{ ok: boolean; refund_id: string }>("/ui/billing/refund", body);

export const createCheckoutSession = (body: BillingCheckoutReq) =>
  api.post<{ session_id: string; url: string }>("/ui/billing/checkout_session", body);

export const getLedger = (limit = 50) =>
  api.get<{ items: LedgerEntry[] }>("/ui/billing/ledger", { limit: String(limit) });

export const getPayments = (limit = 50) =>
  api.get<{ items: LedgerEntry[] }>("/ui/billing/payments", { limit: String(limit) });

export const getSubscriptions = (limit = 50) =>
  api.get<{ items: Subscription[] }>("/ui/billing/subscriptions", { limit: String(limit) });

export const getWallet = () =>
  api.get<WalletBalance>("/ui/billing/wallet");

export const depositToWallet = (body: WalletDepositReq) =>
  api.post<{ status: string; payment_intent_id: string; wallet_balance_cents: number }>("/ui/billing/wallet/deposit", body);

export const withdrawFromWallet = (body: WalletWithdrawReq) =>
  api.post<{ ok: boolean; wallet_balance_cents: number }>("/ui/billing/wallet/withdraw", body);
