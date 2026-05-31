import { api } from "@/api/client";
import type {
  CreateSgIn,
  UpdateSgIn,
  SecurityRuleIn,
  UpdateRuleIn,
  SecurityGroupOut,
  SgListOut,
  EffectiveRulesOut,
} from "@/api/types";

const BASE = "/ui/compute/security-groups";

export const listSecurityGroups = () => api.get<SgListOut>(BASE);

export const getSecurityGroup = (sgId: string) =>
  api.get<SecurityGroupOut>(`${BASE}/${sgId}`);

export const getEffectiveRules = (sgId: string) =>
  api.get<EffectiveRulesOut>(`${BASE}/${sgId}/effective-rules`);

export const createSecurityGroup = (body: CreateSgIn) =>
  api.post<SecurityGroupOut>(BASE, body);

export const updateSecurityGroup = (sgId: string, body: UpdateSgIn) =>
  api.patch<SecurityGroupOut>(`${BASE}/${sgId}`, body);

export const deleteSecurityGroup = (sgId: string) =>
  api.del<{ ok: boolean }>(`${BASE}/${sgId}`);

export const addSecurityGroupRule = (sgId: string, body: SecurityRuleIn) =>
  api.post<SecurityGroupOut>(`${BASE}/${sgId}/rules`, body);

export const removeSecurityGroupRule = (sgId: string, ruleId: string) =>
  api.del<SecurityGroupOut>(`${BASE}/${sgId}/rules/${ruleId}`);

export const updateSecurityGroupRule = (
  sgId: string,
  ruleId: string,
  body: UpdateRuleIn,
) => api.patch<SecurityGroupOut>(`${BASE}/${sgId}/rules/${ruleId}`, body);
