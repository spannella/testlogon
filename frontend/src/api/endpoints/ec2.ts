import { api } from "@/api/client";
import type {
  Ec2LaunchIn,
  Ec2InstanceOut,
  Ec2InstanceListOut,
  Ec2InstanceTypeListOut,
  Ec2AmiListOut,
} from "@/api/types";

const BASE = "/ui/remote/ec2";

export const listInstanceTypes = () =>
  api.get<Ec2InstanceTypeListOut>(`${BASE}/instance-types`);

export const listAmis = () =>
  api.get<Ec2AmiListOut>(`${BASE}/amis`);

export const launchInstance = (body: Ec2LaunchIn) =>
  api.post<Ec2InstanceOut>(`${BASE}/launch`, body);

export const listInstances = (status?: string) =>
  api.get<Ec2InstanceListOut>(`${BASE}/instances`, status ? { status } : undefined);

export const getInstance = (instanceId: string) =>
  api.get<Ec2InstanceOut>(`${BASE}/instances/${instanceId}`);

export const stopInstance = (instanceId: string) =>
  api.post<Ec2InstanceOut>(`${BASE}/instances/${instanceId}/stop`);

export const startInstance = (instanceId: string) =>
  api.post<Ec2InstanceOut>(`${BASE}/instances/${instanceId}/start`);

export const terminateInstance = (instanceId: string) =>
  api.post<Ec2InstanceOut>(`${BASE}/instances/${instanceId}/terminate`);

export const rebootInstance = (instanceId: string) =>
  api.post<Ec2InstanceOut>(`${BASE}/instances/${instanceId}/reboot`);
