/**
 * Hotel Setup API endpoints (QloApps HTL spine).
 *
 * All paths are under /ui/hotels (mounted on the Vite proxy to backend).
 * Feature-gated: HOTEL_PMS_ENABLED (default OFF) -> 404 when off.
 *
 * Inline TS types mirror app/models.py Hotel, Amenity, RoomType, HkTask models.
 */

import { api } from "@/api/client";

// ─── Shared sub-models ────────────────────────────────────────────────────────

export interface HotelAddress {
  line1: string;
  line2?: string | null;
  city: string;
  region: string;
  postal_code: string;
  country: string;
}

export interface HotelPolicies {
  cancellation_text: string;
  pet_policy: string;
  smoking: boolean;
  children: boolean;
}

export interface HotelContact {
  phone: string;
  email: string;
  website: string;
}

// ─── Hotel ────────────────────────────────────────────────────────────────────

export interface HotelOut {
  hotel_id: string;
  owner_sub: string;
  name: string;
  description: string;
  star_rating: number;
  address: HotelAddress;
  check_in_time: string;
  check_out_time: string;
  policies: HotelPolicies;
  contact: HotelContact;
  photo_urls: string[];
  status: "active" | "archived";
  created_at: number;
  updated_at: number;
}

export interface HotelListResp {
  items: HotelOut[];
  count: number;
  cursor: string | null;
}

export interface HotelIn {
  name: string;
  description?: string;
  star_rating: number;
  address: HotelAddress;
  check_in_time?: string;
  check_out_time?: string;
  policies?: Partial<HotelPolicies>;
  contact?: Partial<HotelContact>;
  photo_urls?: string[];
}

export interface HotelUpdateIn {
  name?: string;
  description?: string;
  star_rating?: number;
  address?: HotelAddress;
  check_in_time?: string;
  check_out_time?: string;
  policies?: Partial<HotelPolicies>;
  contact?: Partial<HotelContact>;
  photo_urls?: string[];
}

export const listHotels = (opts?: { status?: string; cursor?: string; limit?: number }) => {
  const params: Record<string, string> = {};
  if (opts?.status) params.status = opts.status;
  if (opts?.cursor) params.cursor = opts.cursor;
  if (opts?.limit) params.limit = String(opts.limit);
  return api.get<HotelListResp>("/ui/hotels", params);
};

export const getHotel = (hotelId: string) =>
  api.get<HotelOut>(`/ui/hotels/${hotelId}`);

export const createHotel = (body: HotelIn) =>
  api.post<HotelOut>("/ui/hotels", body);

export const updateHotel = (hotelId: string, body: HotelUpdateIn) =>
  api.put<HotelOut>(`/ui/hotels/${hotelId}`, body);

export const archiveHotel = (hotelId: string) =>
  api.del<HotelOut>(`/ui/hotels/${hotelId}`);

// ─── Amenities (dictionary) ───────────────────────────────────────────────────

export type AmenityCategory =
  | "connectivity"
  | "wellness"
  | "parking"
  | "dining"
  | "family"
  | "accessibility"
  | "general";

export interface AmenityOut {
  amenity_id: string;
  name: string;
  category: string;
  icon: string | null;
  created_at: number;
}

export interface AmenityAssociationOut {
  amenity_id: string;
  name: string;
  category: string;
  icon: string | null;
  target_type: "hotel" | "room_type";
  created_at: number;
}

export interface AmenityIn {
  name: string;
  category: AmenityCategory;
  icon?: string | null;
}

export const listAmenities = (category?: string) => {
  const params: Record<string, string> = {};
  if (category) params.category = category;
  return api.get<AmenityOut[]>("/ui/hotels/amenities", params);
};

export const createAmenity = (body: AmenityIn) =>
  api.post<AmenityOut>("/ui/hotels/amenities", body);

export const listHotelAmenities = (hotelId: string) =>
  api.get<AmenityAssociationOut[]>(`/ui/hotels/${hotelId}/amenities`);

export const attachAmenity = (targetType: "hotel" | "room_type", targetId: string, amenityId: string) =>
  api.post<AmenityAssociationOut>("/ui/hotels/amenities/attach", {
    target_type: targetType,
    target_id: targetId,
    amenity_id: amenityId,
  });

export const detachAmenity = (targetType: "hotel" | "room_type", targetId: string, amenityId: string) =>
  api.post<{ ok: boolean }>("/ui/hotels/amenities/detach", {
    target_type: targetType,
    target_id: targetId,
    amenity_id: amenityId,
  });

// ─── Room Types ───────────────────────────────────────────────────────────────

export type BedType = "single" | "twin" | "double" | "queen" | "king" | "suite";

export interface RoomTypeOut {
  hotel_id: string;
  room_type_id: string;
  name: string;
  description: string;
  base_occupancy_adults: number;
  base_occupancy_children: number;
  max_occupancy: number;
  bed_type: BedType;
  size_sqft: number;
  base_nightly_rate_cents: number;
  photo_urls: string[];
  status: "active" | "archived";
  created_at: number;
  updated_at: number;
}

export interface RoomTypeListResp {
  room_types: RoomTypeOut[];
  count: number;
  cursor: string | null;
}

export interface RoomTypeIn {
  name: string;
  description?: string;
  base_occupancy_adults: number;
  base_occupancy_children?: number;
  max_occupancy: number;
  bed_type: BedType;
  size_sqft?: number;
  base_nightly_rate_cents: number;
  photo_urls?: string[];
}

export interface RoomTypeUpdateIn {
  name?: string;
  description?: string;
  base_occupancy_adults?: number;
  base_occupancy_children?: number;
  max_occupancy?: number;
  bed_type?: BedType;
  size_sqft?: number;
  base_nightly_rate_cents?: number;
  photo_urls?: string[];
}

export const listRoomTypes = (hotelId: string, opts?: { status?: string; cursor?: string; limit?: number }) => {
  const params: Record<string, string> = {};
  if (opts?.status) params.status = opts.status;
  if (opts?.cursor) params.cursor = opts.cursor;
  if (opts?.limit) params.limit = String(opts.limit);
  return api.get<RoomTypeListResp>(`/ui/hotels/${hotelId}/room-types`, params);
};

export const getRoomType = (hotelId: string, roomTypeId: string) =>
  api.get<RoomTypeOut>(`/ui/hotels/${hotelId}/room-types/${roomTypeId}`);

export const createRoomType = (hotelId: string, body: RoomTypeIn) =>
  api.post<RoomTypeOut>(`/ui/hotels/${hotelId}/room-types`, body);

export const updateRoomType = (hotelId: string, roomTypeId: string, body: RoomTypeUpdateIn) =>
  api.put<RoomTypeOut>(`/ui/hotels/${hotelId}/room-types/${roomTypeId}`, body);

export const archiveRoomType = (hotelId: string, roomTypeId: string) =>
  api.del<RoomTypeOut>(`/ui/hotels/${hotelId}/room-types/${roomTypeId}`);

// ─── Rooms ────────────────────────────────────────────────────────────────────

export interface RoomOut {
  hotel_id: string;
  room_id: string;
  room_type_id: string;
  room_number: string;
  floor: number;
  status: "available" | "out_of_service";
  housekeeping_status: "clean" | "dirty" | "inspected" | "out_of_service";
  created_at: number;
  updated_at: number;
}

export interface RoomListResp {
  rooms: RoomOut[];
  count: number;
  cursor: string | null;
}

export interface RoomIn {
  room_type_id: string;
  room_number: string;
  floor: number;
  status?: "available" | "out_of_service";
}

export interface RoomUpdateIn {
  room_type_id?: string;
  room_number?: string;
  floor?: number;
  status?: "available" | "out_of_service";
}

export const listRooms = (
  hotelId: string,
  opts?: { room_type_id?: string; status?: string; cursor?: string; limit?: number },
) => {
  const params: Record<string, string> = {};
  if (opts?.room_type_id) params.room_type_id = opts.room_type_id;
  if (opts?.status) params.status = opts.status;
  if (opts?.cursor) params.cursor = opts.cursor;
  if (opts?.limit) params.limit = String(opts.limit);
  return api.get<RoomListResp>(`/ui/hotels/${hotelId}/rooms`, params);
};

export const getRoom = (hotelId: string, roomId: string) =>
  api.get<RoomOut>(`/ui/hotels/${hotelId}/rooms/${roomId}`);

export const createRoom = (hotelId: string, body: RoomIn) =>
  api.post<RoomOut>(`/ui/hotels/${hotelId}/rooms`, body);

export const updateRoom = (hotelId: string, roomId: string, body: RoomUpdateIn) =>
  api.put<RoomOut>(`/ui/hotels/${hotelId}/rooms/${roomId}`, body);

export const deleteRoom = (hotelId: string, roomId: string) =>
  api.del<{ ok: boolean }>(`/ui/hotels/${hotelId}/rooms/${roomId}`);

export const setRoomHousekeepingStatus = (
  hotelId: string,
  roomId: string,
  housekeepingStatus: "clean" | "dirty" | "inspected" | "out_of_service",
) =>
  api.put<RoomOut>(`/ui/hotels/${hotelId}/rooms/${roomId}/housekeeping`, {
    housekeeping_status: housekeepingStatus,
  });

// ─── Housekeeping Tasks ───────────────────────────────────────────────────────

export interface HkTaskOut {
  hotel_id: string;
  task_id: string;
  room_id: string;
  assignee_sub: string;
  status: "open" | "in_progress" | "done";
  due_at: number;
  notes: string;
  created_at: number;
  updated_at: number;
  completed_at: number;
}

export interface HkTaskListResp {
  tasks: HkTaskOut[];
  count: number;
  cursor: string | null;
}

export interface HkTaskIn {
  room_id: string;
  assignee_sub?: string;
  due_at?: number;
  notes?: string;
}

export const listHkTasks = (
  hotelId: string,
  opts?: { status?: string; assignee_sub?: string; cursor?: string; limit?: number },
) => {
  const params: Record<string, string> = {};
  if (opts?.status) params.status = opts.status;
  if (opts?.assignee_sub) params.assignee_sub = opts.assignee_sub;
  if (opts?.cursor) params.cursor = opts.cursor;
  if (opts?.limit) params.limit = String(opts.limit);
  return api.get<HkTaskListResp>(`/ui/hotels/${hotelId}/housekeeping/tasks`, params);
};

export const createHkTask = (hotelId: string, body: HkTaskIn) =>
  api.post<HkTaskOut>(`/ui/hotels/${hotelId}/housekeeping/tasks`, body);

export const assignHkTask = (hotelId: string, taskId: string, assigneeSub: string) =>
  api.put<HkTaskOut>(`/ui/hotels/${hotelId}/housekeeping/tasks/${taskId}/assign`, {
    assignee_sub: assigneeSub,
  });

export const completeHkTask = (hotelId: string, taskId: string) =>
  api.put<HkTaskOut>(`/ui/hotels/${hotelId}/housekeeping/tasks/${taskId}/complete`, {});

// ─── Cancellation Policy ──────────────────────────────────────────────────────

export interface CancellationPolicyOut {
  hotel_id: string;
  policy_id: string;
  scope: string;
  free_until_days_before: number;
  penalty_pct: number;
  penalty_fixed_cents: number;
  no_show_fee_cents: number;
  created_at: number;
  updated_at: number;
}

export interface CancellationPolicyIn {
  free_until_days_before?: number;
  penalty_pct?: number;
  penalty_fixed_cents?: number;
  no_show_fee_cents?: number;
}

export const getCancellationPolicy = (hotelId: string, scope = "default") =>
  api.get<CancellationPolicyOut>(`/ui/hotels/${hotelId}/cancellation-policy`, { scope });

export const upsertCancellationPolicy = (hotelId: string, body: CancellationPolicyIn, scope = "default") =>
  api.put<CancellationPolicyOut>(`/ui/hotels/${hotelId}/cancellation-policy?scope=${encodeURIComponent(scope)}`, body);

// ─── KPI Report ───────────────────────────────────────────────────────────────

export interface HotelKpisOut {
  hotel_id: string;
  from_ts: number;
  to_ts: number;
  rooms_available: number;
  rooms_sold: number;
  occupancy_pct: number;
  room_revenue_cents: number;
  adr_cents: number;
  revpar_cents: number;
  arrivals: number;
  departures: number;
  currency: string;
}

export const getHotelKpis = (hotelId: string, fromTs: number, toTs: number) =>
  api.get<HotelKpisOut>(`/ui/hotels/${hotelId}/reports/kpis`, {
    from_ts: String(fromTs),
    to_ts: String(toTs),
  });
