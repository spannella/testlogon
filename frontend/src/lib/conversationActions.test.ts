import { describe, expect, it } from "vitest";

import {
  isPendingInvite,
  isActiveMember,
  activeParticipantCount,
  canLeave,
  canRespondToInvite,
  canDelete,
  canManageParticipants,
  canRemoveParticipant,
  leaveActionLabel,
  deleteActionLabel,
  roleToggleLabel,
  nextRole,
  type ConversationLifecycleView,
} from "./conversationActions";

const group = (
  overrides: Partial<ConversationLifecycleView> = {},
): ConversationLifecycleView => ({
  status: "active",
  type: "group",
  participants: [
    { user_id: "me", status: "active", role: "admin" },
    { user_id: "them", status: "active", role: "member" },
  ],
  ...overrides,
});

describe("membership status helpers", () => {
  it("detects a pending invite", () => {
    expect(isPendingInvite({ status: "pending" })).toBe(true);
    expect(isPendingInvite({ status: "active" })).toBe(false);
    expect(isPendingInvite(null)).toBe(false);
    expect(isPendingInvite(undefined)).toBe(false);
  });

  it("detects an active member", () => {
    expect(isActiveMember({ status: "active" })).toBe(true);
    expect(isActiveMember({ status: "pending" })).toBe(false);
    expect(isActiveMember({ status: "left" })).toBe(false);
  });

  it("counts active participants and treats missing status as active", () => {
    expect(activeParticipantCount(group())).toBe(2);
    expect(
      activeParticipantCount({
        participants: [
          { user_id: "a", status: "active" },
          { user_id: "b", status: "left" },
          { user_id: "c" }, // missing -> active
        ],
      }),
    ).toBe(2);
    expect(activeParticipantCount({})).toBe(0);
  });
});

describe("canLeave / canRespondToInvite", () => {
  it("allows leaving only when active", () => {
    expect(canLeave({ status: "active" })).toBe(true);
    expect(canLeave({ status: "pending" })).toBe(false);
    expect(canLeave({ status: "left" })).toBe(false);
  });

  it("allows responding to an invite only when pending", () => {
    expect(canRespondToInvite({ status: "pending" })).toBe(true);
    expect(canRespondToInvite({ status: "active" })).toBe(false);
  });
});

describe("canDelete", () => {
  it("allows delete when the viewer is the only active participant", () => {
    expect(
      canDelete({ status: "active", participants: [{ user_id: "me", status: "active" }] }),
    ).toBe(true);
  });

  it("blocks delete when other active participants exist", () => {
    expect(canDelete(group())).toBe(false);
  });

  it("blocks delete for a non-active viewer", () => {
    expect(canDelete({ status: "pending", participants: [{ user_id: "me", status: "pending" }] })).toBe(false);
  });

  it("permits the attempt when participant data is unknown (backend gates it)", () => {
    expect(canDelete({ status: "active" })).toBe(true);
  });
});

describe("canManageParticipants", () => {
  it("is true for an active admin in a group", () => {
    expect(canManageParticipants(group(), "me")).toBe(true);
  });

  it("is false for a non-admin member", () => {
    expect(canManageParticipants(group(), "them")).toBe(false);
  });

  it("is false in a DM", () => {
    expect(canManageParticipants(group({ type: "dm" }), "me")).toBe(false);
  });

  it("is false when viewer is not active", () => {
    expect(canManageParticipants(group({ status: "pending" }), "me")).toBe(false);
  });

  it("is false without a viewer id", () => {
    expect(canManageParticipants(group(), null)).toBe(false);
    expect(canManageParticipants(group(), undefined)).toBe(false);
  });
});

describe("canRemoveParticipant", () => {
  it("lets an admin remove another participant", () => {
    expect(canRemoveParticipant(group(), "me", "them")).toBe(true);
  });

  it("never lets an admin remove themselves", () => {
    expect(canRemoveParticipant(group(), "me", "me")).toBe(false);
  });

  it("blocks non-admins", () => {
    expect(canRemoveParticipant(group(), "them", "me")).toBe(false);
  });
});

describe("labels", () => {
  it("switches the leave label between decline and leave", () => {
    expect(leaveActionLabel({ status: "pending" })).toBe("Decline invite");
    expect(leaveActionLabel({ status: "active" })).toBe("Leave conversation");
  });

  it("labels delete by conversation type", () => {
    expect(deleteActionLabel({ type: "group" })).toBe("Delete group");
    expect(deleteActionLabel({ type: "dm" })).toBe("Delete conversation");
    expect(deleteActionLabel({})).toBe("Delete conversation");
  });

  it("computes role toggle label and next role", () => {
    expect(roleToggleLabel("admin")).toBe("Demote to member");
    expect(roleToggleLabel("member")).toBe("Promote to admin");
    expect(roleToggleLabel(undefined)).toBe("Promote to admin");
    expect(nextRole("admin")).toBe("member");
    expect(nextRole("member")).toBe("admin");
    expect(nextRole(undefined)).toBe("admin");
  });
});
