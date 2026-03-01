import { describe, it, expect, vi, beforeEach } from "vitest";
import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { SignaturePacketComposer } from "../SignaturePacketComposer";

const createSignaturePacket = vi.fn();
const getSignaturePacketDetail = vi.fn();
const createSignaturePacketField = vi.fn();
const deleteSignaturePacketField = vi.fn();
const sendSignaturePacket = vi.fn();
const acknowledgeSignaturePacketLegalNotice = vi.fn();
const fillSignaturePacketField = vi.fn();
const markSignaturePacketDone = vi.fn();
const downloadSignaturePacketFinalPdf = vi.fn();

vi.mock("@/api/endpoints/signaturePackets", () => ({
  createSignaturePacket: (...args: unknown[]) => createSignaturePacket(...args),
  getSignaturePacketDetail: (...args: unknown[]) => getSignaturePacketDetail(...args),
  createSignaturePacketField: (...args: unknown[]) => createSignaturePacketField(...args),
  deleteSignaturePacketField: (...args: unknown[]) => deleteSignaturePacketField(...args),
  sendSignaturePacket: (...args: unknown[]) => sendSignaturePacket(...args),
  acknowledgeSignaturePacketLegalNotice: (...args: unknown[]) => acknowledgeSignaturePacketLegalNotice(...args),
  fillSignaturePacketField: (...args: unknown[]) => fillSignaturePacketField(...args),
  markSignaturePacketDone: (...args: unknown[]) => markSignaturePacketDone(...args),
  downloadSignaturePacketFinalPdf: (...args: unknown[]) => downloadSignaturePacketFinalPdf(...args),
}));

const signerPacket = {
  packet_id: "sp_1",
  status: "sent",
  owner_user_id: "owner-1",
  source_path: "/nda.pdf",
  role: "signer",
  signer_status: "pending",
  created_at: "2026-01-01T00:00:00+00:00",
  sent_at: "2026-01-01T01:00:00+00:00",
  completed_at: null,
  signers: [{ signer_id: "signer-1", status: "pending" }],
  capabilities: { can_edit_fields: false, can_send: false, can_fill_fields: true },
  fields: [
    {
      field_id: "sf_assigned",
      page: 1,
      x: 0.1,
      y: 0.1,
      width: 0.2,
      height: 0.1,
      field_type: "text",
      required: true,
      assigned_signer_id: "signer-1",
      is_assigned_to_viewer: true,
      filled_at: undefined,
    },
    {
      field_id: "sf_other",
      page: 1,
      x: 0.4,
      y: 0.2,
      width: 0.2,
      height: 0.1,
      field_type: "text",
      required: true,
      assigned_signer_id: "signer-2",
      is_assigned_to_viewer: false,
      filled_at: undefined,
    },
  ],
};

describe("SignaturePacketComposer signer fill UX", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    window.localStorage.clear();
    getSignaturePacketDetail.mockResolvedValue(signerPacket);
    fillSignaturePacketField.mockResolvedValue({});
    acknowledgeSignaturePacketLegalNotice.mockResolvedValue({});
    markSignaturePacketDone.mockResolvedValue({});
    createSignaturePacket.mockResolvedValue({ packet_id: "sp_created" });
    createSignaturePacketField.mockResolvedValue({});
    deleteSignaturePacketField.mockResolvedValue({});
    sendSignaturePacket.mockResolvedValue({});
    downloadSignaturePacketFinalPdf.mockResolvedValue(undefined);
  });

  it("renders only assigned fields editable and keeps mark-done disabled until requirements are met", async () => {
    window.localStorage.setItem("signature_packet_capture_mode_default", "drawn");
  render(<SignaturePacketComposer />);
    await userEvent.type(screen.getByPlaceholderText(/Packet ID/i), "sp_1");
    await userEvent.click(screen.getByRole("button", { name: /Load/i }));

    expect(await screen.findByTestId("signer-fill-panel")).toBeInTheDocument();
    expect(screen.getByTestId("remaining-required").textContent).toMatch(/1/);

    const markDone = screen.getByTestId("mark-done-btn") as HTMLButtonElement;
    expect(markDone.disabled).toBe(true);

    expect(screen.getByTestId("field-input-sf_assigned")).toBeInTheDocument();
    expect(screen.queryByTestId("field-input-sf_other")).not.toBeInTheDocument();

    await userEvent.type(screen.getByTestId("field-input-sf_assigned"), "ok signer text");
    await userEvent.click(screen.getByTestId("field-submit-sf_assigned"));

    await waitFor(() => {
      expect(fillSignaturePacketField).toHaveBeenCalledWith("sp_1", "sf_assigned", { value: "ok signer text" });
    });
  });

  it("shows field-level validation and prevents invalid fill submission", async () => {
    render(<SignaturePacketComposer />);
    await userEvent.type(screen.getByPlaceholderText(/Packet ID/i), "sp_1");
    await userEvent.click(screen.getByRole("button", { name: /Load/i }));

    await screen.findByTestId("field-input-sf_assigned");
    await userEvent.click(screen.getByTestId("field-submit-sf_assigned"));

    expect(await screen.findByTestId("field-error-sf_assigned")).toBeInTheDocument();
    expect(fillSignaturePacketField).not.toHaveBeenCalled();
  });

  it("shows timeline + status chip and download CTA when packet is completed", async () => {
    getSignaturePacketDetail.mockResolvedValueOnce({
      ...signerPacket,
      status: "completed",
      signer_status: "completed",
      completed_at: "2026-01-02T00:00:00+00:00",
      capabilities: { can_edit_fields: false, can_send: false, can_fill_fields: false },
    });

    render(<SignaturePacketComposer />);
    await userEvent.type(screen.getByPlaceholderText(/Packet ID/i), "sp_1");
    await userEvent.click(screen.getByRole("button", { name: /Load/i }));

    expect(await screen.findByTestId("packet-status-chip")).toHaveTextContent(/completed/i);
    expect(screen.getByTestId("packet-timeline")).toBeInTheDocument();
    const download = screen.getByTestId("final-download-btn");
    await userEvent.click(download);
    expect(downloadSignaturePacketFinalPdf).toHaveBeenCalledWith("sp_1");
  });
});


it("supports signature drawn mode submissions", async () => {
  vi.clearAllMocks();
  window.localStorage.clear();
  window.localStorage.setItem("signature_packet_capture_mode_default", "drawn");
  fillSignaturePacketField.mockResolvedValue({});
  getSignaturePacketDetail.mockResolvedValueOnce({
    ...signerPacket,
    fields: [{
      field_id: "sf_sig",
      page: 1,
      x: 0.1,
      y: 0.1,
      width: 0.2,
      height: 0.1,
      field_type: "signature",
      required: true,
      assigned_signer_id: "signer-1",
      is_assigned_to_viewer: true,
      filled_at: undefined,
    }],
  });

  render(<SignaturePacketComposer />);
  await userEvent.type(screen.getByPlaceholderText(/Packet ID/i), "sp_1");
  await userEvent.click(screen.getByRole("button", { name: /Load/i }));

  await screen.findByTestId("field-drawn-sf_sig");
  fireEvent.change(screen.getByTestId("field-drawn-sf_sig"), { target: { value: '[[0.1,0.2],[0.2,0.3]]' } });
  await userEvent.click(screen.getByTestId("field-submit-sf_sig"));

  await waitFor(() => {
    expect(fillSignaturePacketField).toHaveBeenCalledWith("sp_1", "sf_sig", {
      input_mode: "drawn",
      drawn_strokes: [[0.1, 0.2], [0.2, 0.3]],
    });
  });
});

it("requires legal notice acceptance before signer can proceed", async () => {
  getSignaturePacketDetail.mockResolvedValueOnce({
    ...signerPacket,
    legal_notice: {
      required: true,
      accepted: false,
      version: "2026-01",
      text: "By signing this document, you agree your signature is legally binding.",
    },
    capabilities: { can_edit_fields: false, can_send: false, can_fill_fields: false },
  });
  getSignaturePacketDetail.mockResolvedValueOnce({
    ...signerPacket,
    legal_notice: {
      required: false,
      accepted: true,
      version: "2026-01",
      text: "By signing this document, you agree your signature is legally binding.",
    },
    capabilities: { can_edit_fields: false, can_send: false, can_fill_fields: true },
  });

  render(<SignaturePacketComposer />);
  await userEvent.type(screen.getByPlaceholderText(/Packet ID/i), "sp_1");
  await userEvent.click(screen.getByRole("button", { name: /Load/i }));

  expect(await screen.findByTestId("legal-notice-panel")).toBeInTheDocument();
  await userEvent.click(screen.getByTestId("legal-notice-accept-btn"));

  await waitFor(() => {
    expect(acknowledgeSignaturePacketLegalNotice).toHaveBeenCalledWith("sp_1");
  });
});
