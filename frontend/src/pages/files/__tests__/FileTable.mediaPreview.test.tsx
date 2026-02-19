import { describe, expect, it, vi } from "vitest";
import { fireEvent, render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { FileTable } from "../FileTable";
import type { FileEntry, PreviewStatus } from "@/api/types";

const { emitFilePreviewTelemetry } = vi.hoisted(() => ({
  emitFilePreviewTelemetry: vi.fn().mockResolvedValue({ ok: true }),
}));

vi.mock("@/api/endpoints/files", async () => {
  const actual = await vi.importActual<typeof import("@/api/endpoints/files")>("@/api/endpoints/files");
  return { ...actual, emitFilePreviewTelemetry };
});

function renderTable(data: FileEntry[]) {
  return render(
    <FileTable
      data={data}
      selectedKeys={new Set()}
      onSelectionChange={() => {}}
      onNavigate={() => {}}
      onPreview={() => {}}
      onDownload={() => {}}
      onShare={() => {}}
      onRename={() => {}}
      onMove={() => {}}
      onDelete={() => {}}
    />,
  );
}

describe("FileTable media previews", () => {
  function setMediaCapabilities(opts?: { reducedMotion?: boolean; touch?: boolean }) {
    const reducedMotion = !!opts?.reducedMotion;
    const touch = !!opts?.touch;

    Object.defineProperty(window, "matchMedia", {
      writable: true,
      value: (query: string) => {
        let matches = false;
        if (query === "(prefers-reduced-motion: reduce)") matches = reducedMotion;
        if (query === "(pointer: coarse)") matches = touch;
        if (query === "(hover: none)") matches = touch;
        return {
          matches,
          media: query,
          onchange: null,
          addEventListener: () => {},
          removeEventListener: () => {},
          addListener: () => {},
          removeListener: () => {},
          dispatchEvent: () => false,
        };
      },
    });

    Object.defineProperty(window.navigator, "maxTouchPoints", {
      configurable: true,
      value: touch ? 5 : 0,
    });
  }

  it("shows a video poster thumbnail when preview is ready", () => {
    setMediaCapabilities();
    renderTable([
      {
        type: "file",
        name: "clip.mp4",
        path: "/clip.mp4",
        preview_kind: "video",
        preview_status: "ready",
        poster_url: "https://cdn.example/clip.webp",
      },
    ]);

    const img = screen.getByAltText("Video preview poster") as HTMLImageElement;
    expect(img).toBeInTheDocument();
    expect(img.src).toBe("https://cdn.example/clip.webp");
  });

  it("shows an audio waveform thumbnail when preview is ready", () => {
    setMediaCapabilities();
    renderTable([
      {
        type: "file",
        name: "sound.mp3",
        path: "/sound.mp3",
        preview_kind: "audio",
        preview_status: "ready",
        waveform_url: "https://cdn.example/waveform.png",
      },
    ]);

    const img = screen.getByAltText("Audio waveform preview") as HTMLImageElement;
    expect(img).toBeInTheDocument();
    expect(img.src).toBe("https://cdn.example/waveform.png");
  });

  it.each<{
    kind: "video" | "audio";
    status: Exclude<PreviewStatus, "ready">;
    text: string;
    name: string;
  }>([
    { kind: "video", status: "pending", text: "Video preview pending", name: "clip-pending.mp4" },
    { kind: "video", status: "failed", text: "Video preview unavailable", name: "clip-failed.mp4" },
    { kind: "video", status: "unsupported", text: "Video preview unsupported", name: "clip-unsupported.mp4" },
    { kind: "audio", status: "pending", text: "Audio preview pending", name: "sound-pending.mp3" },
    { kind: "audio", status: "failed", text: "Audio preview unavailable", name: "sound-failed.mp3" },
    { kind: "audio", status: "unsupported", text: "Audio preview unsupported", name: "sound-unsupported.mp3" },
  ])("shows deterministic fallback for $kind status=$status", ({ kind, status, text, name }) => {
    setMediaCapabilities();
    renderTable([
      {
        type: "file",
        name,
        path: `/${name}`,
        preview_kind: kind,
        preview_status: status,
      },
    ]);

    expect(screen.getByText(text)).toBeInTheDocument();
  });

  it("swaps poster to hover clip on pointer hover and keyboard focus", async () => {
    const user = userEvent.setup();
    setMediaCapabilities({ touch: false, reducedMotion: false });
    renderTable([
      {
        type: "file",
        name: "clip.mp4",
        path: "/clip.mp4",
        preview_kind: "video",
        preview_status: "ready",
        poster_url: "https://cdn.example/clip.webp",
        hover_preview_url: "https://cdn.example/clip-preview.mp4",
      },
    ]);

    const trigger = screen.getByLabelText("Video preview for clip.mp4");
    await user.hover(trigger);
    const hoverVideo = screen.getByLabelText("Video hover preview") as HTMLVideoElement;
    expect(hoverVideo).toBeInTheDocument();
    expect(hoverVideo.src).toBe("https://cdn.example/clip-preview.mp4");

    await user.unhover(trigger);
    expect(screen.getByAltText("Video preview poster")).toBeInTheDocument();

    fireEvent.focus(trigger);
    expect(screen.getByLabelText("Video hover preview")).toBeInTheDocument();
  });

  it("respects reduced motion by disabling hover/focus autoplay swapping", async () => {
    const user = userEvent.setup();
    setMediaCapabilities({ reducedMotion: true });
    renderTable([
      {
        type: "file",
        name: "clip.mp4",
        path: "/clip.mp4",
        preview_kind: "video",
        preview_status: "ready",
        poster_url: "https://cdn.example/clip.webp",
        hover_preview_url: "https://cdn.example/clip-preview.mp4",
      },
    ]);

    const poster = screen.getByAltText("Video preview poster");
    await user.hover(poster);
    expect(screen.queryByLabelText("Video hover preview")).not.toBeInTheDocument();
    expect(screen.getByAltText("Video preview poster")).toBeInTheDocument();
  });

  it("keeps poster by default on touch and enables tap-to-preview when capable", async () => {
    const user = userEvent.setup();
    setMediaCapabilities({ touch: true, reducedMotion: false });
    renderTable([
      {
        type: "file",
        name: "clip.mp4",
        path: "/clip.mp4",
        preview_kind: "video",
        preview_status: "ready",
        poster_url: "https://cdn.example/clip.webp",
        hover_preview_url: "https://cdn.example/clip-preview.mp4",
      },
    ]);

    const trigger = screen.getByLabelText("Video preview for clip.mp4");
    expect(screen.queryByLabelText("Video hover preview")).not.toBeInTheDocument();

    await user.hover(trigger);
    expect(screen.queryByLabelText("Video hover preview")).not.toBeInTheDocument();

    await user.click(trigger);
    expect(screen.getByLabelText("Video hover preview")).toBeInTheDocument();
  });
});
