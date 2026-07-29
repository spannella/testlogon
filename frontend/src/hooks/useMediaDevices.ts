/**
 * useMediaDevices — enumerates available audio/video input and audio output
 * devices, re-enumerating on the `devicechange` event (hot-plug).
 *
 * Note: Device labels are empty strings until the user grants getUserMedia
 * permission at least once. Call `refresh()` after a successful getUserMedia
 * to populate labels.
 */
import * as React from "react";

export interface MediaDeviceEntry {
  deviceId: string;
  label: string;
  kind: "audioinput" | "videoinput" | "audiooutput";
  groupId: string;
}

export interface UseMediaDevicesReturn {
  audioInputs: MediaDeviceEntry[];
  videoInputs: MediaDeviceEntry[];
  audioOutputs: MediaDeviceEntry[];
  selectedAudioInput: string | null;
  selectedVideoInput: string | null;
  selectAudioInput: (deviceId: string) => void;
  selectVideoInput: (deviceId: string) => void;
  refresh: () => Promise<void>;
}

export function useMediaDevices(): UseMediaDevicesReturn {
  const [devices, setDevices] = React.useState<MediaDeviceEntry[]>([]);
  const [selectedAudioInput, setSelectedAudioInput] = React.useState<
    string | null
  >(null);
  const [selectedVideoInput, setSelectedVideoInput] = React.useState<
    string | null
  >(null);

  const enumerate = React.useCallback(async () => {
    if (
      typeof navigator === "undefined" ||
      !navigator.mediaDevices?.enumerateDevices
    ) {
      return;
    }
    try {
      const list = await navigator.mediaDevices.enumerateDevices();
      const mapped: MediaDeviceEntry[] = list
        .filter(
          (d) =>
            d.kind === "audioinput" ||
            d.kind === "videoinput" ||
            d.kind === "audiooutput",
        )
        .map((d) => ({
          deviceId: d.deviceId,
          label: d.label || `${d.kind} (${d.deviceId.slice(0, 8)})`,
          kind: d.kind as MediaDeviceEntry["kind"],
          groupId: d.groupId,
        }));
      setDevices(mapped);
    } catch {
      // enumerateDevices can fail in restricted contexts
    }
  }, []);

  // Enumerate on mount and listen for device changes
  React.useEffect(() => {
    enumerate();

    if (
      typeof navigator !== "undefined" &&
      navigator.mediaDevices?.addEventListener
    ) {
      const handler = () => {
        enumerate();
      };
      navigator.mediaDevices.addEventListener("devicechange", handler);
      return () => {
        navigator.mediaDevices.removeEventListener("devicechange", handler);
      };
    }
  }, [enumerate]);

  const audioInputs = React.useMemo(
    () => devices.filter((d) => d.kind === "audioinput" && !!d.deviceId),
    [devices],
  );
  const videoInputs = React.useMemo(
    () => devices.filter((d) => d.kind === "videoinput" && !!d.deviceId),
    [devices],
  );
  const audioOutputs = React.useMemo(
    () => devices.filter((d) => d.kind === "audiooutput" && !!d.deviceId),
    [devices],
  );

  return {
    audioInputs,
    videoInputs,
    audioOutputs,
    selectedAudioInput,
    selectedVideoInput,
    selectAudioInput: setSelectedAudioInput,
    selectVideoInput: setSelectedVideoInput,
    refresh: enumerate,
  };
}
