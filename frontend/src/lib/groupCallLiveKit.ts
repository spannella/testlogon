/**
 * groupCallLiveKit — browser LiveKit media leg for group calls (GAP-0017-sfu).
 *
 * The group-call BACKEND mints a real LiveKit video-grant JWT
 * (`GET /ui/calls/group/{id}/livekit-token`); `useGroupCall` fetches it and,
 * when `sfu_provider==="livekit"`, hands the {url,token} to this helper which
 * owns the real `Room.connect` + publish + subscribe against the SAME LiveKit
 * SFU the audio rooms use. This replaces the SEAM (token-real, media-not-wired)
 * with real media flow.
 *
 * The LiveKit participant *identity* is the platform `user_id` (see the token
 * endpoint `.with_identity(str(uid))`), so remote tracks map 1:1 onto the
 * participant tiles the overlay renders (keyed by user_id).
 *
 * We expose remote media as plain `MediaStream`s keyed by user_id so the LiveKit
 * path reuses the exact same {localStream, remoteStreams} contract the mesh path
 * already exposes — the overlay renders both identically. The mesh
 * RTCPeerConnection path is untouched and remains the fallback when LiveKit is
 * not configured (mode:mesh / 503 token).
 */
import {
  Room,
  RoomEvent,
  Track,
  ConnectionState,
  type RemoteParticipant,
  type RemoteTrack,
  type RemoteTrackPublication,
} from "livekit-client";

export type LiveKitPhase =
  | "connecting"
  | "connected"
  | "reconnecting"
  | "disconnected"
  | "failed";

export interface LiveKitCallbacks {
  /** Remote participant media changed — stream is keyed by participant identity (user_id). */
  onRemoteStream: (identity: string, stream: MediaStream | null) => void;
  /** Connection phase changed (drives sfuStatus connecting→connected). */
  onPhase: (phase: LiveKitPhase) => void;
}

export interface LiveKitInitialMedia {
  audio: boolean;
  video: boolean;
}

/**
 * Connect to the LiveKit room, publish local mic/camera per the current
 * mute/camera state, and forward remote tracks to the caller. Returns a handle
 * to toggle media / screen-share and disconnect.
 */
export async function connectGroupCallLiveKit(
  url: string,
  token: string,
  initial: LiveKitInitialMedia,
  cb: LiveKitCallbacks,
): Promise<GroupCallLiveKitSession> {
  const room = new Room({
    adaptiveStream: true,
    dynacast: true,
  });

  // Per-remote-participant MediaStream, keyed by identity (== user_id).
  const remoteStreams = new Map<string, MediaStream>();

  const streamFor = (identity: string): MediaStream => {
    let s = remoteStreams.get(identity);
    if (!s) {
      s = new MediaStream();
      remoteStreams.set(identity, s);
    }
    return s;
  };

  const attach = (
    track: RemoteTrack,
    participant: RemoteParticipant,
  ) => {
    const mt = track.mediaStreamTrack;
    if (!mt) return;
    const stream = streamFor(participant.identity);
    // Replace any existing track of the same kind (camera swap, republish).
    for (const existing of stream.getTracks()) {
      if (existing.kind === mt.kind) stream.removeTrack(existing);
    }
    stream.addTrack(mt);
    cb.onRemoteStream(participant.identity, stream);
  };

  const detach = (
    track: RemoteTrack,
    participant: RemoteParticipant,
  ) => {
    const stream = remoteStreams.get(participant.identity);
    if (!stream) return;
    const mt = track.mediaStreamTrack;
    if (mt) stream.removeTrack(mt);
    if (stream.getTracks().length === 0) {
      remoteStreams.delete(participant.identity);
      cb.onRemoteStream(participant.identity, null);
    } else {
      cb.onRemoteStream(participant.identity, stream);
    }
  };

  const dropParticipant = (participant: RemoteParticipant) => {
    if (remoteStreams.has(participant.identity)) {
      remoteStreams.delete(participant.identity);
      cb.onRemoteStream(participant.identity, null);
    }
  };

  room
    .on(RoomEvent.TrackSubscribed, (track, _pub: RemoteTrackPublication, participant) => {
      if (track.kind === Track.Kind.Audio || track.kind === Track.Kind.Video) {
        attach(track, participant);
      }
    })
    .on(RoomEvent.TrackUnsubscribed, (track, _pub, participant) => {
      detach(track, participant);
    })
    .on(RoomEvent.ParticipantDisconnected, (participant) => {
      dropParticipant(participant);
    })
    .on(RoomEvent.ConnectionStateChanged, (state) => {
      switch (state) {
        case ConnectionState.Connecting:
          cb.onPhase("connecting");
          break;
        case ConnectionState.Connected:
          cb.onPhase("connected");
          break;
        case ConnectionState.Reconnecting:
          cb.onPhase("reconnecting");
          break;
        case ConnectionState.Disconnected:
          cb.onPhase("disconnected");
          break;
        default:
          break;
      }
    })
    .on(RoomEvent.Disconnected, () => {
      cb.onPhase("disconnected");
    });

  await room.connect(url, token);

  // Publish local media honoring the call's current mute/camera state.
  try {
    if (initial.audio) await room.localParticipant.setMicrophoneEnabled(true);
    if (initial.video) await room.localParticipant.setCameraEnabled(true);
  } catch {
    // Publish failure (no devices / denied permission) is non-fatal — the
    // participant stays receive-only, mirroring the mesh path's tolerance.
  }

  return new GroupCallLiveKitSession(room);
}

/** Live handle over a connected LiveKit room. */
export class GroupCallLiveKitSession {
  constructor(private readonly room: Room) {}

  async setMicrophoneEnabled(enabled: boolean): Promise<void> {
    try {
      await this.room.localParticipant.setMicrophoneEnabled(enabled);
    } catch {
      /* device/permission errors are non-fatal */
    }
  }

  async setCameraEnabled(enabled: boolean): Promise<void> {
    try {
      await this.room.localParticipant.setCameraEnabled(enabled);
    } catch {
      /* device/permission errors are non-fatal */
    }
  }

  async setScreenShareEnabled(enabled: boolean): Promise<void> {
    try {
      await this.room.localParticipant.setScreenShareEnabled(enabled);
    } catch {
      /* screen-share grant/cancel errors are non-fatal */
    }
  }

  /** Local camera stream for the self-tile (null when camera is off). */
  localCameraStream(): MediaStream | null {
    const pub = this.room.localParticipant.getTrackPublication(Track.Source.Camera);
    const mt = pub?.track?.mediaStreamTrack;
    if (!mt) return null;
    return new MediaStream([mt]);
  }

  async disconnect(): Promise<void> {
    try {
      await this.room.disconnect();
    } catch {
      /* already disconnected */
    }
  }
}
