import { describe, it, expect } from "vitest";
import {
  providerMeta,
  mountStatusBadge,
  validateMountConfig,
  buildCreateBody,
  validateRotateCredential,
  canTestMount,
  SUPPORTED_PROVIDERS,
} from "./mountConfig";

describe("providerMeta", () => {
  it("labels sftp as a host-based provider", () => {
    const m = providerMeta("sftp");
    expect(m.label).toMatch(/SFTP/);
    expect(m.hostBased).toBe(true);
  });

  it("labels cloud object providers as non-host-based", () => {
    expect(providerMeta("drive").hostBased).toBe(false);
    expect(providerMeta("onedrive").hostBased).toBe(false);
    expect(providerMeta("s3").hostBased).toBe(false);
  });

  it("falls back for unknown providers", () => {
    expect(providerMeta("nope").label).toBe("Mount");
    expect(providerMeta(null).iconKey).toBe("s3");
  });

  it("exposes all supported providers", () => {
    expect(SUPPORTED_PROVIDERS).toEqual(["sftp", "drive", "onedrive", "s3"]);
  });
});

describe("mountStatusBadge", () => {
  it("maps healthy/active to success", () => {
    expect(mountStatusBadge("healthy").severity).toBe("success");
    expect(mountStatusBadge("active").severity).toBe("success");
  });
  it("maps failures to danger", () => {
    expect(mountStatusBadge("auth_failed").severity).toBe("danger");
    expect(mountStatusBadge("unreachable").severity).toBe("danger");
    expect(mountStatusBadge("error").severity).toBe("danger");
  });
  it("maps degraded to warning and disabled to neutral", () => {
    expect(mountStatusBadge("degraded").severity).toBe("warning");
    expect(mountStatusBadge("disabled").severity).toBe("neutral");
  });
  it("falls back to neutral for unknown/empty", () => {
    expect(mountStatusBadge(undefined).severity).toBe("neutral");
    expect(mountStatusBadge("weird").label).toBe("weird");
  });
});

describe("validateMountConfig — sftp", () => {
  const good = {
    provider: "sftp",
    host: "sftp.example.com",
    port: 22,
    remote_root: "/home/u",
    auth_credential_ref: "cred#1",
    protocol: "sftp",
  };

  it("accepts a complete sftp config", () => {
    expect(validateMountConfig(good).ok).toBe(true);
  });

  it("requires host, remote_root, and credential ref", () => {
    const res = validateMountConfig({ provider: "sftp", port: 22 });
    const fields = res.errors.map((e) => e.field);
    expect(res.ok).toBe(false);
    expect(fields).toEqual(expect.arrayContaining(["host", "remote_root", "auth_credential_ref"]));
  });

  it("rejects an out-of-range port", () => {
    const res = validateMountConfig({ ...good, port: 70000 });
    expect(res.ok).toBe(false);
    expect(res.errors.some((e) => e.field === "port")).toBe(true);
  });

  it("rejects a non-integer / missing port", () => {
    expect(validateMountConfig({ ...good, port: "abc" }).ok).toBe(false);
    expect(validateMountConfig({ ...good, port: "" }).ok).toBe(false);
  });

  it("rejects an unsupported protocol", () => {
    const res = validateMountConfig({ ...good, protocol: "http" });
    expect(res.errors.some((e) => e.field === "protocol")).toBe(true);
  });
});

describe("validateMountConfig — s3/drive/onedrive", () => {
  const good = {
    provider: "s3" as const,
    mount_path: "/cloud/a",
    bucket: "my-bucket",
    auth_ref: "secret#1",
    mode: "read_only",
  };

  it("accepts a complete object-store config", () => {
    expect(validateMountConfig(good).ok).toBe(true);
    expect(validateMountConfig({ ...good, provider: "drive" }).ok).toBe(true);
    expect(validateMountConfig({ ...good, provider: "onedrive" }).ok).toBe(true);
  });

  it("requires a mount_path, bucket, and auth_ref", () => {
    const res = validateMountConfig({ provider: "drive" });
    const fields = res.errors.map((e) => e.field);
    expect(fields).toEqual(expect.arrayContaining(["mount_path", "bucket", "auth_ref"]));
  });

  it("rejects a too-short bucket name", () => {
    const res = validateMountConfig({ ...good, bucket: "ab" });
    expect(res.errors.some((e) => e.field === "bucket")).toBe(true);
  });

  it("rejects an invalid mode", () => {
    const res = validateMountConfig({ ...good, mode: "sideways" });
    expect(res.errors.some((e) => e.field === "mode")).toBe(true);
  });
});

describe("validateMountConfig — provider gate", () => {
  it("rejects an unknown provider", () => {
    const res = validateMountConfig({ provider: "dropbox" });
    expect(res.ok).toBe(false);
    expect(res.errors.some((e) => e.field === "provider")).toBe(true);
  });
});

describe("buildCreateBody", () => {
  it("builds the sftp body with defaults", () => {
    const body = buildCreateBody({
      provider: "sftp",
      host: " h ",
      remote_root: "/r",
      auth_credential_ref: " c ",
    });
    expect(body).toMatchObject({
      protocol: "sftp",
      host: "h",
      port: 22,
      remote_root: "/r",
      auth_credential_ref: "c",
      read_only: false,
    });
  });

  it("builds the object-store body with null prefix when empty", () => {
    const body = buildCreateBody({
      provider: "drive",
      mount_path: "/d",
      bucket: "bkt-name",
      auth_ref: "s",
    });
    expect(body).toMatchObject({
      mount_path: "/d",
      bucket: "bkt-name",
      prefix: null,
      auth_ref: "s",
      status: "active",
    });
  });

  it("defaults mode from read_only flag", () => {
    expect(buildCreateBody({ provider: "s3", read_only: true }).mode).toBe("read_only");
    expect(buildCreateBody({ provider: "s3", read_only: false }).mode).toBe("read_write");
  });
});

describe("validateRotateCredential", () => {
  it("accepts password mode with a password", () => {
    expect(
      validateRotateCredential({ auth_mode: "password", username: "u", password: "p" }).ok,
    ).toBe(true);
  });
  it("accepts private_key mode with a key", () => {
    expect(
      validateRotateCredential({ auth_mode: "private_key", username: "u", private_key: "KEY" }).ok,
    ).toBe(true);
  });
  it("requires a password in password mode", () => {
    const res = validateRotateCredential({ auth_mode: "password", username: "u" });
    expect(res.errors.some((e) => e.field === "password")).toBe(true);
  });
  it("requires a key in private_key mode", () => {
    const res = validateRotateCredential({ auth_mode: "private_key", username: "u" });
    expect(res.errors.some((e) => e.field === "private_key")).toBe(true);
  });
  it("rejects a bad auth_mode and missing username", () => {
    const res = validateRotateCredential({ auth_mode: "biometric" });
    const fields = res.errors.map((e) => e.field);
    expect(fields).toEqual(expect.arrayContaining(["auth_mode", "username"]));
  });
});

describe("canTestMount", () => {
  it("is true only for sftp", () => {
    expect(canTestMount("sftp")).toBe(true);
    expect(canTestMount("drive")).toBe(false);
    expect(canTestMount(null)).toBe(false);
  });
});
