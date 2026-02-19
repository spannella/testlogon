import { describe, expect, it } from "vitest";
import { isEditableImageFile, normalizeRect } from "../imageEdit";

describe("imageEdit helpers", () => {
  it("accepts image files by mime or extension and rejects encrypted/non-images", () => {
    expect(isEditableImageFile({ type: "file", name: "photo.bin", path: "/photo.bin", content_type: "image/png", is_encrypted: false })).toBe(true);
    expect(isEditableImageFile({ type: "file", name: "photo.JPG", path: "/photo.JPG", content_type: "", is_encrypted: false })).toBe(true);
    expect(isEditableImageFile({ type: "file", name: "secret.png", path: "/secret.png", content_type: "image/png", is_encrypted: true })).toBe(false);
    expect(isEditableImageFile({ type: "folder", name: "pics", path: "/pics/", content_type: "", is_encrypted: false })).toBe(false);
    expect(isEditableImageFile({ type: "file", name: "notes.txt", path: "/notes.txt", content_type: "text/plain", is_encrypted: false })).toBe(false);
  });

  it("normalizes drag rect into positive bounded dimensions", () => {
    expect(normalizeRect({ x: 80, y: 40 }, { x: 10, y: 5 }, 100, 80)).toEqual({ x: 10, y: 5, w: 70, h: 35 });
    expect(normalizeRect({ x: -20, y: -5 }, { x: 120, y: 90 }, 100, 80)).toEqual({ x: 0, y: 0, w: 100, h: 80 });
  });
});
