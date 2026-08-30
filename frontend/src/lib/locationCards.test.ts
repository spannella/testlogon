import { describe, expect, it } from "vitest";
import {
  directionsUrl,
  formatCoords,
  geoUri,
  isValidLatLng,
  locationPreview,
  mapsOpenUrl,
  staticMapThumbUrl,
} from "./locationCards";

const SF = { lat: 37.7749, lng: -122.4194 };

describe("isValidLatLng", () => {
  it("accepts a normal coordinate", () => {
    expect(isValidLatLng(SF.lat, SF.lng)).toBe(true);
  });
  it("accepts the boundary values", () => {
    expect(isValidLatLng(-90, -180)).toBe(true);
    expect(isValidLatLng(90, 180)).toBe(true);
    expect(isValidLatLng(0, 0)).toBe(true);
  });
  it("rejects out-of-range latitude", () => {
    expect(isValidLatLng(90.1, 0)).toBe(false);
    expect(isValidLatLng(-91, 0)).toBe(false);
  });
  it("rejects out-of-range longitude", () => {
    expect(isValidLatLng(0, 180.1)).toBe(false);
    expect(isValidLatLng(0, -181)).toBe(false);
  });
  it("rejects non-finite values", () => {
    expect(isValidLatLng(NaN, 0)).toBe(false);
    expect(isValidLatLng(0, Infinity)).toBe(false);
  });
  it("rejects non-number values", () => {
    expect(isValidLatLng("37", "-122")).toBe(false);
    expect(isValidLatLng(undefined, null)).toBe(false);
  });
});

describe("formatCoords", () => {
  it("formats to fixed 5 decimals", () => {
    expect(formatCoords(SF.lat, SF.lng)).toBe("37.77490, -122.41940");
  });
  it("rounds and pads", () => {
    expect(formatCoords(1, -2)).toBe("1.00000, -2.00000");
  });
});

describe("mapsOpenUrl", () => {
  it("builds a universal search link with coords when no label", () => {
    const url = mapsOpenUrl(SF.lat, SF.lng);
    expect(url).toContain("https://www.google.com/maps/search/?api=1&query=");
    expect(url).toContain(encodeURIComponent("37.7749,-122.4194"));
  });
  it("includes the label in the query when supplied", () => {
    const url = mapsOpenUrl(SF.lat, SF.lng, "The Cafe");
    expect(url).toContain(encodeURIComponent("The Cafe"));
    expect(url).toContain(encodeURIComponent("37.7749,-122.4194"));
  });
  it("ignores a blank label", () => {
    const url = mapsOpenUrl(SF.lat, SF.lng, "   ");
    expect(url).toBe(mapsOpenUrl(SF.lat, SF.lng));
  });
});

describe("directionsUrl", () => {
  it("builds a directions link with the destination", () => {
    const url = directionsUrl(SF.lat, SF.lng);
    expect(url).toContain("https://www.google.com/maps/dir/?api=1&destination=");
    expect(url).toContain(encodeURIComponent("37.7749,-122.4194"));
  });
});

describe("geoUri", () => {
  it("builds a geo: uri", () => {
    expect(geoUri(SF.lat, SF.lng)).toBe("geo:37.7749,-122.4194");
  });
});

describe("staticMapThumbUrl", () => {
  it("uses keyless OSM static map with a marker and defaults", () => {
    const url = staticMapThumbUrl(SF.lat, SF.lng);
    expect(url).toContain("staticmap.openstreetmap.de/staticmap.php");
    expect(url).toContain(`center=${SF.lat},${SF.lng}`);
    expect(url).toContain(`markers=${SF.lat},${SF.lng},red`);
    expect(url).toContain("size=320x160");
    expect(url).toContain("zoom=15");
  });
  it("honours custom size and zoom", () => {
    const url = staticMapThumbUrl(SF.lat, SF.lng, { w: 200, h: 100, zoom: 12 });
    expect(url).toContain("size=200x100");
    expect(url).toContain("zoom=12");
  });
  it("carries no api key", () => {
    expect(staticMapThumbUrl(SF.lat, SF.lng).toLowerCase()).not.toContain("key=");
  });
});

describe("locationPreview", () => {
  it("uses the label when present", () => {
    expect(locationPreview("Home")).toBe("📍 Home");
  });
  it("falls back to place name", () => {
    expect(locationPreview(undefined, "1 Market St")).toBe("📍 1 Market St");
  });
  it("falls back to a generic label", () => {
    expect(locationPreview()).toBe("📍 Location");
    expect(locationPreview("   ", "  ")).toBe("📍 Location");
  });
});
