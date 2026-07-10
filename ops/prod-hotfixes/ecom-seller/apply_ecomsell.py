"""ECOM-SELLER (G1-G4) idempotent apply: per-seller ship-groups + seller-scoped
sales endpoint + "you sold it" notify + G4 real line names + new DDB table.

Idempotent + anchored (works on divergent prod AND dev clone). ROOT env selects
the tree (default /home/ubuntu/testlogon); set ROOT=/tmp/probe_ecomsell to probe.
"""
import base64, os, sys, py_compile

ROOT = os.environ.get("ROOT", "/home/ubuntu/testlogon")
PROBE = os.environ.get("PROBE", "0") == "1"

SVC_B64 = "IiIiRUNPTS1TRUxMRVIgKEcxLUc0KSAtIHBlci1zZWxsZXIgc2hpcCBncm91cHMgKyBzZWxsZXItc2NvcGVkIGZ1bGZpbG1lbnQuCgpPbiBvcmRlciBBUFBST1ZBTCAocGF5bWVudCBjYXB0dXJlZCkgd2Ugc3BsaXQgdGhlIGJ1eWVyJ3MgY2FydCBpbnRvIG9uZQoqc2VsbGVyIHNoaXAgZ3JvdXAqIHBlciBkaXN0aW5jdCBzZWxsZXIgKGNhdGFsb2ctaXRlbSBvd25lcikuIEVhY2ggZ3JvdXAgY2FycmllcwpPTkxZIHRoYXQgc2VsbGVyJ3MgbGluZSBpdGVtcyAod2l0aCB0aGUgUkVBTCBwcm9kdWN0IG5hbWUgKyBxdHkgKyB1bml0IHByaWNlKSwKdGhlIGJ1eWVyJ3Mgc2hpcHBpbmcgYWRkcmVzcywgYW5kIHRoZSBidXllcidzIGRpc3BsYXkgbmFtZS9lbWFpbCAtIG5ldmVyIGFueQpvdGhlciBzZWxsZXIncyBpdGVtcyBhbmQgbmV2ZXIgdGhlIGJ1eWVyJ3MgcGF5bWVudCBpbnRlcm5hbHMuCgpBIG5vbi1hZG1pbiBzZWxsZXIgdGhlbiBsaXN0cyArIGZ1bGZpbHMgdGhlaXIgb3duIGdyb3VwcyAoYGAvdWkvc2VsbGVyL3NhbGVzYGApLAphZHZhbmNpbmcgdGhlIHNhbWUgb3JkZXItbGlmZWN5Y2xlIHN0YXRlIG1hY2hpbmUgc2NvcGVkIHRvIHRoZWlyIGdyb3VwLiBFYWNoCnNlbGxlciBpcyBub3RpZmllZCAoInlvdSBzb2xkIGl0IikgdmlhIGluLWFwcCBhbGVydCArIEZDTSBwdXNoIG9uIGdyb3VwIGNyZWF0aW9uLgoKU3RvcmFnZTogdGFibGUgYGBzZWxsZXJfc2hpcF9ncm91cHNgYCAtIFBLIGBgc2VsbGVyX2lkYGAgLyBTSyBgYHNoaXBfZ3JvdXBfaWRgYAooZGV0ZXJtaW5pc3RpYyBgYHNoYTEob3JkZXJfaWQjc2VsbGVyX2lkKWBgIC0+IGlkZW1wb3RlbnQgcmUtYXBwcm92YWwpLCBHU0kKYGBHU0lfT1JERVJgYCAocGFydGl0aW9uIGBgb3JkZXJfaWRgYCkgZm9yIHBlci1vcmRlciAobXVsdGktc2VsbGVyKSBsaXN0aW5nLgoiIiIKZnJvbSBfX2Z1dHVyZV9fIGltcG9ydCBhbm5vdGF0aW9ucwoKaW1wb3J0IGhhc2hsaWIKaW1wb3J0IGxvZ2dpbmcKaW1wb3J0IHRpbWUKZnJvbSB0eXBpbmcgaW1wb3J0IEFueSwgRGljdCwgTGlzdCwgT3B0aW9uYWwsIFR1cGxlCgpmcm9tIGJvdG8zLmR5bmFtb2RiLmNvbmRpdGlvbnMgaW1wb3J0IEtleQoKZnJvbSBhcHAuY29yZS5zZXR0aW5ncyBpbXBvcnQgUwpmcm9tIGFwcC5jb3JlLnRhYmxlcyBpbXBvcnQgVAoKbG9nZ2VyID0gbG9nZ2luZy5nZXRMb2dnZXIoX19uYW1lX18pCgojIFRoZSBzZWxsZXIgc2hpcC1ncm91cCBzdGF0dXMgZm9sbG93cyB0aGUgY2Fub25pY2FsIG9yZGVyLWxpZmVjeWNsZSBzdGF0ZQojIG1hY2hpbmU7IGEgZ3JvdXAgaXMgYm9ybiAiYXBwcm92ZWQiICh0aGUgb3JkZXIgaXMgcGFpZCkgYW5kIHRoZSBzZWxsZXIgZHJpdmVzCiMgaXQgYXBwcm92ZWQgLT4gYWxsb2NhdGVkIC0+IHBpY2tpbmcgLT4gcGFja2VkIC0+IHNoaXBwZWQuCl9TVEFSVF9TVEFUVVMgPSAiYXBwcm92ZWQiCgoKZGVmIF9ub3coKSAtPiBpbnQ6CiAgICByZXR1cm4gaW50KHRpbWUudGltZSgpKQoKCmRlZiBfc2dfaWQob3JkZXJfaWQ6IHN0ciwgc2VsbGVyX2lkOiBzdHIpIC0+IHN0cjoKICAgIHJldHVybiBoYXNobGliLnNoYTEoZiJ7b3JkZXJfaWR9I3tzZWxsZXJfaWR9Ii5lbmNvZGUoInV0Zi04IikpLmhleGRpZ2VzdCgpWzozMl0KCgpkZWYgX3NlbGxlcl9vZihpdGVtOiBEaWN0W3N0ciwgQW55XSkgLT4gc3RyOgogICAgcmV0dXJuIHN0cihpdGVtLmdldCgiY3JlYXRvcl91c2VyX2lkIikgb3IgaXRlbS5nZXQoInNlbGxlcl9pZCIpIG9yICIiKS5zdHJpcCgpCgoKZGVmIF90cmFuc2l0aW9ucygpIC0+IERpY3Rbc3RyLCBBbnldOgogICAgZnJvbSBhcHAuc2VydmljZXMub3JkZXJfbGlmZWN5Y2xlIGltcG9ydCBUUkFOU0lUSU9OUwogICAgcmV0dXJuIFRSQU5TSVRJT05TCgoKZGVmIGFsbG93ZWRfdHJhbnNpdGlvbnMoc3RhdHVzOiBzdHIpIC0+IExpc3Rbc3RyXToKICAgIHJldHVybiBzb3J0ZWQoX3RyYW5zaXRpb25zKCkuZ2V0KHN0cihzdGF0dXMgb3IgIiIpLCBzZXQoKSkpCgoKIyAtLSBidXllciBzaGlwcGluZyBhZGRyZXNzIC0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLQoKZGVmIF9yZXNvbHZlX3NoaXBfdG8oYnV5ZXI6IE9wdGlvbmFsW0RpY3Rbc3RyLCBBbnldXSwgYnV5ZXJfc3ViOiBzdHIpIC0+IERpY3Rbc3RyLCBBbnldOgogICAgIiIiQnV5ZXIgc2hpcHBpbmcgYWRkcmVzczogcHJlZmVyIHRoZSBwcm9maWxlIG1haWxpbmdfYWRkcmVzcyBlY2hvZWQgb24gdGhlCiAgICBwdXJjaGFzZTsgZmFsbCBiYWNrIHRvIHRoZSBidXllcidzIHByaW1hcnkgc2F2ZWQgYWRkcmVzcyAoL3VpL2FkZHJlc3NlcykuIiIiCiAgICBidXllciA9IGJ1eWVyIG9yIHt9CiAgICBhZGRyID0gYnV5ZXIuZ2V0KCJtYWlsaW5nX2FkZHJlc3MiKQogICAgaWYgaXNpbnN0YW5jZShhZGRyLCBkaWN0KSBhbmQgYW55KHYgZm9yIHYgaW4gYWRkci52YWx1ZXMoKSk6CiAgICAgICAgcmV0dXJuIGRpY3QoYWRkcikKICAgIHRyeToKICAgICAgICBmcm9tIGFwcC5zZXJ2aWNlcy5hZGRyZXNzZXMgaW1wb3J0IGxpc3RfYWRkcmVzc2VzCiAgICAgICAgcm93cyA9IGxpc3RfYWRkcmVzc2VzKGJ1eWVyX3N1Yikgb3IgW10KICAgICAgICBwcmltYXJ5ID0gbmV4dCgociBmb3IgciBpbiByb3dzIGlmIHIuZ2V0KCJpc19wcmltYXJ5Iikgb3Igci5nZXQoInByaW1hcnkiKSksIE5vbmUpCiAgICAgICAgY2hvc2VuID0gcHJpbWFyeSBvciAocm93c1swXSBpZiByb3dzIGVsc2UgTm9uZSkKICAgICAgICBpZiBjaG9zZW46CiAgICAgICAgICAgIHJldHVybiB7azogdiBmb3IgaywgdiBpbiBjaG9zZW4uaXRlbXMoKSBpZiBrIG5vdCBpbiAoInVzZXJfc3ViIiwpIGFuZCB2IGlzIG5vdCBOb25lfQogICAgZXhjZXB0IEV4Y2VwdGlvbjoKICAgICAgICBsb2dnZXIuZXhjZXB0aW9uKCJzaGlwX3RvIGFkZHJlc3MgZmFsbGJhY2sgZmFpbGVkIGZvciBidXllciAlcyIsIGJ1eWVyX3N1YikKICAgIHJldHVybiB7fQoKCiMgLS0gRzQ6IGJhY2tmaWxsIHRoZSByZWFsIHByb2R1Y3QgbmFtZSBvbnRvIHRoZSBvcmRlciBsaW5lLWl0ZW0gcm93cyAtLS0tLS0tLS0KCmRlZiBfYmFja2ZpbGxfb3JkZXJfaXRlbV9uYW1lcyhvcmRlcl9pZDogc3RyLCBjYXJ0X2l0ZW1zOiBMaXN0W0RpY3Rbc3RyLCBBbnldXSkgLT4gTm9uZToKICAgICIiIlRoZSBjYXJ0LT5vcmRlciBsaW5lIHJvd3MgYXJlIHNlZWRlZCB3aXRoIHRoZSBpbnRlcm5hbCBwcm9kdWN0X3R5cGUKICAgIChgYGludGVybmFsX2FwaV9wYWNrYWdlYGApIGFuZCBubyBgYG5hbWVgYC4gQmFja2ZpbGwgZWFjaCByb3cncyByZWFsIGNhdGFsb2cKICAgIG5hbWUgKyBzZWxsZXJfaWQgZnJvbSB0aGUgbWF0Y2hpbmcgY2FydCBpdGVtIHNvIHRoZSBvcmRlciBsaW5lIChidXllciBkZXRhaWwKICAgIEFORCBzZWxsZXIgc2FsZSkgc2hvd3MgdGhlIHJlYWwgcHJvZHVjdCBuYW1lLiBNYXRjaCBieSBza3UsIGluZGV4IGZhbGxiYWNrLiIiIgogICAgdHJ5OgogICAgICAgIHJlc3AgPSBULm9yZGVyX2l0ZW1zLnF1ZXJ5KEtleUNvbmRpdGlvbkV4cHJlc3Npb249S2V5KCJvcmRlcl9pZCIpLmVxKG9yZGVyX2lkKSkKICAgICAgICByb3dzID0gc29ydGVkKHJlc3AuZ2V0KCJJdGVtcyIsIFtdKSwga2V5PWxhbWJkYSByOiBpbnQoc3RyKHIuZ2V0KCJpdGVtX2lkIikgb3IgIjAiKSBvciAwKSkKICAgIGV4Y2VwdCBFeGNlcHRpb246CiAgICAgICAgbG9nZ2VyLmV4Y2VwdGlvbigiYmFja2ZpbGw6IGNvdWxkIG5vdCBsb2FkIG9yZGVyX2l0ZW1zIGZvciAlcyIsIG9yZGVyX2lkKQogICAgICAgIHJldHVybgogICAgYnlfc2t1ID0ge3N0cihjaS5nZXQoInNrdSIpKTogY2kgZm9yIGNpIGluIGNhcnRfaXRlbXMgaWYgY2kuZ2V0KCJza3UiKX0KICAgIGZvciBpZHgsIHJvdyBpbiBlbnVtZXJhdGUocm93cyk6CiAgICAgICAgY2kgPSBieV9za3UuZ2V0KHN0cihyb3cuZ2V0KCJza3UiKSkpIG9yIChjYXJ0X2l0ZW1zW2lkeF0gaWYgaWR4IDwgbGVuKGNhcnRfaXRlbXMpIGVsc2UgTm9uZSkKICAgICAgICBpZiBub3QgY2k6CiAgICAgICAgICAgIGNvbnRpbnVlCiAgICAgICAgbmFtZSA9IGNpLmdldCgibmFtZSIpCiAgICAgICAgc2VsbGVyID0gX3NlbGxlcl9vZihjaSkKICAgICAgICBpZiBub3QgbmFtZSBhbmQgbm90IHNlbGxlcjoKICAgICAgICAgICAgY29udGludWUKICAgICAgICBzZXRfcGFydHMsIHZhbHMsIG5hbWVzID0gW10sIHt9LCB7fQogICAgICAgIGlmIG5hbWU6CiAgICAgICAgICAgIHNldF9wYXJ0cy5hcHBlbmQoIiNubSA9IDpubSIpOyB2YWxzWyI6bm0iXSA9IHN0cihuYW1lKTsgbmFtZXNbIiNubSJdID0gIm5hbWUiCiAgICAgICAgaWYgc2VsbGVyOgogICAgICAgICAgICBzZXRfcGFydHMuYXBwZW5kKCJzZWxsZXJfaWQgPSA6c2lkIik7IHZhbHNbIjpzaWQiXSA9IHNlbGxlcgogICAgICAgIHRyeToKICAgICAgICAgICAga3dhcmdzID0gewogICAgICAgICAgICAgICAgIktleSI6IHsib3JkZXJfaWQiOiBvcmRlcl9pZCwgIml0ZW1faWQiOiBzdHIocm93LmdldCgiaXRlbV9pZCIpKX0sCiAgICAgICAgICAgICAgICAiVXBkYXRlRXhwcmVzc2lvbiI6ICJTRVQgIiArICIsICIuam9pbihzZXRfcGFydHMpLAogICAgICAgICAgICAgICAgIkV4cHJlc3Npb25BdHRyaWJ1dGVWYWx1ZXMiOiB2YWxzLAogICAgICAgICAgICB9CiAgICAgICAgICAgIGlmIG5hbWVzOgogICAgICAgICAgICAgICAga3dhcmdzWyJFeHByZXNzaW9uQXR0cmlidXRlTmFtZXMiXSA9IG5hbWVzCiAgICAgICAgICAgIFQub3JkZXJfaXRlbXMudXBkYXRlX2l0ZW0oKiprd2FyZ3MpCiAgICAgICAgZXhjZXB0IEV4Y2VwdGlvbjoKICAgICAgICAgICAgbG9nZ2VyLmV4Y2VwdGlvbigiYmFja2ZpbGwgbmFtZSBmYWlsZWQgZm9yIG9yZGVyICVzIGl0ZW0gJXMiLCBvcmRlcl9pZCwgcm93LmdldCgiaXRlbV9pZCIpKQoKCiMgLS0gcG9wdWxhdGUgb24gYXBwcm92YWwgLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0KCmRlZiBwb3B1bGF0ZV9vbl9hcHByb3ZhbCgKICAgICosCiAgICBvcmRlcl9pZDogc3RyLAogICAgYnV5ZXJfc3ViOiBzdHIsCiAgICBjYXJ0X2l0ZW1zOiBMaXN0W0RpY3Rbc3RyLCBBbnldXSwKICAgIGJ1eWVyOiBPcHRpb25hbFtEaWN0W3N0ciwgQW55XV0gPSBOb25lLAogICAgY3VycmVuY3k6IHN0ciA9ICJVU0QiLAopIC0+IExpc3RbRGljdFtzdHIsIEFueV1dOgogICAgIiIiU3BsaXQgdGhlIHBhaWQgb3JkZXIgaW50byBwZXItc2VsbGVyIHNoaXAgZ3JvdXBzIChpZGVtcG90ZW50KSArIG5vdGlmeQogICAgZWFjaCBORVcgc2VsbGVyLiBSZXR1cm5zIHRoZSBsaXN0IG9mIGNyZWF0ZWQgZ3JvdXAgcm93cy4iIiIKICAgIGlmIG5vdCBTLm9yZGVyX2xpZmVjeWNsZV9lbmFibGVkIG9yIG5vdCBvcmRlcl9pZDoKICAgICAgICByZXR1cm4gW10KCiAgICAjIEc0OiByZWFsIGxpbmUgbmFtZXMgb250byB0aGUgb3JkZXIgcm93cyBmaXJzdCAoYnV5ZXIgKyBzZWxsZXIgYm90aCBiZW5lZml0KS4KICAgIF9iYWNrZmlsbF9vcmRlcl9pdGVtX25hbWVzKG9yZGVyX2lkLCBjYXJ0X2l0ZW1zKQoKICAgIHNoaXBfdG8gPSBfcmVzb2x2ZV9zaGlwX3RvKGJ1eWVyLCBidXllcl9zdWIpCiAgICBidXllcl9uYW1lID0gc3RyKChidXllciBvciB7fSkuZ2V0KCJkaXNwbGF5X25hbWUiKSBvciBidXllcl9zdWIpCiAgICBidXllcl9lbWFpbCA9IHN0cigoYnV5ZXIgb3Ige30pLmdldCgiZGlzcGxheWVkX2VtYWlsIikgb3IgIiIpCgogICAgIyBncm91cCBjYXJ0IGxpbmUgaXRlbXMgYnkgc2VsbGVyIChza2lwIHNlbGYtcHVyY2hhc2VzICsgaXRlbXMgd2l0aCBubyBzZWxsZXIpCiAgICBieV9zZWxsZXI6IERpY3Rbc3RyLCBMaXN0W0RpY3Rbc3RyLCBBbnldXV0gPSB7fQogICAgZm9yIGNpIGluIGNhcnRfaXRlbXM6CiAgICAgICAgc2VsbGVyID0gX3NlbGxlcl9vZihjaSkKICAgICAgICBpZiBub3Qgc2VsbGVyIG9yIHNlbGxlciA9PSBidXllcl9zdWI6CiAgICAgICAgICAgIGNvbnRpbnVlCiAgICAgICAgcXR5ID0gaW50KGNpLmdldCgicXVhbnRpdHkiKSBvciAxKQogICAgICAgIHVuaXQgPSBpbnQoY2kuZ2V0KCJ1bml0X3ByaWNlX2NlbnRzIikgb3IgMCkKICAgICAgICBsaW5lX3RvdGFsID0gaW50KGNpLmdldCgibGluZV90b3RhbF9jZW50cyIpIG9yIChxdHkgKiB1bml0KSkKICAgICAgICBieV9zZWxsZXIuc2V0ZGVmYXVsdChzZWxsZXIsIFtdKS5hcHBlbmQoewogICAgICAgICAgICAiaXRlbV9pZCI6IHN0cihjaS5nZXQoIml0ZW1faWQiKSBvciBjaS5nZXQoInNrdSIpIG9yICIiKSwKICAgICAgICAgICAgInNrdSI6IHN0cihjaS5nZXQoInNrdSIpIG9yICIiKSwKICAgICAgICAgICAgIm5hbWUiOiBzdHIoY2kuZ2V0KCJuYW1lIikgb3IgIiIpLAogICAgICAgICAgICAicXVhbnRpdHkiOiBxdHksCiAgICAgICAgICAgICJ1bml0X3ByaWNlX2NlbnRzIjogdW5pdCwKICAgICAgICAgICAgImxpbmVfdG90YWxfY2VudHMiOiBsaW5lX3RvdGFsLAogICAgICAgIH0pCgogICAgY3JlYXRlZDogTGlzdFtEaWN0W3N0ciwgQW55XV0gPSBbXQogICAgbm93ID0gX25vdygpCiAgICBmb3Igc2VsbGVyLCBsaW5lcyBpbiBieV9zZWxsZXIuaXRlbXMoKToKICAgICAgICBzZ19pZCA9IF9zZ19pZChvcmRlcl9pZCwgc2VsbGVyKQogICAgICAgIHN1YnRvdGFsID0gc3VtKGludChsWyJsaW5lX3RvdGFsX2NlbnRzIl0pIGZvciBsIGluIGxpbmVzKQogICAgICAgIHJvdyA9IHsKICAgICAgICAgICAgInNlbGxlcl9pZCI6IHNlbGxlciwKICAgICAgICAgICAgInNoaXBfZ3JvdXBfaWQiOiBzZ19pZCwKICAgICAgICAgICAgIm9yZGVyX2lkIjogb3JkZXJfaWQsCiAgICAgICAgICAgICJidXllcl9pZCI6IGJ1eWVyX3N1YiwKICAgICAgICAgICAgImJ1eWVyX25hbWUiOiBidXllcl9uYW1lLAogICAgICAgICAgICAiYnV5ZXJfZW1haWwiOiBidXllcl9lbWFpbCwKICAgICAgICAgICAgInNoaXBfdG8iOiBzaGlwX3RvLAogICAgICAgICAgICAibGluZV9pdGVtcyI6IGxpbmVzLAogICAgICAgICAgICAiaXRlbV9jb3VudCI6IGxlbihsaW5lcyksCiAgICAgICAgICAgICJzdWJ0b3RhbF9jZW50cyI6IGludChzdWJ0b3RhbCksCiAgICAgICAgICAgICJjdXJyZW5jeSI6IHN0cihjdXJyZW5jeSBvciAiVVNEIikudXBwZXIoKSwKICAgICAgICAgICAgInN0YXR1cyI6IF9TVEFSVF9TVEFUVVMsCiAgICAgICAgICAgICJjcmVhdGVkX2F0Ijogbm93LAogICAgICAgICAgICAidXBkYXRlZF9hdCI6IG5vdywKICAgICAgICB9CiAgICAgICAgdHJ5OgogICAgICAgICAgICBULnNlbGxlcl9zaGlwX2dyb3Vwcy5wdXRfaXRlbSgKICAgICAgICAgICAgICAgIEl0ZW09cm93LAogICAgICAgICAgICAgICAgQ29uZGl0aW9uRXhwcmVzc2lvbj0iYXR0cmlidXRlX25vdF9leGlzdHMoc2hpcF9ncm91cF9pZCkiLAogICAgICAgICAgICApCiAgICAgICAgZXhjZXB0IEV4Y2VwdGlvbiBhcyBleGM6CiAgICAgICAgICAgIGNvZGUgPSAiIgogICAgICAgICAgICB0cnk6CiAgICAgICAgICAgICAgICBjb2RlID0gZXhjLnJlc3BvbnNlWyJFcnJvciJdWyJDb2RlIl0gICMgdHlwZTogaWdub3JlW2F0dHItZGVmaW5lZF0KICAgICAgICAgICAgZXhjZXB0IEV4Y2VwdGlvbjoKICAgICAgICAgICAgICAgIHBhc3MKICAgICAgICAgICAgaWYgY29kZSA9PSAiQ29uZGl0aW9uYWxDaGVja0ZhaWxlZEV4Y2VwdGlvbiI6CiAgICAgICAgICAgICAgICBjb250aW51ZSAgIyBhbHJlYWR5IGV4aXN0cyAoaWRlbXBvdGVudCByZXBsYXkpIC0gZG8gbm90IHJlLW5vdGlmeQogICAgICAgICAgICBsb2dnZXIuZXhjZXB0aW9uKCJmYWlsZWQgdG8gd3JpdGUgc2VsbGVyIHNoaXAgZ3JvdXAgJXMvJXMiLCBvcmRlcl9pZCwgc2VsbGVyKQogICAgICAgICAgICBjb250aW51ZQogICAgICAgIGNyZWF0ZWQuYXBwZW5kKHJvdykKICAgICAgICBfbm90aWZ5X3NlbGxlcihyb3cpCiAgICByZXR1cm4gY3JlYXRlZAoKCmRlZiBfbm90aWZ5X3NlbGxlcihyb3c6IERpY3Rbc3RyLCBBbnldKSAtPiBOb25lOgogICAgIiIiRzE6ICJ5b3Ugc29sZCBpdCIgaW4tYXBwIGFsZXJ0ICh3cml0ZV9hbGVydCkgKyBGQ00gcHVzaCB0byB0aGUgc2VsbGVyLAogICAgZGVlcC1saW5raW5nIHRvIHRoZWlyIHNhbGVzIHF1ZXVlLiIiIgogICAgc2VsbGVyID0gcm93WyJzZWxsZXJfaWQiXQogICAgc2dfaWQgPSByb3dbInNoaXBfZ3JvdXBfaWQiXQogICAgbGluZXMgPSByb3cuZ2V0KCJsaW5lX2l0ZW1zIiwgW10pCiAgICBuID0gbGVuKGxpbmVzKQogICAgZmlyc3QgPSAobGluZXNbMF0uZ2V0KCJuYW1lIikgaWYgbGluZXMgZWxzZSAiIikgb3IgInlvdXIgaXRlbSIKICAgIHN1bW1hcnkgPSBmaXJzdCBpZiBuIDw9IDEgZWxzZSBmIntmaXJzdH0gK3tuIC0gMX0gbW9yZSIKICAgIGNpdHkgPSAocm93LmdldCgic2hpcF90byIpIG9yIHt9KS5nZXQoImNpdHkiKSBvciAiIgogICAgc2hpcF9oaW50ID0gZiIgLSBzaGlwIHRvIHtyb3cuZ2V0KCdidXllcl9uYW1lJywnYnV5ZXInKX0iICsgKGYiLCB7Y2l0eX0iIGlmIGNpdHkgZWxzZSAiIikKICAgIHRpdGxlID0gZiJZb3Ugc29sZCB7c3VtbWFyeX0iCiAgICBib2R5ID0gZiJ7cm93LmdldCgnYnV5ZXJfbmFtZScsJ0EgYnV5ZXInKX0gYm91Z2h0IHtufSBpdGVtKHMpe3NoaXBfaGludH0uIFRhcCB0byBmdWxmaWwuIgogICAgYWN0aW9uX3VybCA9IGYiL3NlbGxlci9vcmRlcnM/c2FsZT17c2dfaWR9IgogICAgYWxlcnRfaWQgPSAiIgogICAgdHJ5OgogICAgICAgIGZyb20gYXBwLnNlcnZpY2VzLmFsZXJ0cyBpbXBvcnQgd3JpdGVfYWxlcnQKICAgICAgICByZXMgPSB3cml0ZV9hbGVydCgKICAgICAgICAgICAgc2VsbGVyLAogICAgICAgICAgICBldmVudD0ic2hvcF9pdGVtX3NvbGQiLAogICAgICAgICAgICBvdXRjb21lPSJzdWNjZXNzIiwKICAgICAgICAgICAgdGl0bGU9dGl0bGUsCiAgICAgICAgICAgIGRldGFpbHM9ewogICAgICAgICAgICAgICAgImFsZXJ0X3R5cGUiOiAic2hvcF9pdGVtX3NvbGQiLAogICAgICAgICAgICAgICAgInNoaXBfZ3JvdXBfaWQiOiBzZ19pZCwKICAgICAgICAgICAgICAgICJvcmRlcl9pZCI6IHJvdy5nZXQoIm9yZGVyX2lkIiksCiAgICAgICAgICAgICAgICAiaXRlbV9jb3VudCI6IG4sCiAgICAgICAgICAgICAgICAic3VidG90YWxfY2VudHMiOiByb3cuZ2V0KCJzdWJ0b3RhbF9jZW50cyIpLAogICAgICAgICAgICAgICAgImJ1eWVyX25hbWUiOiByb3cuZ2V0KCJidXllcl9uYW1lIiksCiAgICAgICAgICAgICAgICAic3VtbWFyeSI6IHN1bW1hcnksCiAgICAgICAgICAgIH0sCiAgICAgICAgICAgIGFjdGlvbl91cmw9YWN0aW9uX3VybCwKICAgICAgICAgICAgc291cmNlX3R5cGU9InNlbGxlcl9zaGlwX2dyb3VwIiwKICAgICAgICAgICAgc291cmNlX2lkPXNnX2lkLAogICAgICAgICkKICAgICAgICBhbGVydF9pZCA9IChyZXMgb3Ige30pLmdldCgiYWxlcnRfaWQiLCAiIikgaWYgaXNpbnN0YW5jZShyZXMsIGRpY3QpIGVsc2UgIiIKICAgIGV4Y2VwdCBFeGNlcHRpb246CiAgICAgICAgbG9nZ2VyLmV4Y2VwdGlvbigid3JpdGVfYWxlcnQgZmFpbGVkIGZvciBzZWxsZXIgJXMgc2cgJXMiLCBzZWxsZXIsIHNnX2lkKQogICAgdHJ5OgogICAgICAgIGZyb20gYXBwLnNlcnZpY2VzLnB1c2ggaW1wb3J0IHNlbmRfcHVzaF9mb3JfYWxlcnQKICAgICAgICBzZW5kX3B1c2hfZm9yX2FsZXJ0KHNlbGxlciwgInNob3BfaXRlbV9zb2xkIiwgdGl0bGUsIGJvZHksIGFsZXJ0X2lkIG9yIHNnX2lkKQogICAgZXhjZXB0IEV4Y2VwdGlvbjoKICAgICAgICBsb2dnZXIuZXhjZXB0aW9uKCJwdXNoIGZhaWxlZCBmb3Igc2VsbGVyICVzIHNnICVzIiwgc2VsbGVyLCBzZ19pZCkKCgojIC0tIHNlbGxlci1zY29wZWQgcmVhZHMgLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tCgpkZWYgbGlzdF9mb3Jfc2VsbGVyKHNlbGxlcl9pZDogc3RyLCAqLCBsaW1pdDogaW50ID0gNTAsIGN1cnNvcjogT3B0aW9uYWxbc3RyXSA9IE5vbmUpIC0+IFR1cGxlW0xpc3RbRGljdFtzdHIsIEFueV1dLCBPcHRpb25hbFtzdHJdXToKICAgIGt3YXJnczogRGljdFtzdHIsIEFueV0gPSB7CiAgICAgICAgIktleUNvbmRpdGlvbkV4cHJlc3Npb24iOiBLZXkoInNlbGxlcl9pZCIpLmVxKHNlbGxlcl9pZCksCiAgICAgICAgIlNjYW5JbmRleEZvcndhcmQiOiBGYWxzZSwKICAgICAgICAiTGltaXQiOiBtYXgoMSwgbWluKGludChsaW1pdCksIDIwMCkpLAogICAgfQogICAgaWYgY3Vyc29yOgogICAgICAgIGt3YXJnc1siRXhjbHVzaXZlU3RhcnRLZXkiXSA9IHsic2VsbGVyX2lkIjogc2VsbGVyX2lkLCAic2hpcF9ncm91cF9pZCI6IGN1cnNvcn0KICAgIHJlc3AgPSBULnNlbGxlcl9zaGlwX2dyb3Vwcy5xdWVyeSgqKmt3YXJncykKICAgIHJvd3MgPSBsaXN0KHJlc3AuZ2V0KCJJdGVtcyIsIFtdKSkKICAgIHJvd3Muc29ydChrZXk9bGFtYmRhIHI6IGludChyLmdldCgiY3JlYXRlZF9hdCIsIDApKSwgcmV2ZXJzZT1UcnVlKQogICAgbGVrID0gcmVzcC5nZXQoIkxhc3RFdmFsdWF0ZWRLZXkiKSBvciB7fQogICAgcmV0dXJuIHJvd3MsIChsZWsuZ2V0KCJzaGlwX2dyb3VwX2lkIikgaWYgbGVrIGVsc2UgTm9uZSkKCgpkZWYgZ2V0X2Zvcl9zZWxsZXIoc2VsbGVyX2lkOiBzdHIsIHNoaXBfZ3JvdXBfaWQ6IHN0cikgLT4gT3B0aW9uYWxbRGljdFtzdHIsIEFueV1dOgogICAgcmVzcCA9IFQuc2VsbGVyX3NoaXBfZ3JvdXBzLmdldF9pdGVtKEtleT17InNlbGxlcl9pZCI6IHNlbGxlcl9pZCwgInNoaXBfZ3JvdXBfaWQiOiBzaGlwX2dyb3VwX2lkfSkKICAgIHJvdyA9IHJlc3AuZ2V0KCJJdGVtIikKICAgIGlmIG5vdCByb3cgb3Igc3RyKHJvdy5nZXQoInNlbGxlcl9pZCIpKSAhPSBzdHIoc2VsbGVyX2lkKToKICAgICAgICByZXR1cm4gTm9uZQogICAgcmV0dXJuIHJvdwoKCmRlZiBsaXN0X2J5X29yZGVyKG9yZGVyX2lkOiBzdHIpIC0+IExpc3RbRGljdFtzdHIsIEFueV1dOgogICAgIiIiQWxsIHNlbGxlciBncm91cHMgZm9yIG9uZSBvcmRlciAocGVyLW9yZGVyIG11bHRpLXNlbGxlciB2aWV3IC8gYWRtaW4gLyB2ZXJpZnkpLiIiIgogICAgcmVzcCA9IFQuc2VsbGVyX3NoaXBfZ3JvdXBzLnF1ZXJ5KAogICAgICAgIEluZGV4TmFtZT0iR1NJX09SREVSIiwKICAgICAgICBLZXlDb25kaXRpb25FeHByZXNzaW9uPUtleSgib3JkZXJfaWQiKS5lcShvcmRlcl9pZCksCiAgICApCiAgICByZXR1cm4gbGlzdChyZXNwLmdldCgiSXRlbXMiLCBbXSkpCgoKIyAtLSBzZWxsZXItc2NvcGVkIGZ1bGZpbG1lbnQgKHRyYW5zaXRpb24sIHNjb3BlZCB0byB0aGUgc2VsbGVyJ3Mgb3duIGdyb3VwKSAtLQoKY2xhc3MgU2hpcEdyb3VwTm90Rm91bmQoRXhjZXB0aW9uKToKICAgIHBhc3MKCgpjbGFzcyBJbGxlZ2FsU2hpcEdyb3VwVHJhbnNpdGlvbihFeGNlcHRpb24pOgogICAgZGVmIF9faW5pdF9fKHNlbGYsIGZybTogc3RyLCB0bzogc3RyKSAtPiBOb25lOgogICAgICAgIHNlbGYuZnJtLCBzZWxmLnRvID0gZnJtLCB0bwogICAgICAgIHN1cGVyKCkuX19pbml0X18oZiJpbGxlZ2FsIHRyYW5zaXRpb24ge2ZybX0gLT4ge3RvfSIpCgoKZGVmIHRyYW5zaXRpb24oCiAgICBzZWxsZXJfaWQ6IHN0ciwKICAgIHNoaXBfZ3JvdXBfaWQ6IHN0ciwKICAgIHRhcmdldF9zdGF0dXM6IHN0ciwKICAgICosCiAgICBhY3Rvcjogc3RyLAogICAgdHJhY2tpbmdfbnVtYmVyOiBPcHRpb25hbFtzdHJdID0gTm9uZSwKICAgIGNhcnJpZXI6IE9wdGlvbmFsW3N0cl0gPSBOb25lLAogICAgaWRlbXBvdGVuY3lfa2V5OiBPcHRpb25hbFtzdHJdID0gTm9uZSwKKSAtPiBEaWN0W3N0ciwgQW55XToKICAgICIiIkFkdmFuY2UgYSBzZWxsZXIgc2hpcCBncm91cCB0aHJvdWdoIHRoZSBvcmRlci1saWZlY3ljbGUgc3RhdGUgbWFjaGluZSwKICAgIHNjb3BlZCB0byB0aGUgc2VsbGVyJ3MgT1dOIGdyb3VwLiBOb24tYWRtaW4uIiIiCiAgICByb3cgPSBnZXRfZm9yX3NlbGxlcihzZWxsZXJfaWQsIHNoaXBfZ3JvdXBfaWQpCiAgICBpZiBub3Qgcm93OgogICAgICAgIHJhaXNlIFNoaXBHcm91cE5vdEZvdW5kKHNoaXBfZ3JvdXBfaWQpCiAgICBjdXJyZW50ID0gc3RyKHJvdy5nZXQoInN0YXR1cyIpIG9yICIiKQogICAgdGFyZ2V0ID0gc3RyKHRhcmdldF9zdGF0dXMgb3IgIiIpCgogICAgaWYgY3VycmVudCA9PSB0YXJnZXQgYW5kIGlkZW1wb3RlbmN5X2tleToKICAgICAgICByZXR1cm4gcm93ICAjIGlkZW1wb3RlbnQgcmVwbGF5CgogICAgaWYgdGFyZ2V0IG5vdCBpbiBfdHJhbnNpdGlvbnMoKS5nZXQoY3VycmVudCwgc2V0KCkpOgogICAgICAgIHJhaXNlIElsbGVnYWxTaGlwR3JvdXBUcmFuc2l0aW9uKGN1cnJlbnQsIHRhcmdldCkKCiAgICBub3cgPSBfbm93KCkKICAgIHNldF9wYXJ0cyA9IFsiI3N0ID0gOnN0IiwgInVwZGF0ZWRfYXQgPSA6dWEiXQogICAgdmFsczogRGljdFtzdHIsIEFueV0gPSB7IjpzdCI6IHRhcmdldCwgIjp1YSI6IG5vdywgIjpjdXIiOiBjdXJyZW50fQogICAgaWYgdHJhY2tpbmdfbnVtYmVyIGlzIG5vdCBOb25lOgogICAgICAgIHNldF9wYXJ0cy5hcHBlbmQoInRyYWNraW5nX251bWJlciA9IDp0biIpOyB2YWxzWyI6dG4iXSA9IHN0cih0cmFja2luZ19udW1iZXIpCiAgICBpZiBjYXJyaWVyIGlzIG5vdCBOb25lOgogICAgICAgIHNldF9wYXJ0cy5hcHBlbmQoImNhcnJpZXIgPSA6Y2EiKTsgdmFsc1siOmNhIl0gPSBzdHIoY2FycmllcikKICAgIHNldF9wYXJ0cy5hcHBlbmQoImhpc3RvcnkgPSBsaXN0X2FwcGVuZChpZl9ub3RfZXhpc3RzKGhpc3RvcnksIDplbXB0eSksIDpoKSIpCiAgICB2YWxzWyI6ZW1wdHkiXSA9IFtdCiAgICB2YWxzWyI6aCJdID0gW3siZnJvbSI6IGN1cnJlbnQsICJ0byI6IHRhcmdldCwgImFjdG9yIjogYWN0b3IsICJ0cyI6IG5vd31dCgogICAgcmVzcCA9IFQuc2VsbGVyX3NoaXBfZ3JvdXBzLnVwZGF0ZV9pdGVtKAogICAgICAgIEtleT17InNlbGxlcl9pZCI6IHNlbGxlcl9pZCwgInNoaXBfZ3JvdXBfaWQiOiBzaGlwX2dyb3VwX2lkfSwKICAgICAgICBVcGRhdGVFeHByZXNzaW9uPSJTRVQgIiArICIsICIuam9pbihzZXRfcGFydHMpLAogICAgICAgIEV4cHJlc3Npb25BdHRyaWJ1dGVOYW1lcz17IiNzdCI6ICJzdGF0dXMifSwKICAgICAgICBFeHByZXNzaW9uQXR0cmlidXRlVmFsdWVzPXZhbHMsCiAgICAgICAgQ29uZGl0aW9uRXhwcmVzc2lvbj0iI3N0ID0gOmN1ciIsCiAgICAgICAgUmV0dXJuVmFsdWVzPSJBTExfTkVXIiwKICAgICkKICAgIHJldHVybiByZXNwLmdldCgiQXR0cmlidXRlcyIsIHJvdykK"
ROUTER_B64 = "IiIiRUNPTS1TRUxMRVIgKEczKSAtIHNlbGxlci1zY29wZWQgc2FsZXMgLyBmdWxmaWxtZW50IHJvdXRlci4KCk1vdW50ZWQgYXQgYGAvdWkvc2VsbGVyL3NhbGVzYGAuIEEgTk9OLUFETUlOIGF1dGhlbnRpY2F0ZWQgc2VsbGVyIGxpc3RzICsgZmV0Y2hlcwpPTkxZIHRoZWlyIG93biBwZXItc2VsbGVyIHNoaXAgZ3JvdXBzICh3aXRoIHRoZSBidXllciBzaGlwcGluZyBhZGRyZXNzICsgcmVhbApsaW5lLWl0ZW0gbmFtZXMpIGFuZCBhZHZhbmNlcyB0aGUgb3JkZXItbGlmZWN5Y2xlIHN0YXRlIG1hY2hpbmUgc2NvcGVkIHRvIHRoZWlyCm93biBncm91cC4gQSBzZWxsZXIgY2FuIG5ldmVyIHNlZSBhbm90aGVyIHNlbGxlcidzIGl0ZW1zIG5vciB0aGUgYnV5ZXIncyBwYXltZW50CmludGVybmFscy4gQWxsIGhhbmRsZXJzIDUwMyB3aGVuIGBgUy5vcmRlcl9saWZlY3ljbGVfZW5hYmxlZGBgIGlzIG9mZi4KCiAgR0VUICAvdWkvc2VsbGVyL3NhbGVzICAgICAgICAgICAgICAgICAgICAtPiBTZWxsZXJTYWxlTGlzdE91dCAoY2FsbGVyJ3MgZ3JvdXBzKQogIEdFVCAgL3VpL3NlbGxlci9zYWxlcy97c2hpcF9ncm91cF9pZH0gICAgLT4gU2VsbGVyU2FsZU91dCAgICAgKDQwNCBpZiBub3QgY2FsbGVyJ3MpCiAgUE9TVCAvdWkvc2VsbGVyL3NhbGVzL3tzaGlwX2dyb3VwX2lkfS90cmFuc2l0aW9uIC0+IFNlbGxlclNhbGVPdXQgKHNjb3BlZCBmdWxmaWwpCiIiIgpmcm9tIF9fZnV0dXJlX18gaW1wb3J0IGFubm90YXRpb25zCgpmcm9tIHR5cGluZyBpbXBvcnQgQW55LCBEaWN0LCBMaXN0LCBPcHRpb25hbAoKZnJvbSBmYXN0YXBpIGltcG9ydCBBUElSb3V0ZXIsIERlcGVuZHMsIEhUVFBFeGNlcHRpb24sIFF1ZXJ5CmZyb20gcHlkYW50aWMgaW1wb3J0IEJhc2VNb2RlbAoKZnJvbSBhcHAuY29yZS5zZXR0aW5ncyBpbXBvcnQgUwpmcm9tIGFwcC5zZXJ2aWNlcy5zZXNzaW9ucyBpbXBvcnQgcmVxdWlyZV91aV9zZXNzaW9uCgpyb3V0ZXIgPSBBUElSb3V0ZXIocHJlZml4PSIvdWkvc2VsbGVyL3NhbGVzIiwgdGFncz1bInNlbGxlci1zYWxlcyJdKQoKCmRlZiBfcmVxdWlyZV9lbmFibGVkKCkgLT4gTm9uZToKICAgIGlmIG5vdCBTLm9yZGVyX2xpZmVjeWNsZV9lbmFibGVkOgogICAgICAgIHJhaXNlIEhUVFBFeGNlcHRpb24oCiAgICAgICAgICAgIHN0YXR1c19jb2RlPTUwMywKICAgICAgICAgICAgZGV0YWlsPXsiY29kZSI6ICJvcmRlcl9saWZlY3ljbGVfbm90X2VuYWJsZWQiLCAibWVzc2FnZSI6ICJPcmRlciBsaWZlY3ljbGUgaXMgbm90IGVuYWJsZWQifSwKICAgICAgICApCgoKY2xhc3MgU2VsbGVyU2FsZUxpbmVJdGVtKEJhc2VNb2RlbCk6CiAgICBpdGVtX2lkOiBzdHIgPSAiIgogICAgc2t1OiBzdHIgPSAiIgogICAgbmFtZTogc3RyID0gIiIKICAgIHF1YW50aXR5OiBpbnQgPSAxCiAgICB1bml0X3ByaWNlX2NlbnRzOiBpbnQgPSAwCiAgICBsaW5lX3RvdGFsX2NlbnRzOiBpbnQgPSAwCgoKY2xhc3MgU2VsbGVyU2FsZU91dChCYXNlTW9kZWwpOgogICAgc2hpcF9ncm91cF9pZDogc3RyCiAgICBvcmRlcl9pZDogc3RyCiAgICBzdGF0dXM6IHN0cgogICAgYWxsb3dlZF90cmFuc2l0aW9uczogTGlzdFtzdHJdID0gW10KICAgIGJ1eWVyX25hbWU6IHN0ciA9ICIiCiAgICBidXllcl9lbWFpbDogc3RyID0gIiIKICAgIHNoaXBfdG86IERpY3Rbc3RyLCBBbnldID0ge30KICAgIGxpbmVfaXRlbXM6IExpc3RbU2VsbGVyU2FsZUxpbmVJdGVtXSA9IFtdCiAgICBpdGVtX2NvdW50OiBpbnQgPSAwCiAgICBzdWJ0b3RhbF9jZW50czogaW50ID0gMAogICAgY3VycmVuY3k6IHN0ciA9ICJVU0QiCiAgICB0cmFja2luZ19udW1iZXI6IE9wdGlvbmFsW3N0cl0gPSBOb25lCiAgICBjYXJyaWVyOiBPcHRpb25hbFtzdHJdID0gTm9uZQogICAgY3JlYXRlZF9hdDogaW50ID0gMAogICAgdXBkYXRlZF9hdDogaW50ID0gMAoKCmNsYXNzIFNlbGxlclNhbGVMaXN0T3V0KEJhc2VNb2RlbCk6CiAgICBzYWxlczogTGlzdFtTZWxsZXJTYWxlT3V0XSA9IFtdCiAgICBuZXh0X2N1cnNvcjogT3B0aW9uYWxbc3RyXSA9IE5vbmUKCgpjbGFzcyBTZWxsZXJTYWxlVHJhbnNpdGlvbkluKEJhc2VNb2RlbCk6CiAgICB0YXJnZXRfc3RhdHVzOiBzdHIKICAgIHJlYXNvbjogT3B0aW9uYWxbc3RyXSA9IE5vbmUKICAgIHRyYWNraW5nX251bWJlcjogT3B0aW9uYWxbc3RyXSA9IE5vbmUKICAgIGNhcnJpZXI6IE9wdGlvbmFsW3N0cl0gPSBOb25lCiAgICBpZGVtcG90ZW5jeV9rZXk6IE9wdGlvbmFsW3N0cl0gPSBOb25lCgoKZGVmIF9yb3dfdG9fb3V0KHJvdzogRGljdFtzdHIsIEFueV0pIC0+IFNlbGxlclNhbGVPdXQ6CiAgICBmcm9tIGFwcC5zZXJ2aWNlcyBpbXBvcnQgc2VsbGVyX3NoaXBfZ3JvdXBzIGFzIHNzZwoKICAgIHN0YXR1cyA9IHN0cihyb3cuZ2V0KCJzdGF0dXMiKSBvciAiIikKICAgIHJldHVybiBTZWxsZXJTYWxlT3V0KAogICAgICAgIHNoaXBfZ3JvdXBfaWQ9c3RyKHJvdy5nZXQoInNoaXBfZ3JvdXBfaWQiLCAiIikpLAogICAgICAgIG9yZGVyX2lkPXN0cihyb3cuZ2V0KCJvcmRlcl9pZCIsICIiKSksCiAgICAgICAgc3RhdHVzPXN0YXR1cywKICAgICAgICBhbGxvd2VkX3RyYW5zaXRpb25zPXNzZy5hbGxvd2VkX3RyYW5zaXRpb25zKHN0YXR1cyksCiAgICAgICAgYnV5ZXJfbmFtZT1zdHIocm93LmdldCgiYnV5ZXJfbmFtZSIsICIiKSksCiAgICAgICAgYnV5ZXJfZW1haWw9c3RyKHJvdy5nZXQoImJ1eWVyX2VtYWlsIiwgIiIpKSwKICAgICAgICBzaGlwX3RvPWRpY3Qocm93LmdldCgic2hpcF90byIpIG9yIHt9KSwKICAgICAgICBsaW5lX2l0ZW1zPVtTZWxsZXJTYWxlTGluZUl0ZW0oKip7azogbGkuZ2V0KGspIGZvciBrIGluIFNlbGxlclNhbGVMaW5lSXRlbS5tb2RlbF9maWVsZHMgaWYgbGkuZ2V0KGspIGlzIG5vdCBOb25lfSkgZm9yIGxpIGluIChyb3cuZ2V0KCJsaW5lX2l0ZW1zIikgb3IgW10pXSwKICAgICAgICBpdGVtX2NvdW50PWludChyb3cuZ2V0KCJpdGVtX2NvdW50IiwgMCkgb3IgMCksCiAgICAgICAgc3VidG90YWxfY2VudHM9aW50KHJvdy5nZXQoInN1YnRvdGFsX2NlbnRzIiwgMCkgb3IgMCksCiAgICAgICAgY3VycmVuY3k9c3RyKHJvdy5nZXQoImN1cnJlbmN5IiwgIlVTRCIpKSwKICAgICAgICB0cmFja2luZ19udW1iZXI9KHN0cihyb3dbInRyYWNraW5nX251bWJlciJdKSBpZiByb3cuZ2V0KCJ0cmFja2luZ19udW1iZXIiKSBlbHNlIE5vbmUpLAogICAgICAgIGNhcnJpZXI9KHN0cihyb3dbImNhcnJpZXIiXSkgaWYgcm93LmdldCgiY2FycmllciIpIGVsc2UgTm9uZSksCiAgICAgICAgY3JlYXRlZF9hdD1pbnQocm93LmdldCgiY3JlYXRlZF9hdCIsIDApIG9yIDApLAogICAgICAgIHVwZGF0ZWRfYXQ9aW50KHJvdy5nZXQoInVwZGF0ZWRfYXQiLCAwKSBvciAwKSwKICAgICkKCgpAcm91dGVyLmdldCgiIiwgcmVzcG9uc2VfbW9kZWw9U2VsbGVyU2FsZUxpc3RPdXQpCmFzeW5jIGRlZiBsaXN0X3NlbGxlcl9zYWxlcygKICAgIGxpbWl0OiBpbnQgPSBRdWVyeShkZWZhdWx0PTUwLCBnZT0xLCBsZT0yMDApLAogICAgY3Vyc29yOiBPcHRpb25hbFtzdHJdID0gUXVlcnkoZGVmYXVsdD1Ob25lKSwKICAgIGN0eDogRGljdFtzdHIsIEFueV0gPSBEZXBlbmRzKHJlcXVpcmVfdWlfc2Vzc2lvbiksCikgLT4gU2VsbGVyU2FsZUxpc3RPdXQ6CiAgICAiIiJMaXN0IHRoZSBhdXRoZW50aWNhdGVkIHNlbGxlcidzIG93biBzaGlwIGdyb3VwcyAodGhlaXIgcmVjZWl2ZWQgc2FsZXMpLiIiIgogICAgX3JlcXVpcmVfZW5hYmxlZCgpCiAgICBmcm9tIGFwcC5zZXJ2aWNlcyBpbXBvcnQgc2VsbGVyX3NoaXBfZ3JvdXBzIGFzIHNzZwoKICAgIHJvd3MsIG5leHRfY3Vyc29yID0gc3NnLmxpc3RfZm9yX3NlbGxlcihjdHhbInVzZXJfc3ViIl0sIGxpbWl0PWxpbWl0LCBjdXJzb3I9Y3Vyc29yKQogICAgcmV0dXJuIFNlbGxlclNhbGVMaXN0T3V0KHNhbGVzPVtfcm93X3RvX291dChyKSBmb3IgciBpbiByb3dzXSwgbmV4dF9jdXJzb3I9bmV4dF9jdXJzb3IpCgoKQHJvdXRlci5nZXQoIi97c2hpcF9ncm91cF9pZH0iLCByZXNwb25zZV9tb2RlbD1TZWxsZXJTYWxlT3V0KQphc3luYyBkZWYgZ2V0X3NlbGxlcl9zYWxlKAogICAgc2hpcF9ncm91cF9pZDogc3RyLAogICAgY3R4OiBEaWN0W3N0ciwgQW55XSA9IERlcGVuZHMocmVxdWlyZV91aV9zZXNzaW9uKSwKKSAtPiBTZWxsZXJTYWxlT3V0OgogICAgIiIiRmV0Y2ggb25lIG9mIHRoZSBzZWxsZXIncyBvd24gc2hpcCBncm91cHMgKDQwNCBpZiBub3QgdGhlaXJzKS4iIiIKICAgIF9yZXF1aXJlX2VuYWJsZWQoKQogICAgZnJvbSBhcHAuc2VydmljZXMgaW1wb3J0IHNlbGxlcl9zaGlwX2dyb3VwcyBhcyBzc2cKCiAgICByb3cgPSBzc2cuZ2V0X2Zvcl9zZWxsZXIoY3R4WyJ1c2VyX3N1YiJdLCBzaGlwX2dyb3VwX2lkKQogICAgaWYgbm90IHJvdzoKICAgICAgICByYWlzZSBIVFRQRXhjZXB0aW9uKDQwNCwgeyJjb2RlIjogInNoaXBfZ3JvdXBfbm90X2ZvdW5kIn0pCiAgICByZXR1cm4gX3Jvd190b19vdXQocm93KQoKCkByb3V0ZXIucG9zdCgiL3tzaGlwX2dyb3VwX2lkfS90cmFuc2l0aW9uIiwgcmVzcG9uc2VfbW9kZWw9U2VsbGVyU2FsZU91dCkKYXN5bmMgZGVmIHRyYW5zaXRpb25fc2VsbGVyX3NhbGUoCiAgICBzaGlwX2dyb3VwX2lkOiBzdHIsCiAgICBib2R5OiBTZWxsZXJTYWxlVHJhbnNpdGlvbkluLAogICAgY3R4OiBEaWN0W3N0ciwgQW55XSA9IERlcGVuZHMocmVxdWlyZV91aV9zZXNzaW9uKSwKKSAtPiBTZWxsZXJTYWxlT3V0OgogICAgIiIiQWR2YW5jZSB0aGUgc2VsbGVyJ3Mgb3duIHNoaXAgZ3JvdXAgKGUuZy4gYXBwcm92ZWQtPmFsbG9jYXRlZC0+Li4uLT5zaGlwcGVkKS4iIiIKICAgIF9yZXF1aXJlX2VuYWJsZWQoKQogICAgZnJvbSBhcHAuc2VydmljZXMgaW1wb3J0IHNlbGxlcl9zaGlwX2dyb3VwcyBhcyBzc2cKCiAgICB0cnk6CiAgICAgICAgcm93ID0gc3NnLnRyYW5zaXRpb24oCiAgICAgICAgICAgIGN0eFsidXNlcl9zdWIiXSwKICAgICAgICAgICAgc2hpcF9ncm91cF9pZCwKICAgICAgICAgICAgYm9keS50YXJnZXRfc3RhdHVzLAogICAgICAgICAgICBhY3Rvcj1jdHhbInVzZXJfc3ViIl0sCiAgICAgICAgICAgIHRyYWNraW5nX251bWJlcj1ib2R5LnRyYWNraW5nX251bWJlciwKICAgICAgICAgICAgY2Fycmllcj1ib2R5LmNhcnJpZXIsCiAgICAgICAgICAgIGlkZW1wb3RlbmN5X2tleT1ib2R5LmlkZW1wb3RlbmN5X2tleSwKICAgICAgICApCiAgICBleGNlcHQgc3NnLlNoaXBHcm91cE5vdEZvdW5kOgogICAgICAgIHJhaXNlIEhUVFBFeGNlcHRpb24oNDA0LCB7ImNvZGUiOiAic2hpcF9ncm91cF9ub3RfZm91bmQifSkKICAgIGV4Y2VwdCBzc2cuSWxsZWdhbFNoaXBHcm91cFRyYW5zaXRpb24gYXMgZXhjOgogICAgICAgIHJhaXNlIEhUVFBFeGNlcHRpb24oNDA5LCB7ImNvZGUiOiAiaWxsZWdhbF90cmFuc2l0aW9uIiwgImRldGFpbCI6IHN0cihleGMpfSkKICAgIHJldHVybiBfcm93X3RvX291dChyb3cpCg=="

log = []
def note(x): log.append(x); print(x)

def write_new(relpath, b64):
    path = os.path.join(ROOT, relpath)
    content = base64.b64decode(b64).decode("utf-8")
    if os.path.exists(path) and open(path, encoding="utf-8").read() == content:
        note(f"SKIP (identical) {relpath}"); return path
    with open(path, "w", encoding="utf-8") as f:
        f.write(content)
    note(f"WROTE {relpath} ({len(content)} bytes)"); return path

def edit(relpath, marker, anchor, insert_after=True, replacement=None):
    """If marker already in file -> SKIP. Else anchor-replace."""
    path = os.path.join(ROOT, relpath)
    txt = open(path, encoding="utf-8").read()
    if marker in txt:
        note(f"SKIP (marker present) {relpath}"); return
    if anchor not in txt:
        note(f"!! ANCHOR MISSING in {relpath}: {anchor[:60]!r}"); return
    if replacement is not None:
        newtxt = txt.replace(anchor, replacement, 1)
    else:
        newtxt = txt  # not used
    if newtxt == txt:
        note(f"!! NO-OP replace {relpath}"); return
    with open(path, "w", encoding="utf-8") as f:
        f.write(newtxt)
    note(f"EDITED {relpath}")

# 1) new files ---------------------------------------------------------------
write_new("app/services/seller_ship_groups.py", SVC_B64)
write_new("app/routers/seller_ship_groups.py", ROUTER_B64)

# 2) shoppingcart approval hook ----------------------------------------------
SC_ANCHOR = (
    '        _logging_ol.getLogger(__name__).exception(\n'
    '            "Failed to advance order lifecycle for cart %s order %s", cart_id, order_id\n'
    '        )\n'
)
SC_INSERT = SC_ANCHOR + (
    "\n"
    "    # ECOM-SELLER (G1-G4): on order approval, split the paid cart into per-seller\n"
    "    # ship-groups (each = that seller's line items w/ REAL names + the buyer ship\n"
    "    # address), notify each seller (you-sold-it alert+push), backfill line names.\n"
    "    try:\n"
    "        if S.order_lifecycle_enabled and order_id:\n"
    "            from app.services import seller_ship_groups as _ssg\n"
    "            _ssg.populate_on_approval(\n"
    "                order_id=order_id,\n"
    "                buyer_sub=user_sub,\n"
    "                cart_items=items,\n"
    "                buyer=buyer,\n"
    "                currency=str(cart.get(\"currency\", \"USD\")),\n"
    "            )\n"
    "    except Exception:\n"
    "        import logging as _lg_ssg\n"
    "        _lg_ssg.getLogger(__name__).exception(\"seller ship-group populate failed for order %s\", order_id)\n"
)
edit("app/services/shoppingcart.py", "ECOM-SELLER (G1-G4)", SC_ANCHOR, replacement=SC_INSERT)

# 3) main.py import + include ------------------------------------------------
edit("app/main.py", "seller_ship_groups import router as seller_sales_router",
     "from app.routers.orders import router as orders_adj_ship_router\n",
     replacement="from app.routers.orders import router as orders_adj_ship_router\n"
                 "from app.routers.seller_ship_groups import router as seller_sales_router  # ECOM-SELLER\n")
edit("app/main.py", "include_router(seller_sales_router)",
     "    app.include_router(orders_adj_ship_router)\n",
     replacement="    app.include_router(orders_adj_ship_router)\n"
                 "    app.include_router(seller_sales_router)  # ECOM-SELLER seller-scoped sales\n")

# 4) settings.py table name --------------------------------------------------
edit("app/core/settings.py", "seller_ship_groups_table_name",
     '    order_items_table_name: str = os.environ.get("ORDER_ITEMS_TABLE_NAME", "order_items")\n',
     replacement='    order_items_table_name: str = os.environ.get("ORDER_ITEMS_TABLE_NAME", "order_items")\n'
                 '    seller_ship_groups_table_name: str = os.environ.get("SELLER_SHIP_GROUPS_TABLE_NAME", "seller_ship_groups")\n')

# 5) tables.py field + registration ------------------------------------------
edit("app/core/tables.py", "seller_ship_groups: Any",
     "    order_items: Any\n",
     replacement="    order_items: Any\n    seller_ship_groups: Any\n")
edit("app/core/tables.py", "seller_ship_groups=_safe_table",
     "    order_items=_safe_table(S.order_items_table_name),\n",
     replacement="    order_items=_safe_table(S.order_items_table_name),\n"
                 "    seller_ship_groups=_safe_table(S.seller_ship_groups_table_name),\n")

# 6) local-ddb-init TableDef -------------------------------------------------
DDB_ANCHOR = '        TableDef(_resolve_table_name(S.order_items_table_name, "order_items"), "order_id", "item_id"),\n'
DDB_INSERT = DDB_ANCHOR + (
    '        TableDef(\n'
    '            _resolve_table_name(S.seller_ship_groups_table_name, "seller_ship_groups"),\n'
    '            "seller_id",\n'
    '            "ship_group_id",\n'
    '            gsi=[\n'
    '                {"index_name": "GSI_ORDER", "partition_key": "order_id", "sort_key": "ship_group_id"},\n'
    '            ],\n'
    '        ),\n'
)
edit("scripts/local-ddb-init.py", "seller_ship_groups", DDB_ANCHOR, replacement=DDB_INSERT)

# 7) create the DDB table (idempotent) ---------------------------------------
if not PROBE:
    sys.path.insert(0, ROOT)
    os.chdir(ROOT)
    try:
        from app.core.tables import T
        from app.core.settings import S as _S
        client = T.order_items.meta.client
        name = _S.seller_ship_groups_table_name
        try:
            client.create_table(
                TableName=name,
                KeySchema=[
                    {"AttributeName": "seller_id", "KeyType": "HASH"},
                    {"AttributeName": "ship_group_id", "KeyType": "RANGE"},
                ],
                AttributeDefinitions=[
                    {"AttributeName": "seller_id", "AttributeType": "S"},
                    {"AttributeName": "ship_group_id", "AttributeType": "S"},
                    {"AttributeName": "order_id", "AttributeType": "S"},
                ],
                GlobalSecondaryIndexes=[{
                    "IndexName": "GSI_ORDER",
                    "KeySchema": [
                        {"AttributeName": "order_id", "KeyType": "HASH"},
                        {"AttributeName": "ship_group_id", "KeyType": "RANGE"},
                    ],
                    "Projection": {"ProjectionType": "ALL"},
                }],
                BillingMode="PAY_PER_REQUEST",
            )
            note(f"CREATED TABLE {name}")
        except client.exceptions.ResourceInUseException:
            note(f"TABLE EXISTS {name}")
        except Exception as e:
            if "ResourceInUseException" in type(e).__name__ or "Table already exists" in str(e):
                note(f"TABLE EXISTS {name}")
            else:
                note(f"!! create_table error: {e!r}")
    except Exception as e:
        note(f"!! table step error: {e!r}")

# 8) py_compile the touched python files -------------------------------------
for f in ["app/services/seller_ship_groups.py", "app/routers/seller_ship_groups.py",
          "app/services/shoppingcart.py", "app/main.py", "app/core/settings.py",
          "app/core/tables.py", "scripts/local-ddb-init.py"]:
    p = os.path.join(ROOT, f)
    try:
        py_compile.compile(p, doraise=True)
    except Exception as e:
        note(f"!! PYCOMPILE FAIL {f}: {e}")
    else:
        note(f"pycompile OK {f}")

print("APPLY_DONE")
