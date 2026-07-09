p = "app/routers/admin_moderation.py"
s = open(p, encoding="utf-8").read()
a = ("    if content_type == \"syndicate_post\":\n"
     "        from app.services import syndicate_feed as _sf\n"
     "        syndicate_id = str(meta.get(\"syndicate_id\") or \"\")\n")
b = ("    if content_type == \"syndicate_post\":\n"
     "        from app.services import syndicate_feed as _sf\n"
     "        from app.services import moderation_case as _mc2\n"
     "        syndicate_id = str(meta.get(\"syndicate_id\") or \"\")\n"
     "        if not syndicate_id:\n"
     "            _c = _mc2.get_case_for_content(content_type, content_id) or {}\n"
     "            syndicate_id = str((_c.get(\"content_metadata\") or {}).get(\"syndicate_id\") or \"\")\n")
if "from app.services import moderation_case as _mc2" in s:
    print("ALREADY")
elif a in s:
    s = s.replace(a, b, 1)
    open(p, "w", encoding="utf-8").write(s)
    import py_compile; py_compile.compile(p, doraise=True)
    print("PATCHED")
else:
    print("ANCHOR MISSING"); raise SystemExit(2)
