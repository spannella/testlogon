p="app/routers/catalog.py"
s=open(p).read()
if "import logging" not in s:
    s=s.replace("import json\n", "import json\nimport logging\n", 1)
if "logger = logging.getLogger(__name__)" not in s:
    idx=s.find("router = APIRouter(")
    s=s[:idx]+"logger = logging.getLogger(__name__)\n\n"+s[idx:]
open(p,"w").write(s)
import ast; ast.parse(s); print("prod catalog logger added")
