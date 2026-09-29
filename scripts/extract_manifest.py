"""Build an mcp-audit manifest JSON from MCP server source code.

Static extraction, no server execution: parses tool/resource/prompt
definitions out of TypeScript (modelcontextprotocol reference servers,
server.registerTool style with zod schemas) or Python (FastMCP style
Tool(...) calls with pydantic models for inputSchema).

This is how the "Findings on real public MCP servers" section of the
README was produced. It reads documentation, not behavior: annotations
and descriptions come straight from the source, and anything the source
does not say (server-side validation, enforced auth) will not be in the
manifest. Treat the output as a starting point, then review it.

Usage:
    python scripts/extract_manifest.py --ts src/filesystem/index.ts \\
        --name filesystem --version 0.2.0 > filesystem.json
    python scripts/extract_manifest.py --py src/git/server.py \\
        --name git --version 0.1.0 > git.json
"""

from __future__ import annotations

import argparse
import ast
import json
import re

# ---------------------------------------------------------------------------
# shared helpers
# ---------------------------------------------------------------------------


def find_matching(src, start, open_c, close_c):
    depth = 0
    i = start
    in_str = None
    while i < len(src):
        ch = src[i]
        if in_str:
            if ch == "\\":
                i += 2
                continue
            if ch == in_str:
                in_str = None
            i += 1
            continue
        if ch in ("'", '"', "`"):
            in_str = ch
        elif ch == "/" and i + 1 < len(src) and src[i + 1] == "/":
            j = src.find("\n", i)
            i = len(src) if j == -1 else j
            continue
        elif ch == "/" and i + 1 < len(src) and src[i + 1] == "*":
            j = src.find("*/", i)
            i = len(src) if j == -1 else j + 2
            continue
        elif ch == open_c:
            depth += 1
        elif ch == close_c:
            depth -= 1
            if depth == 0:
                return i
        i += 1
    return -1


def split_top_level(s, sep=","):
    parts, depth, cur = [], 0, []
    in_str = None
    i = 0
    while i < len(s):
        ch = s[i]
        if in_str:
            cur.append(ch)
            if ch == "\\":
                if i + 1 < len(s):
                    cur.append(s[i + 1])
                    i += 1
            elif ch == in_str:
                in_str = None
            i += 1
            continue
        if ch in ("'", '"', "`"):
            in_str = ch
            cur.append(ch)
        elif ch in "([{":
            depth += 1
            cur.append(ch)
        elif ch in ")]}":
            depth -= 1
            cur.append(ch)
        elif ch == sep and depth == 0:
            parts.append("".join(cur))
            cur = []
        else:
            cur.append(ch)
        i += 1
    parts.append("".join(cur))
    return parts


def eval_ts_string(expr):
    expr = re.sub(r"\$\{[^}]*\}", "", expr)
    toks = re.findall(r"'(?:[^'\\]|\\.)*'|\"(?:[^\"\\]|\\.)*\"|`(?:[^`\\]|\\.)*`", expr)
    out = []
    for t in toks:
        body = t[1:-1]
        body = (
            body.replace("\\n", "\n")
            .replace("\\t", "\t")
            .replace("\\'", "'")
            .replace('\\"', '"')
            .replace("\\\\", "\\")
        )
        out.append(body)
    return "".join(out)


# ---------------------------------------------------------------------------
# TypeScript extraction
# ---------------------------------------------------------------------------


def parse_zod_field(expr):
    spec = {}
    m = re.match(r"\s*z\.(\w+)", expr)
    if not m:
        return spec
    kind = m.group(1)
    if kind == "string":
        spec["type"] = "string"
    elif kind == "number":
        spec["type"] = "number"
    elif kind == "boolean":
        spec["type"] = "boolean"
    elif kind == "array":
        spec["type"] = "array"
    elif kind == "object":
        spec["type"] = "object"
    elif kind == "enum":
        spec["type"] = "string"
        vals = re.findall(r"'([^']*)'|\"([^\"]*)\"", expr)
        spec["enum"] = [a or b for a, b in vals]
    if re.search(r"\.regex\s*\(", expr):
        spec["pattern"] = "present"
    mm = re.search(r"\.min\s*\(\s*(\d+)", expr)
    if mm:
        spec["minLength"] = int(mm.group(1))
    mm = re.search(r"\.max\s*\(\s*(\d+)", expr)
    if mm:
        spec["maxLength"] = int(mm.group(1))
    if re.search(r"\.url\s*\(", expr):
        spec["format"] = "uri"
    dm = re.search(r"\.describe\s*\(\s*('(?:[^'\\]|\\.)*'|\"(?:[^\"\\]|\\.)*\")", expr)
    if dm:
        spec["description"] = eval_ts_string(dm.group(1))
    return spec


def parse_zod_object(obj_src):
    props = {}
    for part in split_top_level(obj_src):
        part = part.strip()
        if ":" not in part:
            continue
        name, expr = part.split(":", 1)
        name = name.strip().strip("'\"")
        if not re.match(r"^[A-Za-z_$][\w$]*$", name):
            continue
        props[name] = parse_zod_field(expr.strip())
    return props


def extract_ts(src):
    schema_defs = {}
    for m in re.finditer(r"const\s+(\w+)\s*=\s*z\.object\s*\(", src):
        name = m.group(1)
        start = m.end() - 1
        end = find_matching(src, start, "(", ")")
        if end != -1:
            schema_defs[name] = parse_zod_object(src[start + 1 : end])

    tools = []
    for m in re.finditer(r"server\.registerTool\s*\(", src):
        start = m.end() - 1
        end = find_matching(src, start, "(", ")")
        if end == -1:
            continue
        args = split_top_level(src[start + 1 : end])
        if len(args) < 2:
            continue
        name = eval_ts_string(args[0].strip())
        mm = re.match(r"\{(.*)\}", args[1].strip(), re.S)
        if not mm:
            continue
        tool = {"name": name, "annotations": {}}
        for part in split_top_level(mm.group(1)):
            part = part.strip()
            if ":" not in part:
                continue
            key, val = part.split(":", 1)
            key, val = key.strip(), val.strip()
            if key == "description":
                tool["description"] = eval_ts_string(val)
            elif key == "annotations":
                am = re.match(r"\{(.*)\}", val, re.S)
                if am:
                    for ap in split_top_level(am.group(1)):
                        ap = ap.strip()
                        if ":" not in ap:
                            continue
                        ak, av = ap.split(":", 1)
                        ak, av = ak.strip(), av.strip()
                        if av == "true":
                            tool["annotations"][ak] = True
                        elif av == "false":
                            tool["annotations"][ak] = False
            elif key == "inputSchema":
                schema = {"type": "object", "properties": {}}
                sm = re.match(r"(\w+)\.shape$", val)
                if sm and sm.group(1) in schema_defs:
                    schema["properties"] = schema_defs[sm.group(1)]
                else:
                    im = re.match(r"\{(.*)\}", val, re.S)
                    if im:
                        schema["properties"] = parse_zod_object(im.group(1))
                tool["inputSchema"] = schema
        tools.append(tool)

    resources = []
    consts = dict(re.findall(r"const\s+(\w+)\s*=\s*\"([^\"]+)\"", src))
    for m in re.finditer(r"server\.registerResource\s*\(", src):
        start = m.end() - 1
        end = find_matching(src, start, "(", ")")
        if end == -1:
            continue
        args = split_top_level(src[start + 1 : end])
        if len(args) < 3:
            continue
        name = eval_ts_string(args[0].strip())
        uri_expr = args[1].strip()
        uri = consts.get(uri_expr, eval_ts_string(uri_expr))
        desc = ""
        opts = re.match(r"\{(.*)\}", args[2].strip(), re.S)
        if opts:
            dm = re.search(
                r"description\s*:\s*('(?:[^'\\]|\\.)*'|\"(?:[^\"\\]|\\.)*\")",
                opts.group(1),
            )
            if dm:
                desc = eval_ts_string(dm.group(1))
        resources.append({"name": name, "uri": uri, "description": desc})

    return tools, resources, []


# ---------------------------------------------------------------------------
# Python extraction
# ---------------------------------------------------------------------------


def py_const_str(node):
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    if isinstance(node, ast.JoinedStr):
        parts = []
        for v in node.values:
            if isinstance(v, ast.Constant) and isinstance(v.value, str):
                parts.append(v.value)
            else:
                parts.append("{...}")
        return "".join(parts)
    return None


def pytype_to_json(ann):
    if isinstance(ann, ast.Name):
        return {
            "str": {"type": "string"},
            "int": {"type": "integer"},
            "float": {"type": "number"},
            "bool": {"type": "boolean"},
            "dict": {"type": "object"},
            "Any": {},
        }.get(ann.id, {})
    if isinstance(ann, ast.Attribute):
        return pytype_to_json(ast.Name(id=ann.attr))
    if isinstance(ann, ast.Subscript):
        base = ann.value
        bname = base.id if isinstance(base, ast.Name) else getattr(base, "attr", "")
        sl = ann.slice
        if bname in ("list", "List", "Sequence"):
            return {"type": "array"}
        if bname in ("dict", "Dict"):
            return {"type": "object"}
        if bname == "Optional":
            return pytype_to_json(sl)
        if bname == "Annotated":
            elts = sl.elts if isinstance(sl, ast.Tuple) else [sl]
            spec = pytype_to_json(elts[0])
            for e in elts[1:]:
                if isinstance(e, ast.Call) and getattr(e.func, "id", "") == "Field":
                    for kw in e.keywords:
                        if kw.arg == "description":
                            d = py_const_str(kw.value)
                            if d:
                                spec["description"] = d
            inner = elts[0]
            aname = inner.id if isinstance(inner, ast.Name) else ""
            if not spec.get("type") and "Url" in aname:
                spec = {"type": "string", "format": "uri"}
            return spec
    if isinstance(ann, ast.BinOp) and isinstance(ann.op, ast.BitOr):
        return pytype_to_json(ann.left)
    return {}


def extract_py(src):
    tree = ast.parse(src)
    enum_map = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.ClassDef):
            for stmt in node.body:
                if isinstance(stmt, ast.Assign) and len(stmt.targets) == 1:
                    t = stmt.targets[0]
                    if isinstance(t, ast.Name) and isinstance(stmt.value, ast.Constant):
                        enum_map[f"{node.name}.{t.id}"] = stmt.value.value

    def model_to_schema(model_name):
        props = {}
        for node in ast.walk(tree):
            if isinstance(node, ast.ClassDef) and node.name == model_name:
                for stmt in node.body:
                    if isinstance(stmt, ast.AnnAssign) and isinstance(stmt.target, ast.Name):
                        spec = pytype_to_json(stmt.annotation)
                        is_field_call = (
                            isinstance(stmt.value, ast.Call)
                            and getattr(stmt.value.func, "id", "") == "Field"
                        )
                        if is_field_call:
                            for kw in stmt.value.keywords:
                                if kw.arg == "description":
                                    d = py_const_str(kw.value)
                                    if d:
                                        spec["description"] = d
                        props[stmt.target.id] = spec
        return {"type": "object", "properties": props}

    tools, prompts = [], []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        fname = getattr(node.func, "id", "")
        if fname == "Tool":
            kw = {k.arg: k.value for k in node.keywords}
            name_node = kw.get("name")
            name = py_const_str(name_node)
            if name is None and isinstance(name_node, ast.Attribute):
                name = enum_map.get(f"{name_node.value.id}.{name_node.attr}")
            if isinstance(name_node, ast.Call):
                f = name_node.func
                if isinstance(f, ast.Attribute) and isinstance(f.value, ast.Attribute):
                    name = enum_map.get(f"{f.value.value.id}.{f.value.attr}")
            tool = {"name": name or "?", "annotations": {}}
            tool["description"] = py_const_str(kw.get("description")) or ""
            sch = kw.get("inputSchema")
            if isinstance(sch, ast.Call) and getattr(sch.func, "attr", "") == "model_json_schema":
                model = sch.func.value.id if isinstance(sch.func.value, ast.Name) else "?"
                tool["inputSchema"] = model_to_schema(model)
            else:
                tool["inputSchema"] = {"type": "object", "properties": {}}
            ann = kw.get("annotations")
            if isinstance(ann, ast.Call):
                for ak in ann.keywords:
                    if isinstance(ak.value, ast.Constant):
                        tool["annotations"][ak.arg] = ak.value.value
            tools.append(tool)
        elif fname == "Prompt":
            kw = {k.arg: k.value for k in node.keywords}
            prompts.append(
                {
                    "name": py_const_str(kw.get("name")) or "?",
                    "description": py_const_str(kw.get("description")) or "",
                    "template": "",
                }
            )
    return tools, [], prompts


# ---------------------------------------------------------------------------


def main():
    ap = argparse.ArgumentParser(description="Build an mcp-audit manifest from server source.")
    ap.add_argument("--ts", help="TypeScript server source file")
    ap.add_argument("--py", help="Python server source file")
    ap.add_argument("--name", required=True, help="server name for the manifest")
    ap.add_argument("--version", default="0.0.0", help="server version for the manifest")
    args = ap.parse_args()
    if bool(args.ts) == bool(args.py):
        ap.error("pass exactly one of --ts or --py")
    path = args.ts or args.py
    src = open(path, encoding="utf-8").read()
    tools, resources, prompts = extract_ts(src) if args.ts else extract_py(src)
    manifest = {
        "server": {"name": args.name, "version": args.version},
        "tools": tools,
        "resources": resources,
        "prompts": prompts,
    }
    print(json.dumps(manifest, indent=2))


if __name__ == "__main__":
    main()
