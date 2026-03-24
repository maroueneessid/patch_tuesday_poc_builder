# -*- coding: utf-8 -*-
# Creates DataTypes for C++ class using Ghidra decompiled C output
#
# What it does (minimal, decompile-only):
#   1) Enumerate MSVC-style backticked vtables in Symbol Tree:
#        `vftable'  and  `vftable'{for `Base'}
#      Build (DerivedClass, BaseName) -> vtable address map.
#   2) Find constructors/Initialize-like roots per class and DECOMPILE them.
#   3) Parse C text to extract:
#        - vtable stores:
#            *(...)this = &`vftable'{for_`Base'}                 => off 0
#            *(...)&this->field_0xNNN = &`vftable'{for_`Base'}  => off NNN
#            *(...)(this + NNN) = &`vftable'{for_`Base'}        => off NNN (hex 0x.. or decimal)
#        - typed field stores (LHS cast has type):
#            *(_TYPE **)(this + NNN) = name;        -> field type = _TYPE *
#            *(_TYPE **)&this->field_0xNNN = name;  -> field type = _TYPE *
#          (if cast can't be parsed or is undefined, fallback to using RHS symbol type)
#   4) Build vtable DTs, apply at vtable addresses, and wire vptrs at parsed offsets.
#   5) Apply typed fields (skip undefined; no zero-init scaffolding).
#
#@category C++
#@runtime Jython
#@author CravateRouge

from __future__ import print_function, unicode_literals
import re

from ghidra.app.decompiler import DecompInterface, DecompileOptions
from ghidra.program.model.data import (
    DataTypeConflictHandler, CategoryPath, StructureDataType,
    FunctionDefinitionDataType, PointerDataType, VoidDataType, Pointer
)
from ghidra.program.model.symbol import SymbolType

# Optional: try to parse cast strings into DataType
try:
    from ghidra.app.util.datatype import DataTypeParser
except:
    DataTypeParser = None

# -------------------------
# Debug
# -------------------------
DEBUG = False
def dbg(msg):
    if DEBUG:
        print("[CppClassExtractor] " + str(msg))

# -------------------------
# Basics / helpers
# -------------------------
PTR_SIZE = currentProgram.getDefaultPointerSize()

def get_dtm():
    return currentProgram.getDataTypeManager()

def sanitize_name(s):
    return re.sub(r"[^A-Za-z0-9_]", "_", str(s or ""))

def parse_off_num(s):
    """Parse '0xNN' (hex) or 'NNN' (dec) to int."""
    s = s.strip()
    if s.lower().startswith("0x"):
        return int(s, 16)
    return int(s, 10)

# -------------------------
# Regex over decompiled C text
# -------------------------

# =========================
# VTABLE stores (underscore style)
# =========================
# Primary vptr at offset 0
#   *(undefined ***)this = &_vftable_;
# Captures (optional) Base if the decompiler ever prints “… = &_vftable__for__Base__”
RE_VT_THIS0 = re.compile(
    r"\*\s*\([^)]*\)\s*this\s*=\s*&_vftable_(?:_for__([A-Za-z0-9_:$]+)__)?",
    re.M
)
# Non-zero offset using + (with or without parentheses)
#   *(undefined ***)this + 0x20      = &_vftable__for__CClfsLogFcbCommon__;
#   *(undefined ***)(this + 0x250)   = &_vftable__for__IObservable__;
# Groups: (1)=offset (hex/dec), (2)=Base (if present)
RE_VT_THISPLUS = re.compile(
    r"\*\s*\([^)]*\)\s*(?:\(\s*this\s*\+\s*|this\s*\+\s*)(0x[0-9A-Fa-f]+|\d+)\s*\)?\s*=\s*&_vftable_(?:_for__([A-Za-z0-9_:$]+)__)?",
    re.M
)
# Non-zero offset using index syntax
#   this[0x15a0] = &_vftable__for__SomeBase__;
#   this[600]    = &_vftable__for__SomeBase__;
# Groups: (1)=offset (hex/dec), (2)=Base (if present)
RE_VT_THISINDEX = re.compile(
    r"this\[\s*(0x[0-9A-Fa-f]+|\d+)\s*\]\s*=\s*&_vftable_(?:_for__([A-Za-z0-9_:$]+)__)?",
    re.M
)

# =========================
# Typed field stores (LHS cast provides type)
# =========================
# Cast + (this + N) with or without parentheses:
#   *(_TYPE **)(this + 0x1590) = param_1;
#   *(_TYPE **)this + 600       = memberName;
# Groups: (1)=type, (2)=offset (hex/dec), (3)=rhs identifier
RE_TFIELD_THISPLUS = re.compile(
    r"\*\s*\(\s*([^)]+?)\s*\)\s*(?:\(\s*this\s*\+\s*|this\s*\+\s*)(0x[0-9A-Fa-f]+|\d+)\s*\)?\s*=\s*([_A-Za-z]\w*)\s*;",
    re.M
)
# Cast + index syntax:
#   *(_TYPE ** )this[0x15a0] = memberName;
#   *(_TYPE *)  this[600]     = someVar;
# Groups: (1)=type, (2)=offset (hex/dec), (3)=rhs identifier
RE_TFIELD_THISINDEX = re.compile(
    r"\*\s*\(\s*([^)]+?)\s*\)\s*this\[\s*(0x[0-9A-Fa-f]+|\d+)\s*\]\s*=\s*([_A-Za-z]\w*)\s*;",
    re.M
)

# -------------------------
# Vftable symbols (Symbol Tree)
# -------------------------
VTABLE_RE      = re.compile(r"^`vftable'\{for[ _]`([^']+)'\}$")  # `vftable'{for `Base'}
VTABLE_SELF_RE = re.compile(r"^`vftable'$")                      # `vftable'

def full_ns(sym):
    ns = sym.getParentNamespace()
    names = []
    while ns and not ns.isGlobal():
        names.append(ns.getName())
        ns = ns.getParentNamespace()
    return "::".join(names[::-1])

def parse_vftable_symbol(sym):
    if sym.getSymbolType() != SymbolType.LABEL:
        return None
    nm = sym.getName()
    cls = full_ns(sym) or "Anonymous"
    if VTABLE_SELF_RE.match(nm):
        return (cls, None, sym.getAddress())
    m = VTABLE_RE.match(nm)
    if m:
        return (cls, m.group(1), sym.getAddress())
    return None

def iter_vftable_symbols():
    st = currentProgram.getSymbolTable()
    it = st.getAllSymbols(True)
    seen = set()
    for s in it:
        info = parse_vftable_symbol(s)
        if not info:
            continue
        cls, fr, addr = info
        if addr in seen:
            continue
        seen.add(addr)
        dbg("vftable sym: %s%s @ %s" % (cls, ("{for " + fr + "}" if fr else ""), addr))
        yield info

# -------------------------
# Decompile helpers (text)
# -------------------------
def decompile_function(func):
    iface = DecompInterface()
    iface.setOptions(DecompileOptions())
    iface.openProgram(currentProgram)
    res = iface.decompileFunction(func, 30, monitor)
    try:
        if res and res.getDecompiledFunction():
            return res
    except:
        pass
    return None

def get_decompiled_text(func):
    res = decompile_function(func)
    if not res: return "", None
    try:
        return res.getDecompiledFunction().getC() or "", res
    except:
        return "", res

def build_symbol_typemap(res):
    """
    From a DecompileResults 'res', build {symbolName: DataType} using the decompiler's symbol map.
    """
    m = {}
    try:
        hf = res.getHighFunction()
        if not hf:
            return m
        symmap = hf.getLocalSymbolMap()
        it = symmap.getSymbols()
        while it.hasNext():
            s = it.next()
            nm, dt = s.getName(), s.getDataType()
            if nm and dt:
                m[nm] = dt
    except:
        pass
    return m

# -------------------------
# Roots (constructors + Initialize/Init*)
# -------------------------
INIT_METHOD_NAMES = {"Initialize", "InitializeEx", "Init", "InitEx", "InitInstance", "Setup", "Start"}

def iter_class_roots(cls):
    st = currentProgram.getSymbolTable()
    fm = currentProgram.getFunctionManager()
    seen = set()

    # Demangled class namespace
    it = st.getSymbols(cls)
    for sym in it:
        f = getFunctionAt(sym.getAddress())
        if not f: continue
        ns = f.getParentNamespace()
        if not ns or ns.getName() != cls: continue
        name = f.getName()
        if name == cls or name in INIT_METHOD_NAMES:
            ep = f.getEntryPoint()
            if ep not in seen:
                seen.add(ep)
                dbg("root(demangled): %s @ %s" % (name, ep))
                yield f

    # Mangled patterns (MSVC)
    it2 = fm.getFunctions(True)
    while it2.hasNext():
        f = it2.next()
        ep = f.getEntryPoint()
        if ep in seen: continue
        nm = f.getName()
        if nm.startswith("??0" + cls + "@@"):  # ctor
            seen.add(ep); dbg("root(mangled): %s @ %s" % (nm, ep)); yield f; continue
        for base in INIT_METHOD_NAMES:
            if nm.startswith("?" + base + "@" + cls + "@@"):
                seen.add(ep); dbg("root(mangled): %s @ %s" % (nm, ep)); yield f; break

# -------------------------
# Build vtable data types (walk memory, not instructions)
# -------------------------
def make_funcptr_dt(func):
    sig = func.getSignature()
    fdef = FunctionDefinitionDataType(sig)
    nm = sanitize_name(sig.getPrototypeString())
    cat = CategoryPath("/funcptrs")
    get_dtm().createCategory(cat)
    fdef.setNameAndCategory(cat, nm)
    return get_dtm().getPointer(fdef)

def walk_vftable(start):
    mem = currentProgram.getMemory()
    blk = mem.getBlock(start)
    if not blk:
        return []
    funcs = []
    a = start
    end = blk.getEnd()
    while a <= end:
        try:
            if PTR_SIZE == 8:
                val = getLong(a)
            else:
                val = getInt(a) & 0xffffffff
        except:
            break
        if val == 0:
            break
        tgt = toAddr(val)
        # Require code or executable memory
        f = getFunctionAt(tgt)
        if not f:
            mb = getMemoryBlock(tgt)
            if not (mb and mb.isExecute()):
                break
        funcs.append(tgt)
        a = a.add(PTR_SIZE)
    return funcs

def build_vtable_struct_type(derived_class, for_base, func_addrs):
    dtm = get_dtm()
    cat = "/vftables/" + sanitize_name(derived_class)
    sub = ""
    if for_base:
        sub = "/for_" + sanitize_name(for_base)
    cpath = CategoryPath(cat + sub)
    dtm.createCategory(cpath)

    dt = dtm.getDataType(cpath, "vftable")
    if dt is None:
        dt = StructureDataType(cpath, "vftable", 0)
    dt.deleteAll()

    for i, faddr in enumerate(func_addrs):
        f = getFunctionAt(faddr)
        if f:
            comp = make_funcptr_dt(f)
            nm = f.getName()
        else:
            comp = PointerDataType()
            nm = "slot_%d" % i
        dt.add(comp, PTR_SIZE, nm, "")

    dt = dtm.addDataType(dt, DataTypeConflictHandler.KEEP_HANDLER)
    return dt

# -------------------------
# Class struct helpers
# -------------------------
def get_or_create_struct(name):
    dtm = get_dtm()
    cat = CategoryPath("/classes")
    dtm.createCategory(cat)
    dt = dtm.getDataType(cat, name)
    if dt is None:
        dt = StructureDataType(cat, name, 0)
        dt = dtm.addDataType(dt, DataTypeConflictHandler.KEEP_HANDLER)
        dbg("%s: created empty struct" % name)
    return dt

def ensure_len_at_least(name, size):
    if size <= 0:
        get_or_create_struct(name); return
    dt = get_or_create_struct(name)
    if dt.getLength() < size:
        dt.growStructure(size - dt.getLength())
        get_dtm().addDataType(dt, DataTypeConflictHandler.KEEP_HANDLER)
        dbg("%s: grow size -> 0x%X" % (name, size))

def add_or_replace_at_offset(dt, off, comp_dt, nm, cmt=""):
    # remove overlaps
    to_del = []
    for i in range(dt.getNumComponents()):
        c = dt.getComponent(i)
        if not c: continue
        cs, ce = c.getOffset(), c.getOffset() + c.getLength()
        if max(cs, off) < min(ce, off + comp_dt.getLength()):
            to_del.append(i)
    for i in reversed(to_del):
        dt.delete(i)
    dt.insertAtOffset(off, comp_dt, comp_dt.getLength(), nm, cmt)
    get_dtm().addDataType(dt, DataTypeConflictHandler.KEEP_HANDLER)

def safe_clear(start_addr, size):
    if size and size > 0:
        try:
            clearListing(start_addr, start_addr.add(size - 1))
        except Exception as e:
            dbg("safe_clear failed @%s size=%d: %s" % (start_addr, size, e))

# -------------------------
# Decompile-text parsing
# -------------------------
def collect_vfptr_offsets_from_text(ctext, derived_class, vt_addr_map):
    """
    Find vptr stores in decompiled text. Return dict { vtable_addr : offset }.
    """
    out = {}
    # offset 0:
    for m in RE_VT_THIS0.finditer(ctext):
        base = m.group(1)
        # If no base probably means it's the derived_class own vtable
        if not base:
            base = derived_class
        a = vt_addr_map.get((derived_class, base))
        if a and a not in out:
            out[a] = 0
    # &this->field_0xNNN:
    for m in RE_VT_THISINDEX.finditer(ctext):
        off_hex, base = m.group(1), m.group(2)
        if not base:
            base = derived_class
        a = vt_addr_map.get((derived_class, base))
        if a and a not in out:
            out[a] = int(off_hex, 16)
    # (this + NNN):
    for m in RE_VT_THISPLUS.finditer(ctext):
        off_str, base = m.group(1), m.group(2)
        if not base:
            base = derived_class
        a = vt_addr_map.get((derived_class, base))
        if a and a not in out:
            out[a] = parse_off_num(off_str)

    if out:
        dbg("vptr(text) %s: %s" % (derived_class, ", ".join("0x%X@%s" % (o, a) for a,o in out.items())))
    return out

def _deref_one(dt):
    """Return the pointed-to DataType if dt is a Pointer; else dt."""
    try:
        if isinstance(dt, Pointer):
            inner = dt.getDataType()
            return inner or VoidDataType()
    except:
        pass
    return dt

def _dt_from_cast_string_for_field(type_str, rhs_name=None, rhs_types=None):
    """
    Build the **field** DataType from the LHS cast string:
      *(_T **)(this+off)  ==> field type is _T *   (dereference one level)
    If parsing fails or yields 'undefined', try RHS symbol type (param/local).
    """
    if not type_str:
        return None
    t = type_str.strip()
    if "undefined" in t.lower():
        t = ""

    # Try parser
    parsed_dt = None
    if t and DataTypeParser is not None:
        try:
            parser = DataTypeParser(get_dtm(), None, True, monitor)
            parsed_dt = parser.parse(t)
        except:
            parsed_dt = None

    if parsed_dt:
        return _deref_one(parsed_dt)

    # Fallback: use RHS symbol type
    if rhs_name and rhs_types:
        dt = rhs_types.get(rhs_name)
        if dt and "undefined" not in (dt.getDisplayName() or "").lower():
            return dt

    return None

def collect_typed_fields_from_text(ctext, rhs_types):
    """
    Parse typed field stores from decompiled text.
    Returns dict off -> (DataType, field_name)
    """
    result = {}

    def add(off_str, type_str, rhs_name):
        dt = _dt_from_cast_string_for_field(type_str, rhs_name=rhs_name, rhs_types=rhs_types)
        if not dt:  # skip if we still don't have a meaningful type
            return
        off = parse_off_num(off_str)
        nm = sanitize_name(rhs_name)
        if off not in result:
            result[off] = (dt, nm)

    for m in RE_TFIELD_THISPLUS.finditer(ctext):
        type_str, off_str, rhs = m.group(1), m.group(2), m.group(3)
        add(off_str, type_str, rhs)

    for m in RE_TFIELD_THISINDEX.finditer(ctext):
        type_str, off_hex, rhs = m.group(1), m.group(2), m.group(3)
        add(off_hex, type_str, rhs)

    if result:
        dbg("fields(text): " + ", ".join("0x%X:%s" % (o, dt.getDisplayName()) for o,(dt,_) in sorted(result.items())))
    return result

# -------------------------
# Connect vtable to class
# -------------------------
def connect_vtable_to_class(derived_class, for_base, vtable_dt, vtable_addr, vf_offsets):
    if vtable_addr not in vf_offsets:
        return
    off = int(vf_offsets[vtable_addr]) & 0xffffffff
    ensure_len_at_least(derived_class, off + PTR_SIZE)
    dt = get_or_create_struct(derived_class)
    ptr_dt = get_dtm().getPointer(vtable_dt)
    fname  = "vptr" if not for_base else ("vptr_for_" + sanitize_name(for_base))
    # Construct a helpful comment like "CClfsLogFcbPhysical/for_CClfsLogFcbCommon/vftable"
    cmt = sanitize_name(derived_class)
    if for_base:
        cmt += "/for_" + sanitize_name(for_base)
    cmt += "/vftable"
    add_or_replace_at_offset(dt, off, ptr_dt, fname, cmt)

# -------------------------
# Main
# -------------------------
def main():
    # 0) Gather vftable symbols and build (derived, base) -> address map
    vt_syms = list(iter_vftable_symbols())
    if not vt_syms:
        dbg("No vtable symbols found; nothing to do.")
        return

    vt_addr_map = {}  # (derived_class, base_name) -> Address
    class_to_addrs = {}
    for cls, fr, addr in vt_syms:
        if fr:
            vt_addr_map[(cls, fr)] = addr
        else:
            # Keep a self key just in case a decompiler print omits {for_...} (rare).
            vt_addr_map[(cls, cls)] = addr
        class_to_addrs.setdefault(cls, []).append(addr)

    # 1) Analysis (decompile-only): per-class
    per_class_vfmap   = {}  # { vtable_addr : offset }
    per_class_fields  = {}  # { off : (DataType, name) }
    for cls in class_to_addrs.keys():
        vfmap = {}
        field_map = {}

        for f in iter_class_roots(cls):
            ctext, res = get_decompiled_text(f)
            if not ctext or not res:
                continue
            rhs_types = build_symbol_typemap(res)

            # vptr offsets from text
            add_v = collect_vfptr_offsets_from_text(ctext, cls, vt_addr_map)
            for a, o in add_v.items():
                if a not in vfmap:
                    vfmap[a] = o

            # typed fields from text
            add_fields = collect_typed_fields_from_text(ctext, rhs_types)
            for off, (dt, nm) in add_fields.items():
                if off not in field_map:
                    field_map[off] = (dt, nm)
                    
        # If a class has no vtable connected at all, fall back to default vtable at offset 0
        if not vfmap:
            default_addr = vt_addr_map.get((cls, cls))
            if default_addr:
                vfmap[default_addr] = 0
                dbg("Added fallback default vftable for class %s at offset 0" % cls)
            
        per_class_vfmap[cls]  = vfmap
        per_class_fields[cls] = field_map
        dbg("%s: final vfptr map: %s" % (cls, ", ".join("0x%X@%s" % (o, a) for a,o in vfmap.items()) or "{}"))

    # 2) Build/apply vtable DTs; connect to DERIVED at inferred offsets
    for cls, for_base, addr in vt_syms:
        # build vtable DT from memory
        funcs = walk_vftable(addr)
        vt_dt = build_vtable_struct_type(cls, for_base, funcs)

        # apply DT at vtable address
        safe_clear(addr, vt_dt.getLength())
        try:
            createData(addr, vt_dt)
        except Exception as e:
            dbg("createData vtable @%s failed: %s" % (addr, e))

        # connect to derived
        vfmap = per_class_vfmap.get(cls, {})
        connect_vtable_to_class(cls, for_base, vt_dt, addr, vfmap)
                
    # 3) Apply typed fields (skip offsets used by vptrs)
    for cls, fmap in per_class_fields.items():
        if not fmap:
            continue
        reserved = set(per_class_vfmap.get(cls, {}).values())
        dt = get_or_create_struct(cls)

        # ensure size large enough
        max_end = 0
        for off, (fdt, _) in fmap.items():
            sz = fdt.getLength()
            if sz <= 0: sz = PTR_SIZE
            max_end = max(max_end, off + sz)
        ensure_len_at_least(cls, max_end)

        for off, (fdt, name) in sorted(fmap.items()):
            if off in reserved:
                continue
            add_or_replace_at_offset(dt, off, fdt, sanitize_name(name), "")

    dbg("Done.")

# ------------------------------------------------------------
if __name__ == "__main__":
    main()