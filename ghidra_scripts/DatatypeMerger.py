# -*- coding: utf-8 -*-
# Replace empty composites (structures/unions) in the current Program archive by the
# first non-empty same-named definition found in other open data type archives.
#
# What it does:
#   1) Enumerate Structure/Union types in the Program DTM; mark as "empty" if
#      getNumComponents()==0 or isNotYetDefined()==True.
#   2) For each empty, scan ALL open DTMs and
#      pick the first non-empty match by name
#
#@category Data Types
#@runtime Jython
#@author CravateRouge

from __future__ import print_function, unicode_literals
from ghidra.app.services import DataTypeManagerService
from ghidra.program.model.data import (
    Structure, Union, DataTypeConflictHandler
)

# -------------------------
# Debug
# -------------------------
DEBUG = True
def dbg(msg):
    if DEBUG:
        print("[DatatypeMerger] " + str(msg))


# -------------------------
# Helpers
# -------------------------
def get_program_dtm():
    return currentProgram.getDataTypeManager()

def safe_dtm_name(dtm):
    try:
        n = dtm.getName()
        return n if n else "<unnamed>"
    except Exception:
        return "<unknown-dtm>"

def fmt_dt(dt):
    try:
        return "%s%s" % (dt.getCategoryPath(), dt.getName())
    except Exception:
        return "<unnamed-datatype>"

def walk_category(cat):
    """Depth-first walk of all datatypes in a Category tree."""
    try:
        for dt in cat.getDataTypes():
            yield dt
        for sub in cat.getCategories():
            for dt in walk_category(sub):
                yield dt
    except Exception as e:
        dbg("Category walk error: %s" % str(e))
        return

def is_empty_composite(dt):
    """True if dt is Structure/Union and has 0 components or isNotYetDefined()."""
    if not isinstance(dt, (Structure, Union)):
        return False
    try:
        if dt.isNotYetDefined():
            return True
    except Exception:
        pass
    try:
        return dt.getNumComponents() == 0
    except Exception:
        return False

def _safe_comp_count(dt):
    try:
        return dt.getNumComponents()
    except Exception:
        return "?"

# Good idea but empty can be UNION when it's actually a STRUCTURE
# def is_non_empty_same_kind(dt, dt_cand):
    # """Same kind and non-empty."""
    # if type(dt_cand)== type(dt):
        # try:
            # return (not dt_cand.isNotYetDefined()) and (dt_cand.getNumComponents() > 0)
        # except Exception as e:
            # dbg("Cannot compare %s with %s: %s" % (fmt_dt(dt), fmt_dt(dt_cand), str(e)))
            # return False
    # return False

def find_first_non_empty_match(search_dtms, empty_dt):
    """Search archives for the first non-empty same-kind match."""
    name = empty_dt.getName()
    cpath = empty_dt.getCategoryPath()

    for dtm in search_dtms:
        dbg("Search in DTM: %s for name=%s in cat=%s" % (safe_dtm_name(dtm), name, cpath))
        cand_list = []            
        dtm.findDataTypes(name, cand_list)

        for cand in cand_list:
            if not is_empty_composite(cand):
                dbg("Found %s (comps=%s)" % (fmt_dt(cand), _safe_comp_count(cand)))
                return cand
    return None

def get_search_dtms():
    """Return list of all DTMs."""
    tool = state.getTool()
    if tool is None:
        dbg("No tool context; open in GUI.")
        return []
    service = tool.getService(DataTypeManagerService)
    if service is None:
        dbg("DataTypeManagerService not available.")
        return []


    all_dtms = list(service.getDataTypeManagers())
    dbg("All open DTMs (%d): %s" % (len(all_dtms), ", ".join(safe_dtm_name(d) for d in all_dtms)))
    
    return all_dtms

    # search = []
    # prog_dtm = get_program_dtm()
    # for dtm in all_dtms:
        # if dtm is prog_dtm:
            # dbg("Skip Program DTM: %s" % safe_dtm_name(dtm))
            # continue
        # nm = (dtm.getName() or "").lower()
        # if nm == "built-in" or "built in" in nm:
            # dbg("Skip Built-In DTM: %s" % safe_dtm_name(dtm))
            # continue
        # search.append(dtm)

    # dbg("Search DTMs (%d): %s" % (len(search), ", ".join(safe_dtm_name(d) for d in search)))
    # return search

# -------------------------
# Main
# -------------------------
def main():
    prog_dtm = get_program_dtm()
    dbg("Program DTM: %s" % safe_dtm_name(prog_dtm))

    search_dtms = get_search_dtms()
    if not search_dtms:
        dbg("No external archives are open; nothing to search.")
        return

    # Collect empty composites in Program
    empty_list = []
    root = prog_dtm.getRootCategory()
    for dt in walk_category(root):
        if is_empty_composite(dt):
            dbg("Found empty: %s (comps=%s)" % (fmt_dt(dt), _safe_comp_count(dt)))
            empty_list.append(dt)

    dbg("Empty composites found in Program: %d" % len(empty_list))
    if not empty_list:
        return

    replaced = 0
    skipped  = 0
    
    tx = prog_dtm.startTransaction("Replace empty composites from open archives")
    try:
        total = len(empty_list)
        for idx, empty_dt in enumerate(empty_list, 1):
            if monitor and monitor.isCancelled():
                break

            dbg("==> [%d/%d] Try replace: %s (comps=%s)" %
                (idx, total, fmt_dt(empty_dt), _safe_comp_count(empty_dt)))

            cand = find_first_non_empty_match(search_dtms, empty_dt)
            if cand is None:
                dbg("Non-empty match not found for %s" % fmt_dt(empty_dt))
                skipped += 1
                continue

            dbg("Using candidate: %s (from %s; comps=%s)" %
                (fmt_dt(cand), safe_dtm_name(cand.getDataTypeManager()), _safe_comp_count(cand)))

            try:
                prog_dtm.replaceDataType(empty_dt, cand, False)
                replaced += 1
                dbg("Replaced: %s  <-  %s (from %s)" %
                      (fmt_dt(empty_dt), fmt_dt(cand), safe_dtm_name(cand.getDataTypeManager())))
            except Exception as e:
                dbg("Replacement failed for %s: %s" % (fmt_dt(empty_dt), str(e)))
                skipped += 1

    finally:
        prog_dtm.endTransaction(tx, True)

    dbg("Summary:")
    dbg("Processed empties : %d" % len(empty_list))
    dbg("Replaced          : %d" % replaced)
    dbg("No match/failed   : %d" % skipped)
    dbg("Done.")

# ------------------------------------------------------------
if __name__ == "__main__":
    main()