# 1. Extract C++ Classes
print("Starting Step 1: CppClassExtractor...")
runScript("CppClassExtractor.py")

# 2. Merge Datatypes
print("Starting Step 2: DatatypeMerger...")
runScript("DatatypeMerger.py")

# 3. Export BinExport files
print("Starting Step 3: post_script_export_binexports...")
runScript("post_script_export_binexports.py")

print("--- Workflow Completed Successfully ---")