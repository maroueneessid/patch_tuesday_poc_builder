from com.google.security.binexport import BinExportExporter
from java.io import File

# Get the program name (e.g., "RasMediaManager.dll")
program_name = currentProgram.getName()

# Use Java's File class for cross-platform path handling
program_file = File(currentProgram.getExecutablePath())
program_dir = program_file.getParentFile()

# Get PE name without extension
if program_name.endswith(".dll"):
    pe_name = program_name[:-4]
elif program_name.endswith(".exe"):
    pe_name = program_name[:-4]
else:
    pe_name = program_name

# Determine if patched or unpatched based on parent directory name
parent_dir_name = program_dir.getParentFile().getName()

if parent_dir_name == "patched":
    prefix = "patched"
elif parent_dir_name == "unpatched":
    prefix = "unpatched"
else:
    prefix = "unknown"

# Remove "Unpatched_" prefix if it exists in the name
if pe_name.startswith("Unpatched_"):
    pe_name = pe_name[10:]

# Construct path: go up 2 levels to base, then into diffs/<pe_name>/
base_dir = program_dir.getParentFile().getParentFile()
diffs_dir = File(base_dir, "diffs")
pe_diffs_dir = File(diffs_dir, pe_name)

# Create directories if they don't exist
if not pe_diffs_dir.exists():
    pe_diffs_dir.mkdirs()

# Create output file
output_filename = prefix + "_" + pe_name + ".BinExport"
output_file = File(pe_diffs_dir, output_filename)

# Export
addr_set = currentProgram.getMemory()
exporter = BinExportExporter()
exporter.export(output_file, currentProgram, addr_set, monitor)

print("BinExport created: " + output_file.getAbsolutePath())