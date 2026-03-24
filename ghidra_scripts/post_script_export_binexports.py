from com.google.security.binexport import BinExportExporter
from java.io import File

program_name = currentProgram.getName()
program_file = File(currentProgram.getExecutablePath())
program_dir  = program_file.getParentFile()

pe_name = program_file.getName()

output_file = File(program_dir, pe_name + ".BinExport")

addr_set = currentProgram.getMemory()
exporter = BinExportExporter()
exporter.export(output_file, currentProgram, addr_set, monitor)

print("BinExport created: " + output_file.getAbsolutePath())