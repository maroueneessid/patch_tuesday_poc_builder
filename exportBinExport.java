// File: exportBinExport.java
import ghidra.app.script.GhidraScript;
import ghidra.app.util.importer.AutoImporter;
import ghidra.app.util.exporter.Exporter;
import ghidra.framework.model.DomainFile;
import ghidra.program.model.listing.Program;
import ghidra.util.task.TaskMonitor;
import com.google.security.binexport.BinExportExporter;

import java.io.File;

public class exportBinExport extends GhidraScript {

    @Override
    public void run() throws Exception {
        String[] scriptArgs = getScriptArgs();
        if (scriptArgs == null || scriptArgs.length != 2) {
            println("Usage: exportBinExport <parentDir> <binexportFilename>");
            return;
        }

        String parentDirPath = scriptArgs[0];
        String binexportFilename = scriptArgs[1];

        File parentDir = new File(parentDirPath);
        if (!parentDir.exists() || !parentDir.isDirectory()) {
            println("Invalid parent directory: " + parentDirPath);
            return;
        }

        walkAndExport(parentDir, binexportFilename);
    }

    private void walkAndExport(File dir, String binexportFilename) throws Exception {
        File[] files = dir.listFiles();
        if (files == null) return;

        for (File f : files) {
            if (f.isDirectory()) {
                walkAndExport(f, binexportFilename);
            } else if (f.isFile() && f.getName().toLowerCase().endsWith(".exe")) {
                println("Processing: " + f.getAbsolutePath());

                // Import the file into headless project
                DomainFile df = AutoImporter.importByUsingBestGuess(
                        f, null, false, TaskMonitor.DUMMY, this);
                Program program = (Program) df.getDomainObject(this, true, false, TaskMonitor.DUMMY);

                // Check for PDB in same directory
                File pdbFile = new File(f.getParentFile(), getBaseName(f) + ".pdb");
                if (pdbFile.exists()) {
                    println("Found PDB: " + pdbFile.getAbsolutePath());
                    // Load PDB (simplest way using PdbUniversalAnalyzer API)
                    ghidra.app.plugin.prototype.pdb.PdbUniversalAnalyzer.setPdbFileOption(program, pdbFile);
                }

                // Prepare output file
                File outputFile = new File(dir, getBaseName(f) + ".binexport");

                // Export using BinExport
                BinExportExporter exporter = new BinExportExporter();
                exporter.export(program, outputFile, null, TaskMonitor.DUMMY);

                program.release(this);
                println("Exported: " + outputFile.getAbsolutePath());
            }
        }
    }

    private String getBaseName(File f) {
        String name = f.getName();
        int dot = name.lastIndexOf('.');
        return (dot == -1) ? name : name.substring(0, dot);
    }
}
