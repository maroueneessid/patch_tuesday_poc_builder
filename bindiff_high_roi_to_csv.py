import sqlite3
import csv
import os
import sys
import subprocess

def run_headless_analysis(primary_bin, secondary_bin):
    # 1. Setup filenames
    base_name = os.path.basename(primary_bin).replace(".BinExport", "")
    output_dir = os.path.dirname(os.path.abspath(primary_bin))
    # BinDiff's default naming convention
    bindiff_db = os.path.join(output_dir, f"{base_name}_vs_{os.path.basename(secondary_bin).replace('.BinExport', '.BinDiff')}")
    output_csv = bindiff_db.replace(".BinDiff", "_high_yield.csv")

    # 2. Execute BinDiff Engine (CLI)
    # Ensure 'bindiff' is in your PATH. On Windows, use "C:\\Path\\To\\bindiff.exe"
    print(f"[*] Comparing {os.path.basename(primary_bin)} vs {os.path.basename(secondary_bin)}...")
    cmd = [
        "bindiff", 
        f"--primary={primary_bin}", 
        f"--secondary={secondary_bin}", 
        f"--output_dir={output_dir}"
    ]

    try:
        # Run silently (stdout/stderr piped)
        subprocess.run(cmd, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    except subprocess.CalledProcessError as e:
        print(f"[!] Error: BinDiff engine failed. Check if BinExport files are valid.\n{e}")
        return

    # 3. Extract High Yield Data from SQLite
    if not os.path.exists(bindiff_db):
        print("[!] Error: .BinDiff file was not generated.")
        return

    try:
        conn = sqlite3.connect(bindiff_db)
        cursor = conn.cursor()
        
        # Filtering for interesting logic changes only
        query = """
        SELECT 
            address1, name1, address2, name2, 
            similarity, confidence, 
            basicblocks, edges, instructions 
        FROM function
        WHERE similarity < 1.0 AND similarity > 0
        ORDER BY similarity ASC, confidence DESC
        """
        cursor.execute(query)
        rows = cursor.fetchall()

        # 4. Write Results to CSV
        with open(output_csv, 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            writer.writerow(["Addr1", "Name1", "Addr2", "Name2", "Sim", "Conf", "BBs", "Edges", "Inst"])
            for row in rows:
                row_list = list(row)
                row_list[0] = hex(row[0]) # Format addresses as Hex
                row_list[2] = hex(row[2])
                row_list[4] = f"{row[4]:.4f}" # Format floats
                row_list[5] = f"{row[5]:.4f}"
                writer.writerow(row_list)

        print(f"[+] Success! Results saved to: {output_csv}")
        

    except sqlite3.Error as e:
        print(f"[!] SQLite Error: {e}")
    finally:
        if conn: conn.close()

if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage: python script.py <primary.BinExport> <secondary.BinExport>")
    else:
        run_headless_analysis(sys.argv[1], sys.argv[2])