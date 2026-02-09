#!/usr/bin/env python3
"""
CBS.log DLL Change Parser
Extracts all DLL changes from Windows Component-Based Servicing logs
"""

import re
import sys
import argparse
from pathlib import Path
from collections import defaultdict
import csv


class CBSLogParser:
    def __init__(self, log_path):
        self.log_path = Path(log_path)
        self.dll_changes = []
        
        if not self.log_path.exists():
            raise FileNotFoundError(f"Log file not found: {log_path}")
    
    def parse(self, filter_dll=None):
        """Parse the CBS.log file and extract DLL changes"""
        
        print(f"[+] Parsing CBS.log: {self.log_path}")
        
        with open(self.log_path, 'r', encoding='utf-8', errors='ignore') as f:
            lines = f.readlines()
        
        for i, line in enumerate(lines):
            installed_match = re.search(r'CSI.*Installed.*?([a-zA-Z0-9_\-]+\.dll).*?version\s+([\d\.]+)', line, re.IGNORECASE)
            if installed_match:
                dll_name = installed_match.group(1)
                version = installed_match.group(2)
                
                if filter_dll and not re.search(filter_dll, dll_name, re.IGNORECASE):
                    continue
                
                old_path, new_path = self._find_paths(lines, i, dll_name)
                
                self.dll_changes.append({
                    'dll_name': dll_name,
                    'new_version': version,
                    'old_path': old_path,
                    'new_path': new_path
                })
            
            version_transition = re.search(r'([a-zA-Z0-9_\-]+\.dll).*?(\d+\.\d+\.\d+\.\d+).*?->.*?(\d+\.\d+\.\d+\.\d+)', line, re.IGNORECASE)
            if version_transition:
                dll_name = version_transition.group(1)
                old_ver = version_transition.group(2)
                new_ver = version_transition.group(3)
                
                if filter_dll and not re.search(filter_dll, dll_name, re.IGNORECASE):
                    continue
                
                if not any(d['dll_name'] == dll_name and d['new_version'] == new_ver for d in self.dll_changes):
                    self.dll_changes.append({
                        'dll_name': dll_name,
                        'new_version': new_ver,
                        'old_version': old_ver,
                        'old_path': None,
                        'new_path': None
                    })
            
            winsxs_match = re.search(r'WinSxS.*?\\([a-zA-Z0-9_\-]+\.dll)', line, re.IGNORECASE)
            if winsxs_match:
                dll_name = winsxs_match.group(1)
                
                if filter_dll and not re.search(filter_dll, dll_name, re.IGNORECASE):
                    continue
                
                path_match = re.search(r'\[ml:.*?\]"(.+?\.dll)"', line)
                if path_match:
                    full_path = path_match.group(1)
                    
                    if i > 0 and 'old' in lines[i-1].lower():
                        self._update_or_add(dll_name, old_path=full_path)
                    elif i > 0 and 'new' in lines[i-1].lower():
                        self._update_or_add(dll_name, new_path=full_path)
        
        self.dll_changes = self._deduplicate()
        
        print(f"[+] Found {len(self.dll_changes)} DLL changes")
        
        return self.dll_changes
    
    def _find_paths(self, lines, start_idx, dll_name):
        """Look ahead to find old/new file paths"""
        old_path = None
        new_path = None
        
        for i in range(start_idx, min(start_idx + 10, len(lines))):
            line = lines[i]
            
            if 'old file:' in line.lower():
                path_match = re.search(r'\[ml:.*?\]"(.+?\.dll)"', line)
                if path_match and dll_name.lower() in path_match.group(1).lower():
                    old_path = path_match.group(1)
            
            if 'new file:' in line.lower():
                path_match = re.search(r'\[ml:.*?\]"(.+?\.dll)"', line)
                if path_match and dll_name.lower() in path_match.group(1).lower():
                    new_path = path_match.group(1)
        
        return old_path, new_path
    
    def _update_or_add(self, dll_name, old_path=None, new_path=None):
        """Update existing entry or add new one"""
        for entry in self.dll_changes:
            if entry['dll_name'] == dll_name:
                if old_path:
                    entry['old_path'] = old_path
                if new_path:
                    entry['new_path'] = new_path
                return
        
        self.dll_changes.append({
            'dll_name': dll_name,
            'new_version': None,
            'old_path': old_path,
            'new_path': new_path
        })
    
    def _deduplicate(self):
        """Remove duplicates, keeping most complete entries"""
        dll_dict = {}
        
        for entry in self.dll_changes:
            dll_name = entry['dll_name']
            
            if dll_name not in dll_dict:
                dll_dict[dll_name] = entry
            else:
                existing = dll_dict[dll_name]
                for key in ['new_version', 'old_version', 'old_path', 'new_path']:
                    if entry.get(key) and not existing.get(key):
                        existing[key] = entry[key]
        
        return list(dll_dict.values())
    
    def export_csv(self, output_path):
        """Export results to CSV"""
        with open(output_path, 'w', newline='', encoding='utf-8') as f:
            if not self.dll_changes:
                print("[-] No DLL changes to export")
                return
            
            fieldnames = ['dll_name', 'new_version', 'old_version', 'old_path', 'new_path']
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            
            writer.writeheader()
            for entry in self.dll_changes:
                row = {k: entry.get(k, '') for k in fieldnames}
                writer.writerow(row)
        
        print(f"[+] Results exported to: {output_path}")
    
    def print_summary(self):
        """Print summary statistics"""
        if not self.dll_changes:
            print("[-] No DLL changes found")
            return
        
        print("\n=== Summary ===")
        print(f"Total DLLs changed: {len(self.dll_changes)}")
        print(f"DLLs with version info: {sum(1 for d in self.dll_changes if d.get('new_version'))}")
        print(f"DLLs with old paths: {sum(1 for d in self.dll_changes if d.get('old_path'))}")
        print(f"DLLs with new paths: {sum(1 for d in self.dll_changes if d.get('new_path'))}")
        
        print("\n=== DLL Changes ===")
        for entry in sorted(self.dll_changes, key=lambda x: x['dll_name']):
            print(f"\n{entry['dll_name']}")
            if entry.get('new_version'):
                print(f"  Version: {entry.get('old_version', '?')} -> {entry['new_version']}")
            if entry.get('old_path'):
                print(f"  Old: {entry['old_path']}")
            if entry.get('new_path'):
                print(f"  New: {entry['new_path']}")
    
    def generate_extraction_script(self, output_path='extract_dlls.ps1'):
        """Generate PowerShell script to extract DLLs from WinSxS"""
        script_lines = [
            "# DLL Extraction Script",
            "# Generated from CBS.log analysis",
            "# Run this to copy DLLs from WinSxS to current directory",
            "",
            "$ErrorActionPreference = 'SilentlyContinue'",
            ""
        ]
        
        for entry in self.dll_changes:
            dll_name = entry['dll_name']
            
            if entry.get('old_path'):
                script_lines.append(f"# Old: {dll_name}")
                script_lines.append(f"Copy-Item '{entry['old_path']}' -Destination '.\\old_{dll_name}'")
                script_lines.append("")
            
            if entry.get('new_path'):
                script_lines.append(f"# New: {dll_name}")
                script_lines.append(f"Copy-Item '{entry['new_path']}' -Destination '.\\new_{dll_name}'")
                script_lines.append("")
        
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write('\n'.join(script_lines))
        
        print(f"[+] DLL extraction script saved to: {output_path}")
        print(f"    Run: powershell -ExecutionPolicy Bypass -File {output_path}")


def main():
    parser = argparse.ArgumentParser(
        description='Parse Windows CBS.log to extract DLL changes',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python parse_cbs_dlls.py C:\\Windows\\Logs\\CBS\\CBS.log
  python parse_cbs_dlls.py C:\\Windows\\Logs\\CBS\\CBS.log -f "rasman|rras"
  python parse_cbs_dlls.py C:\\Windows\\Logs\\CBS\\CBS.log -o results.csv --extract
        """
    )
    
    parser.add_argument('log_path', help='Absolute path to CBS.log file')
    parser.add_argument('-f', '--filter', help='Filter DLLs by regex pattern (e.g., "rasman|ntdll")')
    parser.add_argument('-o', '--output', default='dll_changes.csv', help='Output CSV file (default: dll_changes.csv)')
    parser.add_argument('-e', '--extract', action='store_true', help='Generate PowerShell extraction script')
    parser.add_argument('-q', '--quiet', action='store_true', help='Suppress summary output')
    
    args = parser.parse_args()
    
    try:
        parser_obj = CBSLogParser(args.log_path)
        parser_obj.parse(filter_dll=args.filter)
        
        if not args.quiet:
            parser_obj.print_summary()
        
        parser_obj.export_csv(args.output)
        
        if args.extract:
            parser_obj.generate_extraction_script()
        
    except FileNotFoundError as e:
        print(f"[!] Error: {e}", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"[!] Unexpected error: {e}", file=sys.stderr)
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == '__main__':
    main()