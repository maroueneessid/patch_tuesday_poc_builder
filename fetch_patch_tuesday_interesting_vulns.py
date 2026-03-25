#!/usr/bin/env python3
"""
Microsoft MSRC CVRF API - Patch Tuesday CVE Fetcher
Fetches all CVEs from current month's security update where exploitability is "More Likely" or "Detected".

Author: Security Research Assistant
License: MIT
"""

import requests
import json
import sys
from datetime import datetime
from typing import List, Dict, Optional
import argparse


class MSRCAPIClient:
    """Client for Microsoft Security Response Center CVRF API."""
    
    BASE_URL = "https://api.msrc.microsoft.com"
    
    def __init__(self, api_token: Optional[str] = None):
        self.headers = {
            'Accept': 'application/json',
            'Content-Type': 'application/json'
        }
        if api_token:
            self.headers['Authorization'] = f'Bearer {api_token}'
    
    def get_cvrf(self, month_year: Optional[str] = None) -> Optional[Dict]:
        """
        Get the CVRF document for a given month.
        
        Args:
            month_year: Optional "YYYY-MM" or "YYYY-Mon" string (e.g. "2025-03" or "2025-Mar").
                        Defaults to current month.
        """
        try:
            if month_year:
                # Accept both "2025-03" and "2025-Mar"
                for fmt in ("%Y-%m", "%Y-%b"):
                    try:
                        dt = datetime.strptime(month_year, fmt)
                        break
                    except ValueError:
                        continue
                else:
                    print(f"ERROR: Invalid month format '{month_year}'. Use YYYY-MM or YYYY-Mon (e.g. 2025-03, 2025-Mar)")
                    sys.exit(1)
            else:
                dt = datetime.now()
            
            slug = f"{dt.year}-{dt.strftime('%b')}"
            print(f"Fetching CVRF document for: {slug}")
            
            response = requests.get(
                f"{self.BASE_URL}/cvrf/{slug}",
                headers=self.headers,
                timeout=30
            )
            
            if response.status_code == 200:
                return response.json()
            elif response.status_code == 401:
                print("ERROR: Unauthorized - API token required for historical data")
                sys.exit(1)
            else:
                print(f"ERROR: Failed to fetch CVRF document: {response.status_code}")
                sys.exit(1)
                
        except requests.exceptions.Timeout:
            print("ERROR: Request timeout - try again later")
            sys.exit(1)
        except Exception as e:
            print(f"ERROR: {e}")
            sys.exit(1)


def get_exploitability(vuln: Dict) -> Optional[str]:
    """
    Extract exploitability assessment from the Threats array.
    In CVRF schema, Threats with Type==1 contain exploit status.
    The actual value is in Description.Value as a string.
    """
    for threat in vuln.get('Threats', []):
        if threat.get('Type') == 1:
            desc = threat.get('Description', {})
            # Handle both dict and string forms
            if isinstance(desc, dict):
                return desc.get('Value', '')
            elif isinstance(desc, str):
                return desc
    return None


def is_high_exploitability(exploit_str: Optional[str]) -> bool:
    """Check if exploitability string indicates Detected or More Likely."""
    if not exploit_str:
        return False
    lowered = exploit_str.strip().lower()
    return ('exploitation detected' in lowered or 
            'exploitation more likely' in lowered)


def get_severity(vuln: Dict) -> Optional[str]:
    """Extract max severity from Threats array (Type==3)."""
    for threat in vuln.get('Threats', []):
        if threat.get('Type') == 3:
            desc = threat.get('Description', {})
            if isinstance(desc, dict):
                return desc.get('Value')
            return desc
    return None


def get_cvss_info(vuln: Dict) -> Dict:
    """Extract CVSS score and vector from CVSSScoreSets."""
    result = {'BaseScore': None, 'Vector': None}
    score_sets = vuln.get('CVSSScoreSets', [])
    if score_sets:
        best = score_sets[0]
        result['BaseScore'] = best.get('BaseScore')
        result['Vector'] = best.get('Vector')
    return result


def fetch_cves_with_high_exploitability(
    client: MSRCAPIClient, 
    output_format: str = "json",
    month_year: Optional[str] = None
) -> str:
    """Fetch all CVEs from a given month with high exploitability."""
    cvrf_doc = client.get_cvrf(month_year)
    if not cvrf_doc:
        return ""
    
    vulnerabilities = cvrf_doc.get('Vulnerability', [])
    cves = []
    
    print(f"Found {len(vulnerabilities)} total CVEs in current month")
    print("-" * 80)
    
    for vuln in vulnerabilities:
        exploit_str = get_exploitability(vuln)
        
        if is_high_exploitability(exploit_str):
            cvss = get_cvss_info(vuln)
            cve_info = {
                'CVE_ID': vuln.get('CVE', 'N/A'),
                'Title': vuln.get('Title', {}).get('Value', '') if isinstance(vuln.get('Title'), dict) else vuln.get('Title', ''),
                'Severity': get_severity(vuln),
                'Exploitability': exploit_str.strip(),
                'CVSS_BaseScore': cvss['BaseScore'],
                'CVSS_Vector': cvss['Vector'],
            }
            cves.append(cve_info)
    
    print(f"Found {len(cves)} CVEs with high exploitability (Detected or More Likely)")
    print("-" * 80)
    
    if output_format == "json":
        return json.dumps(cves, indent=2)
    elif output_format == "csv":
        return _output_csv(cves)
    else:
        return _output_text(cves)


def _output_csv(data: List[Dict]) -> str:
    """Output data as CSV format."""
    if not data:
        return ""
    
    headers = list(data[0].keys())
    lines = [','.join(headers)]
    
    for cve in data:
        row = []
        for header in headers:
            value = cve.get(header, '')
            if value is None:
                value = ''
            value = str(value)
            if ',' in value or '"' in value:
                value = f'"{value}"'
            row.append(value)
        lines.append(','.join(row))
    
    return '\n'.join(lines)


def _output_text(data: List[Dict]) -> str:
    """Output data as formatted text."""
    if not data:
        return "No CVEs found with high exploitability."
    
    lines = []
    lines.append("\n" + "=" * 80)
    lines.append("MICROSOFT MSRC - HIGH EXPLOITABILITY CVEs (Current Month)")
    lines.append("=" * 80)
    
    for i, cve in enumerate(data, 1):
        lines.append(f"\n{i}. {cve['CVE_ID']}")
        lines.append(f"   Title:          {cve['Title']}")
        lines.append(f"   Severity:       {cve['Severity']}")
        lines.append(f"   Exploitability: {cve['Exploitability']}")
        lines.append(f"   CVSS Score:     {cve['CVSS_BaseScore']}")
        lines.append(f"   CVSS Vector:    {cve['CVSS_Vector']}")
    
    return '\n'.join(lines)


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description='Fetch CVEs from MSRC with high exploitability (More Likely or Detected)'
    )
    parser.add_argument(
        '--token', '-t',
        type=str,
        help='Azure AD token for historical data access'
    )
    parser.add_argument(
        '--month', '-m',
        type=str,
        help='Month to query: YYYY-MM or YYYY-Mon (e.g. 2025-03, 2025-Mar). Defaults to current month.'
    )
    parser.add_argument(
        '--format', '-f',
        choices=['json', 'csv', 'text'],
        default='text',
        help='Output format (default: text)'
    )
    
    args = parser.parse_args()
    client = MSRCAPIClient(api_token=args.token)
    result = fetch_cves_with_high_exploitability(client, args.format, args.month)
    if result:
        print(result)


if __name__ == '__main__':
    main()