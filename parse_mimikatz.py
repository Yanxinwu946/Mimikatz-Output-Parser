#!/usr/bin/env python3

import re
import sys
import argparse
from collections import defaultdict


def parse_mimikatz_output(content):
    """Parse mimikatz output and extract user credentials."""
    
    # Dictionary to store parsed results
    results = defaultdict(list)
    
    # Find all authentication blocks
    auth_blocks = re.findall(r'Authentication Id[\s\S]+?(?=Authentication Id|mimikatz\(commandline\)|$)', content)
    
    for block in auth_blocks:
        # Extract user information
        username_match = re.search(r'User Name\s+:\s+(.+)', block)
        domain_match = re.search(r'Domain\s+:\s+(.+)', block)
        
        if username_match and domain_match:
            username = username_match.group(1).strip()
            domain = domain_match.group(1).strip()
            
            # Skip empty or machine accounts
            if not username or username.endswith('$') or username in ['(null)', 'UMFD-0', 'UMFD-1', 'DWM-1']:
                continue
            
            # Extract NTLM hash
            ntlm_match = re.search(r'\* NTLM\s+:\s+([a-fA-F0-9]{32})', block)
            ntlm_hash = ntlm_match.group(1) if ntlm_match else None
            
            if ntlm_hash:
                # Create a unique key for this user
                user_key = f"{domain}\\{username}"
                
                # Add to results if not already present
                if ntlm_hash not in [h for u, h in results[user_key]]:
                    results[user_key].append((username, ntlm_hash))
    
    # Parse the SAM dump section if present - improved version
    sam_sections = re.findall(r'RID\s+:\s+[0-9a-f]+\s+\(\d+\)\s+User\s+:\s+(.+?)[\r\n][\s\S]*?(?=RID\s+:|$)', content)
    domain_match = re.search(r'Domain\s+:\s+(\S+)', content)
    domain = domain_match.group(1) if domain_match else "UNKNOWN"
    
    # Process each SAM section separately
    for section in sam_sections:
        user_match = re.search(r'^(.+?)$', section.strip(), re.MULTILINE)
        if user_match:
            sam_user = user_match.group(1).strip()
            # Skip empty or default accounts
            if not sam_user or sam_user in ['Guest', 'DefaultAccount']:
                continue
                
            # Find NTLM hash for this user in the content
            ntlm_pattern = r'User\s+:\s+' + re.escape(sam_user) + r'[\s\S]*?Hash NTLM: ([a-fA-F0-9]{32})'
            ntlm_match = re.search(ntlm_pattern, content)
            
            if ntlm_match:
                user_key = f"{domain}\\{sam_user}"
                ntlm_hash = ntlm_match.group(1)
                if user_key not in results or ntlm_hash not in [h for _, h in results[user_key]]:
                    results[user_key].append((sam_user, ntlm_hash))
    
    return results


def format_table(data):
    """Create a well-formatted table with dynamic column widths."""
    if not data:
        return "No credentials found."
    
    # Determine column widths based on content
    username_width = max(len("Username"), max(len(username) for user_key, user_data in data.items() 
                                         for username, _ in user_data))
    domain_width = max(len("Domain"), max(len(user_key.split('\\', 1)[0]) for user_key in data.keys()))
    hash_width = 32  # NTLM hashes are always 32 characters
    
    # Add a bit of padding
    username_width += 2
    domain_width += 2
    
    # Create header
    header = f"{'Username':<{username_width}}{'Domain':<{domain_width}}{'NTLM Hash'}"
    separator = "=" * (username_width + domain_width + hash_width)
    
    # Create rows
    rows = []
    for user_key, user_data in sorted(data.items()):
        domain, _ = user_key.split('\\', 1)
        for username, ntlm_hash in user_data:
            rows.append(f"{username:<{username_width}}{domain:<{domain_width}}{ntlm_hash}")
    
    # Combine everything
    return '\n'.join([header, separator] + rows)


def main():
    parser = argparse.ArgumentParser(description="Parse Mimikatz output for credentials")
    parser.add_argument("file", help="Mimikatz output file")
    parser.add_argument("-o", "--output", help="Output file (default: stdout)")
    parser.add_argument("-f", "--format", choices=["text", "hashcat"], default="text", 
                       help="Output format (default: text)")
    parser.add_argument("-u", "--unique", action="store_true",
                       help="Output only unique hashes (for hashcat format)")
    parser.add_argument("-c", "--color", action="store_true",
                       help="Colorize the output (text format only)")
    
    args = parser.parse_args()
    
    try:
        with open(args.file, 'r', encoding='utf-8') as f:
            content = f.read()
    except Exception as e:
        print(f"Error reading file: {e}", file=sys.stderr)
        return 1
    
    results = parse_mimikatz_output(content)
    
    # Prepare output
    if args.format == "text":
        if args.color and sys.stdout.isatty():
            # Define ANSI color codes
            HEADER = '\033[95m'
            OKBLUE = '\033[94m'
            OKGREEN = '\033[92m'
            ENDC = '\033[0m'
            
            # Get table as string
            table_str = format_table(results)
            
            # Colorize the header and separator
            lines = table_str.split('\n')
            if len(lines) >= 2:
                lines[0] = HEADER + lines[0] + ENDC
                lines[1] = OKBLUE + lines[1] + ENDC
                
            # Colorize alternate rows for better readability
            for i in range(2, len(lines)):
                if i % 2 == 0:
                    lines[i] = OKGREEN + lines[i] + ENDC
                    
            output_text = '\n'.join(lines)
        else:
            output_text = format_table(results)
    else:  # hashcat format
        # Create a dictionary to store unique hashes if required
        unique_hashes = {}
        hash_lines = []
        
        for user_key, user_data in results.items():
            for _, ntlm_hash in user_data:
                if args.unique:
                    # Only store the first user we find with this hash
                    if ntlm_hash not in unique_hashes:
                        unique_hashes[ntlm_hash] = user_key
                else:
                    hash_lines.append(f"{ntlm_hash}:{user_key}")
        
        # If unique hashes option is enabled, add them to output
        if args.unique:
            for ntlm_hash, user_key in unique_hashes.items():
                hash_lines.append(f"{ntlm_hash}:{user_key}")
        
        output_text = '\n'.join(hash_lines)
    
    if args.output:
        try:
            with open(args.output, 'w') as f:
                # Strip ANSI codes if writing to file
                if args.color and args.format == "text":
                    output_text = re.sub(r'\033\[\d+m', '', output_text)
                f.write(output_text)
            print(f"Results written to {args.output}")
        except Exception as e:
            print(f"Error writing to output file: {e}", file=sys.stderr)
            return 1
    else:
        print(output_text)
    
    return 0


if __name__ == "__main__":
    sys.exit(main())
