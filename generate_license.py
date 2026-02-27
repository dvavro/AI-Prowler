#!/usr/bin/env python3
"""
RAG License Key Generator
Generate license keys for RAG system monetization

Usage:
    python generate_license.py                    # Generate single key
    python generate_license.py --count 100        # Generate 100 keys
    python generate_license.py --validate KEY     # Validate a key
"""

import hashlib
import random
import string
import argparse

def generate_license_key():
    """Generate a valid license key"""
    # Generate 4 random parts (5 characters each)
    parts = []
    for _ in range(4):
        part = ''.join(random.choices(string.ascii_uppercase + string.digits, k=5))
        parts.append(part)
    
    # Generate checksum (5th part)
    key_data = '-'.join(parts)
    checksum = hashlib.md5(key_data.encode()).hexdigest()[:5].upper()
    parts.append(checksum)
    
    # Combine
    license_key = '-'.join(parts)
    return license_key

def validate_license_key(license_key):
    """Validate license key format and checksum"""
    if not license_key or len(license_key) != 29:
        return False
    
    parts = license_key.split('-')
    if len(parts) != 5:
        return False
    
    # Verify each part is 5 characters
    for part in parts:
        if len(part) != 5:
            return False
    
    # Verify checksum (last part)
    key_data = '-'.join(parts[:-1])
    checksum = hashlib.md5(key_data.encode()).hexdigest()[:5].upper()
    
    return parts[-1].upper() == checksum

def main():
    parser = argparse.ArgumentParser(
        description='Generate RAG license keys'
    )
    parser.add_argument('--count', type=int, default=1,
                       help='Number of keys to generate (default: 1)')
    parser.add_argument('--validate', type=str,
                       help='Validate a license key')
    parser.add_argument('--output', type=str,
                       help='Output file for generated keys')
    
    args = parser.parse_args()
    
    if args.validate:
        # Validate key
        print()
        print("=" * 70)
        print("LICENSE KEY VALIDATION")
        print("=" * 70)
        print()
        print(f"Key: {args.validate}")
        print()
        
        if validate_license_key(args.validate):
            print("✅ Valid license key")
        else:
            print("❌ Invalid license key")
        print()
        return
    
    # Generate keys
    print()
    print("=" * 70)
    print(f"GENERATING {args.count} LICENSE KEY(S)")
    print("=" * 70)
    print()
    
    keys = []
    for i in range(args.count):
        key = generate_license_key()
        keys.append(key)
        print(f"{i+1:4}. {key}")
    
    print()
    
    # Save to file if requested
    if args.output:
        try:
            with open(args.output, 'w') as f:
                for key in keys:
                    f.write(f"{key}\n")
            print(f"✅ Keys saved to: {args.output}")
            print()
        except Exception as e:
            print(f"❌ Error saving keys: {e}")
            print()

if __name__ == "__main__":
    main()
