#!/usr/bin/env python3
"""
Magic Triage Tool
Analyzes suspicious files using magic bytes, generates hashes, and sorts by true file type.
"""

import os
import hashlib
import magic
import shutil
import csv
import sys
from pathlib import Path


def walk_directory(directory_path):
    """
    Walk through directory and return list of all file paths.
    
    Args:
        directory_path: Path to the directory to scan
        
    Returns:
        List of full file paths
    """
    file_list = []
    
    for root, dirs, files in os.walk(directory_path):
        for filename in files:
            # Join directory path with filename to get full path
            full_path = os.path.join(root, filename)
            file_list.append(full_path)
    
    return file_list


def generate_hashes(filepath):
    """
    Generate MD5 and SHA256 hashes for a file.
    
    Args:
        filepath: Path to the file
        
    Returns:
        Tuple of (md5_hash, sha256_hash)
    """
    # Create hash objects
    md5_hash = hashlib.md5()
    sha256_hash = hashlib.sha256()
    
    # Read file in chunks to handle large files
    try:
        with open(filepath, 'rb') as f:  # 'rb' = read binary
            # Read in 8KB chunks
            while chunk := f.read(8192):
                md5_hash.update(chunk)
                sha256_hash.update(chunk)
        
        # Return hexadecimal representation of hashes
        return md5_hash.hexdigest(), sha256_hash.hexdigest()
    
    except Exception as e:
        print(f"Error hashing {filepath}: {e}")
        return "ERROR", "ERROR"


def identify_filetype(filepath):
    """
    Identify true file type using magic bytes.
    
    Args:
        filepath: Path to the file
        
    Returns:
        String describing the file type
    """
    try:
        # Create a Magic object
        mime = magic.Magic()
        # Get file type description
        file_type = mime.from_file(filepath)
        return file_type
    
    except Exception as e:
        print(f"Error identifying {filepath}: {e}")
        return "UNKNOWN"


def categorize_file(file_type_description):
    """
    Categorize file based on its true type.
    
    Args:
        file_type_description: String from magic library
        
    Returns:
        Category folder name
    """
    # Convert to lowercase for easier matching
    file_type_lower = file_type_description.lower()
    
    # Check for executables
    if 'executable' in file_type_lower or 'pe32' in file_type_lower:
        return 'executables'
    
    # Check for scripts
    elif any(script in file_type_lower for script in ['python', 'bash', 'shell', 'powershell', 'perl', 'javascript']):
        return 'scripts'
    
    # Check for text documents
    elif 'text' in file_type_lower or 'ascii' in file_type_lower:
        return 'text_documents'
    
    # Check for archives
    elif any(archive in file_type_lower for archive in ['zip', 'rar', 'gzip', 'tar', '7-zip', 'compressed']):
        return 'archives'
    
    # Check for images
    elif any(img in file_type_lower for img in ['image', 'jpeg', 'png', 'gif', 'bitmap']):
        return 'images'
    
    # Check for PDFs
    elif 'pdf' in file_type_lower:
        return 'documents'
    
    # Default category for unknown types
    else:
        return 'other'


def check_extension_mismatch(filename, true_type):
    """
    Check if file extension matches true file type.
    
    Args:
        filename: Original filename with extension
        true_type: True file type from magic bytes
        
    Returns:
        Note string if mismatch detected, empty string otherwise
    """
    # Get the extension
    extension = os.path.splitext(filename)[1].lower()
    true_type_lower = true_type.lower()
    
    # Define expected type keywords for common extensions
    extension_map = {
        '.exe': ['executable', 'pe32'],
        '.dll': ['executable', 'pe32', 'library'],
        '.pdf': ['pdf'],
        '.txt': ['text', 'ascii'],
        '.jpg': ['jpeg', 'image'],
        '.png': ['png', 'image'],
        '.gif': ['gif', 'image'],
        '.zip': ['zip', 'compressed'],
        '.py': ['python'],
        '.sh': ['shell', 'bash'],
        '.ps1': ['powershell']
    }
    
    # If we have a mapping for this extension
    if extension in extension_map:
        expected_keywords = extension_map[extension]
        # Check if ANY expected keyword is in the true type
        if not any(keyword in true_type_lower for keyword in expected_keywords):
            return "Mismatched extension"
    
    return ""


def sort_files(source_dir, output_dir):
    """
    Sort files from source directory into categorized folders.
    
    Args:
        source_dir: Directory containing files to analyze
        output_dir: Directory where sorted files will be placed
        
    Returns:
        List of dictionaries containing analysis results
    """
    results = []
    
    # Get all files from source directory
    print("Scanning directory...")
    files = walk_directory(source_dir)
    print(f"Found {len(files)} files to process\n")
    
    # Process each file
    for filepath in files:
        print(f"Processing: {os.path.basename(filepath)}")
        
        # Get original filename
        filename = os.path.basename(filepath)
        
        # Generate hashes
        md5_hash, sha256_hash = generate_hashes(filepath)
        
        # Identify true file type
        true_type = identify_filetype(filepath)
        
        # Categorize the file
        category = categorize_file(true_type)
        
        # Check for extension mismatch
        notes = check_extension_mismatch(filename, true_type)
        
        # Create category folder if it doesn't exist
        category_path = os.path.join(output_dir, category)
        if not os.path.exists(category_path):
            os.makedirs(category_path)
        
        # Copy file to appropriate category folder
        destination = os.path.join(category_path, filename)
        try:
            shutil.copy2(filepath, destination)
        except Exception as e:
            print(f"  Error copying file: {e}")
            notes += f" Copy error: {e}"
        
        # Store results
        result = {
            'filename': filename,
            'true_type': true_type,
            'md5': md5_hash,
            'sha256': sha256_hash,
            'notes': notes,
            'category': category
        }
        results.append(result)
        
        print(f"  Type: {true_type}")
        print(f"  Category: {category}")
        if notes:
            print(f"  Notes: {notes}")
        print()
    
    return results


def generate_report(results, output_file):
    """
    Generate CSV report of analysis results.
    
    Args:
        results: List of dictionaries containing file analysis data
        output_file: Path where CSV report will be saved
    """
    try:
        with open(output_file, 'w', newline='') as csvfile:
            # Define CSV headers matching assignment requirements
            fieldnames = ['Original Filename', 'True File Type', 'Hash (MD5 or SHA256)', 'Notes']
            
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            
            # Write header row
            writer.writeheader()
            
            # Write data rows
            for result in results:
                writer.writerow({
                    'Original Filename': result['filename'],
                    'True File Type': result['true_type'],
                    'Hash (MD5 or SHA256)': result['sha256'],  # Using SHA256 as primary
                    'Notes': result['notes']
                })
        
        print(f"\nReport generated successfully: {output_file}")
        
    except Exception as e:
        print(f"Error generating report: {e}")


def main():
    """Main function to orchestrate the file triage process."""
    
    # Check if correct number of arguments provided
    if len(sys.argv) != 3:
        print("Usage: python3 file_triage.py <source_directory> <output_directory>")
        print("Example: python3 file_triage.py ~/Downloads/Lab2_Corpus ~/Downloads/Lab2_Corpus_sorted")
        sys.exit(1)
    
    # Get source and destination directories from command line
    source_dir = sys.argv[1]
    output_dir = sys.argv[2]
    
    # Expand user home directory if needed
    source_dir = os.path.expanduser(source_dir)
    output_dir = os.path.expanduser(output_dir)
    
    # Validate source directory exists
    if not os.path.exists(source_dir):
        print(f"Error: Source directory '{source_dir}' does not exist")
        sys.exit(1)
    
    # Create output directory if it doesn't exist
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)
        print(f"Created output directory: {output_dir}")
    
    print(f"\n{'='*60}")
    print(f"FILE TRIAGE TOOL")
    print(f"{'='*60}")
    print(f"Source: {source_dir}")
    print(f"Output: {output_dir}")
    print(f"{'='*60}\n")
    
    # Sort files and collect results
    results = sort_files(source_dir, output_dir)
    
    # Generate the report in the parent directory of output
    report_path = os.path.join(os.path.dirname(output_dir), "triage_report.csv")
    generate_report(results, report_path)
    
    # Print summary
    print(f"\n{'='*60}")
    print(f"TRIAGE COMPLETE")
    print(f"{'='*60}")
    print(f"Total files processed: {len(results)}")
    print(f"Sorted files location: {output_dir}")
    print(f"Report saved to: {report_path}")
    print(f"{'='*60}\n")


if __name__ == "__main__":

    main()
