'''
tac.py == transfer_to_anki_cards.py

This script serves to split from a 'source_note.md' separate anki cards .

2025-11-22

github repository:
    https://github.com/rwrmanns/zotero-obsidian_split_atomic_notes

'''


import os
import re
import configparser

def load_config(ini_path):
    config = configparser.ConfigParser()
    config.read(ini_path)
    p_root = config['DEFAULT']['p_root']
    ext = config['DEFAULT']['ext']
    rgx_QA = re.compile(config['DEFAULT']['rgx_QA'], re.MULTILINE | re.DOTALL)
    rgx_QA_target = re.compile(config['DEFAULT']['rgx_QA_target'])
    rgx_QA_hash = re.compile(config['DEFAULT']['rgx_QA_hash'])
    return p_root, ext, rgx_QA, rgx_QA_target, rgx_QA_hash

def find_files_with_extension(root, extension):
    matches = []
    for current_dir, _, filenames in os.walk(root):
        for fname in filenames:
            if fname.endswith(extension):
                matches.append(os.path.join(current_dir, fname))
    return matches

def process_files(file_paths, rgx_QA, rgx_QA_target, rgx_QA_hash):
    result = []
    for file_path in file_paths:
        with open(file_path, 'r', encoding='utf-8') as f:
            content = f.read()
        # Skip file if matches rgx_QA anywhere in content (exclude)
        if not rgx_QA.search(content):
            continue
        # Extract one match per regex or None if not found
        target_match = rgx_QA_target.search(content)
        hash_match = rgx_QA_hash.search(content)
        qa_match = rgx_QA.search(content)
        entry = {
            'path': file_path,
            'target': target_match.group(0) if target_match else None,
            'hash': hash_match.group(0) if hash_match else None,
            'qa': qa_match.group(0) if qa_match else None
        }
        result.append(entry)
    return result

# Example usage
if __name__ == "__main__":
    ini_path = './tac.ini'  # path to your ini file
    p_root, ext, rgx_QA, rgx_QA_target, rgx_QA_hash = load_config(ini_path)

    # Find all files with extension in path
    all_files = find_files_with_extension(p_root, ext)

    # Process files and collect required info
    dts = process_files(all_files, rgx_QA, rgx_QA_target, rgx_QA_hash)

    # dts now contains dictionaries with 'path', 'target', 'hash', 'qa' keys
    for entry in dts:
        print(entry)
