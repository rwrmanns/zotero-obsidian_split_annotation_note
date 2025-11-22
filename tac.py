import os
import re
import io
import configparser
import frontmatter
import random
import string

def load_config(ini_path):
    config = configparser.ConfigParser()
    config.read(ini_path)

    p_root = config['DEFAULT']['p_root']
    ext = config['DEFAULT']['ext']
    rgx_QA_exclude = re.compile(config['DEFAULT']['rgx_QA_exclude'], re.MULTILINE | re.DOTALL)
    rgx_QA_pattern = re.compile(config['DEFAULT']['rgx_QA_pattern'], re.MULTILINE | re.DOTALL)
    rgx_QA_hash = re.compile(config['DEFAULT']['rgx_QA_hash'])
    rgx_QA_DECK = re.compile(config['DEFAULT']['rgx_QA_DECK'], re.MULTILINE | re.DOTALL)

    return p_root, ext, rgx_QA_exclude, rgx_QA_pattern, rgx_QA_hash, rgx_QA_DECK

def generate_random_hash(length=8):
    return ''.join(random.choices(string.ascii_uppercase + string.digits, k=length))

def find_files_with_extension(root, extension):
    matches = []
    for current_dir, _, filenames in os.walk(root):
        for fname in filenames:
            if fname.endswith(extension):
                matches.append(os.path.join(current_dir, fname))
    return matches

def process_files(file_paths, rgx_QA_exclude, rgx_QA_pattern, rgx_QA_hash, rgx_QA_DECK):
    result = []
    for file_path in file_paths:
        try:
            post = frontmatter.load(file_path)
            content_io = io.StringIO(post.content)
            content = content_io.read()
        except Exception as e:
            print(f"Warning: Could not load frontmatter from {file_path}: {e}")
            continue

        # Skip files matching exclude regex
        if rgx_QA_exclude.search(content):
            continue

        # Only include files matching pattern regex
        if not rgx_QA_pattern.search(content):
            continue

        # Search for deck entries
        deck_matches = rgx_QA_DECK.findall(content)
        # Example: fixed prefix extraction from pattern (adjust as needed)

        if deck_matches:
            fixed_prefix = "#QA_DECK"
            l_s_deck = [m[len(fixed_prefix):] if m.startswith(fixed_prefix) else m for m in deck_matches]
        else:
            l_s_deck = ''

        # Check for existing zotero_hash or generate new one
        zotero_hash = None
        metadata = post.metadata
        if 'san' in metadata and isinstance(metadata['san'], dict):
            candidate = metadata['san'].get('zotero_hash')
            if candidate and rgx_QA_hash.fullmatch(candidate):
                zotero_hash = candidate

        if not zotero_hash:
            zotero_hash = generate_random_hash()
            if 'san' not in metadata or not isinstance(metadata['san'], dict):
                metadata['san'] = {}
            metadata['san']['zotero_hash'] = zotero_hash
            post.metadata = metadata
            with open(file_path, 'w', encoding='utf-8') as f:
                f.write(frontmatter.dumps(post))

        # Extract all target matches
        raw_matches = rgx_QA_pattern.findall(content)
        if raw_matches and isinstance(raw_matches[0], tuple):
            target_matches = [''.join(m) for m in raw_matches]
        else:
            target_matches = raw_matches

        modified_content = content
        multiple_matches = len(target_matches) > 1

        for idx, match in enumerate(target_matches, start=1):
            if not rgx_QA_hash.search(match):
                escaped_match = re.escape(match)
                if multiple_matches:
                    insert_str = f'({zotero_hash}_{idx})\n'
                else:
                    insert_str = f'({zotero_hash})\n'
                modified_content = re.sub(
                    rf'({escaped_match})',
                    rf'\1{insert_str}',
                    modified_content,
                    count=1
                )
                # Also append insert_str to target_matches entry
                target_matches[idx-1] = match + insert_str

        # Write modified content to new file prefixed with _NEW_
        new_filename = '_NEW_' + os.path.basename(file_path)
        with open(new_filename, 'w', encoding='utf-8') as f_new:
            fm_text = frontmatter.dumps(post)
            split_index = fm_text.find('---', 3)
            if split_index == -1:
                f_new.write(fm_text)
            else:
                frontmatter_header = fm_text[:split_index+3]
                f_new.write(frontmatter_header + '\n' + modified_content)

        qa_match = rgx_QA_pattern.search(content)

        entry = {
            'path': file_path,
            'target': target_matches if target_matches else None,
            'hash': zotero_hash,
            'qa': qa_match.group(0) if qa_match else None,
            'l_s_deck': l_s_deck,
        }
        result.append(entry)
    return result

def main():
    ini_path = 'tac.ini'
    p_root, ext, rgx_QA_exclude, rgx_QA_pattern, rgx_QA_hash, rgx_QA_DECK = load_config(ini_path)

    all_files = find_files_with_extension(p_root, ext)
    dts = process_files(all_files, rgx_QA_exclude, rgx_QA_pattern, rgx_QA_hash, rgx_QA_DECK)

    for entry in dts:
        print(entry)

if __name__ == "__main__":
    main()
