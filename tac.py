import os
import re
import io
import configparser
import difflib
import frontmatter
import hashlib
import pprint
import random

flashcard_sys = 'anki'
flashcard_sys = 'flashcards'

fn_prefix = '_NEW_'

rgx_html_comment = re.compile(r'<!--.*?-->', re.DOTALL)

rgx_QA_exclude = ''
rgx_QA_pattern = ''
rgx_QA_hash    = ''
rgx_QA_DECK    = ''
rgx_d8_hash    = ''

def load_config(ini_path):
    global rgx_QA_exclude
    global rgx_QA_pattern
    global rgx_QA_hash
    global rgx_QA_DECK
    global rgx_d8_hash

    config = configparser.ConfigParser()
    config.read(ini_path)

    p_root = config['DEFAULT']['p_root']
    ext    = config['DEFAULT']['ext']
    p_QA   = config['DEFAULT']['p_QA']
    QA_tag = config['DEFAULT']['QA_tag']

    rgx_QA_exclude = re.compile(config['DEFAULT']['rgx_QA_exclude'], re.MULTILINE | re.DOTALL)
    rgx_QA_pattern = re.compile(config['DEFAULT']['rgx_QA_pattern'], re.MULTILINE | re.DOTALL)
    rgx_QA_hash = re.compile(config['DEFAULT']['rgx_QA_hash'])
    rgx_QA_DECK = re.compile(config['DEFAULT']['rgx_QA_DECK'], re.MULTILINE | re.DOTALL)
    rgx_d8_hash = re.compile(config['DEFAULT']['rgx_d8_hash'], re.MULTILINE | re.DOTALL)

    return p_root, ext, p_QA, QA_tag


def generate_random_hash(length=8):
    return ''.join(random.choices('ABCDEFGHIJKLMNOPQRSTUVWXYZ123456789', k=length))


def calc_d8_hash(s_qa_block) -> str:
    # calc sha256-hash of >s_qa_block< & return last 8 chars of hash.
    # - escape special chars
    s_qa_block = re.escape(s_qa_block)
    # - eliminate consecutive whitespaces >s_qa_block<
    s_qa_block = re.sub(r'\s+', ' ', s_qa_block)
    # - encode UTF-8
    s_qa_block = s_qa_block.encode('utf-8')
    # - encode UTF-8
    hash_int = int(hashlib.sha256(s_qa_block).hexdigest(), 16)
    # - Convert the hexadecimal to an integer hash string
    d8_hash_calc = str(hash_int)[-8:]

    # or kick it like Perplexity: !
    #   Use the modulo operator (%) to keep only the last 8 digits
    #   10**8 is 100,000,000
    #   d8_hash = hash_int % (10 ** 8)
    return d8_hash_calc


def get_d8_hash_vs_0(s_qa_block):
    # Get 8 digits of hash of 's_qa_block'
    # 's_qa_block' == textblock one containing Q: and A: text.
    # 'search in 's_qa_block' string like: '(Y2BBMT5N_000_51275410)'

    QA_hash_long = rgx_QA_hash.search(s_qa_block)
    if QA_hash_long:
        # group_all    = QA_hash_long.group(0)
        # group_1      = QA_hash_long.group(1)
        # group_2      = QA_hash_long.group(2)
        # group_3      = QA_hash_long.group(3)

        d8_hash_org  = QA_hash_long.group(3)

        return calc_d8_hash(s_qa_block)

    if re.search(rgx_d8_hash, s_qa_block):
        d8_hash = rgx_d8_hash.search(s_qa_block)
        return d8_hash.group(0)
    else:
        # # remove existing QA_hash
        # replacement = r'\1\2'
        # result_string = full_pattern.sub(replacement, input_string)

        # Encode the s_qa_block to bytes, a requirement for hashlib functions
        encoded_text = s_qa_block.encode('utf-8')

        # Use SHA-256 for a robust initial hash
        full_hash = hashlib.sha256(encoded_text).hexdigest()

        # Convert the hexadecimal hash string to an integer
        hash_int = int(full_hash, 16)

        # Perplexity: !
        #   Use the modulo operator (%) to keep only the last 8 digits
        #   10**8 is 100,000,000
        #   d8_hash = hash_int % (10 ** 8)

        d8_hash = str(hash_int)[-8:]

        return d8_hash



def find_files_with_extension(root, extension):
    matches = []
    for current_dir, _, filenames in os.walk(root):
        for fname in filenames:
            if fname.endswith(extension):
                matches.append(os.path.normpath(os.path.join(current_dir, fname)))
    return matches


def get_l_s_QA_deck(content, rgx_QA_DECK, fixed_QA_prefix):
    deck_matches = rgx_QA_DECK.findall(content)
    lo_QA_deck = [m[len(fixed_QA_prefix):] if m.startswith(fixed_QA_prefix) else m for m in deck_matches]
    if len(lo_QA_deck) == 0:
        lo_QA_deck = ['Default']
    return lo_QA_deck


def files_are_identical(new_file_path, content2):
    if not os.path.isfile(new_file_path):
        return False
    with open(new_file_path, 'r', encoding='utf-8') as f1:
        content1 = f1.read()
    return content1 == content2

def get_QA_hash_from_frontmatter(file_path, metadata: dict[str, object], post, rgx_QA_hash) -> str:
    QA_hash = None
    if 'san' in metadata and isinstance(metadata['san'], dict):
        candidate = metadata['san'].get('zotero_hash')
        if candidate and rgx_QA_hash.search(candidate):
            QA_hash = candidate

    if not QA_hash:
        # fake: ['san']['zotero_hash']
        QA_hash = generate_random_hash()
        if 'san' not in metadata or not isinstance(metadata['san'], dict):
            metadata['san'] = {}
        metadata['san']['zotero_hash'] = QA_hash
        post.metadata = metadata
        with open(file_path, 'w', encoding='utf-8') as f:
            f.write(frontmatter.dumps(post))
    return QA_hash

def get_lo_all_QA_hashes(content: str, rgx_QA_hash) -> list:
    if flashcard_sys == 'anki':
        lo_all_QA_hashes = rgx_QA_hash.findall(content)
    elif flashcard_sys == 'flashcards':
        # In
        lo_html_comment  = rgx_html_comment.findall(content)
        lo_all_QA_hashes = []
        for html_comment in lo_html_comment:
            if rgx_QA_hash.findall(html_comment):
                lo_all_QA_hashes += rgx_QA_hash.findall(html_comment)
    else:
        exit('get_lo_all_QA_hashes(): flashcard_sys?')
    return lo_all_QA_hashes


def get_tu_Q_A_part(qa_string):
    match = rgx_QA_pattern.search(qa_string)

    if match:
        # Group 1 is the first part (Q:...)
        Q_part = match.group(1).strip()
        # Group 2 is the second part (A:...)
        A_part = match.group(2).strip()

        print(f"First part (Question):\n{question_part}\n")
        print(f"Second part (Answer):\n{answer_part}\n")
        return (Q_part, A_part)
    else:
        print("No Q&A pattern match found.")
        return ('', '')


def get_lo_s_QA(content: str, rgx_QA_pattern) -> list[str]:
    if flashcard_sys == 'anki':
        l_qa_match = rgx_QA_pattern.findall(content)
        if l_qa_match and isinstance(l_qa_match[0], tuple):
            lo_s_qa = [''.join(m) for m in l_qa_match]
        else:
            lo_s_qa = l_qa_match
        return lo_s_qa
    elif flashcard_sys == 'flashcards':
        l_qa_match = rgx_QA_pattern.findall(content)
        # get_tu_Q_A_part(qa_string)
        lo_s_qa = []
        if l_qa_match and isinstance(l_qa_match[0], tuple):
            # lo_s_qa = [''.join(m) for m in l_qa_match]
            for qa_match in l_qa_match:
                lo_s_qa.append(qa_match)
        else:
            lo_s_qa = l_qa_match
        return lo_s_qa
    else:
        exit('get_lo_all_QA_hashes(): flashcard_sys?')

def get_normalized_s_qa_block(s_qa: str) -> str:
    s_qa_block = ''.join(s_qa)
    if not s_qa_block.endswith('\n'):
        s_qa_block += '\n'
    s_qa_block = re.escape(s_qa_block)
    return s_qa_block

def get_lo_qa_entry(file_paths):
    # return list of all QA-entries in note: qa_entry.QA, possibly qa_entry.QA_hash, qa_entry.QA_deck
    lo_qa_entry = []
    # Get frontmatter of note
    for file_path in file_paths:
        fn = os.path.basename(file_path)
        try:
            post = frontmatter.load(file_path)
            content_io = io.StringIO(post.content)
            content = content_io.read()
        except Exception as e:
            print(f"Warning: Could not load frontmatter from {file_path}: {e}")
            continue

        # for example: #ToDo_QA
        if rgx_QA_exclude.search(content):
            continue

        # Pattern of QA
        if not rgx_QA_pattern.search(content):
            continue

        # Anki: Deck
        fixed_QA_prefix = "#QA_DECK_"
        lo_QA_deck = get_l_s_QA_deck(content, rgx_QA_DECK, fixed_QA_prefix)

        # Get from frontmatter: QA_hash
        metadata = post.metadata
        QA_hash =   get_QA_hash_from_frontmatter(file_path, metadata, post, rgx_QA_hash)

        # Get QA-text_blocks in note - maybe multiple QA's, hence list.
        lo_s_qa = get_lo_s_QA(content, rgx_QA_pattern)

        # note may possibly be modified (by inserting QA_hash to QA)
        modified_content = content
        multiple_matches = len(lo_s_qa) > 1

        # QA-text_blocks possibly have already QA_hash -> make list of them
        lo_all_QA_hashes = get_lo_all_QA_hashes(content, rgx_QA_hash)

        # ???
        # lo_qa_hash = [''] * len(lo_s_qa)

        # For every QA-text_block
        for idx, s_qa in enumerate(lo_s_qa):
            s_qa_block = get_normalized_s_qa_block(s_qa)
            s_qa_d8_hash_calc = calc_d8_hash(s_qa_block)
            s_qa_d8_hash = rgx_d8_hash.search(s_qa_block)
            if not s_qa_d8_hash or (s_qa_d8_hash != s_qa_d8_hash_calc):
                s_qa_d8_hash = s_qa_d8_hash_calc

                if multiple_matches:
                    candidate_idx = idx
                    QA_hash_idx = f'{QA_hash}_{candidate_idx:03d}'
                    while QA_hash_idx in lo_all_QA_hashes:
                        candidate_idx += 1
                        QA_hash_idx = f'{QA_hash}_{candidate_idx:03d}_{s_qa_d8_hash}'

                    insert_str = f'({QA_hash_idx}_{s_qa_d8_hash})\n'
                else:
                    insert_str = f'({QA_hash}_{s_qa_d8_hash})\n'

                modified_content = re.sub(
                    rf'({s_qa_block})',
                    rf'\1{insert_str}',
                    modified_content,
                    count=1
                )
                # modify A: attaching index (oder hash von s_qa_block?)
                # lo_s_qa[idx][0] = lo_s_qa[idx][0] + '\n' + insert_str
                s_qa_new = (lo_s_qa[idx][0], lo_s_qa[idx][1] + '\n' + insert_str)
                lo_s_qa[idx] = s_qa_new
                # lo_qa_hash[idx-1] = QA_hash

        orig_dir = os.path.dirname(file_path)
        base_name = os.path.basename(file_path)

        if base_name.startswith(fn_prefix):
            new_filename = base_name
        else:
            new_filename = fn_prefix + base_name

        new_file_path = os.path.normpath(os.path.join(orig_dir, new_filename))

        fm_text = frontmatter.dumps(post)
        split_index = fm_text.find('---', 3)
        if split_index == -1:
            frontmatter_header = fm_text
        else:
            frontmatter_header = fm_text[:split_index + 3]

        full_new_content = frontmatter_header + '\n' + modified_content

        if os.path.exists(new_file_path):
            if not os.path.isfile(new_file_path):
                return False
            with open(new_file_path, 'r', encoding='utf-8') as new_f:
                new_content = new_f.read()

            differ  = difflib.Differ()
            delta_x = list(differ.compare(new_content.splitlines(), full_new_content.splitlines()))
            delta   = "\n".join(delta_x)
            if new_content == full_new_content:
                print(f"File identical, skipping overwrite: {new_file_path}")
            else:
                with open(new_file_path, 'w', encoding='utf-8') as f_new:
                    f_new.write(full_new_content)
                print(f"File updated: {new_file_path}")
            if new_file_path in file_paths:
                file_paths.remove(new_file_path)
        else:
            with open(new_file_path, 'w', encoding='utf-8') as f_new:
                f_new.write(full_new_content)
            print(f"File written: {new_file_path}")

        for s_QA in lo_s_qa:
            for QA_deck in lo_QA_deck:
                s_qa = re.search(rgx_QA_hash, s_QA[1])
                QA_hash = s_qa.group(0) if s_qa else ''
                qa_entry = {
                    'QA_deck': QA_deck,
                    'QA_hash': QA_hash,
                    's_QA': s_QA,
                    # 'path': file_path,
                    'path': fn,
                }
                lo_qa_entry.append(qa_entry)
    return lo_qa_entry

def parse_flashcards(text):
    lo_qa_card = []
    # Split text on marker lines, keeping them as separate entries
    # r"^#marker\s*(.*)$((?:\n|\r\n?)*)",
    #     re.MULTILINE
    blocks = re.split(r'(^#flashcards.*$)', text, flags=re.MULTILINE)
    blocks = re.split(r'(^#flashcards\s*(.*)$((?:\n|\r\n?)*))', text, flags=re.MULTILINE)

    # blocks alternate as ['', marker line, content, marker line, content, ...]
    if blocks[0].strip() == '':
        blocks = blocks[1:]

    # Process pairs of (marker line, content block)
    for i in range(0, len(blocks), 2):
        deck_line = blocks[i].strip()
        if (i+1) >= len(blocks):
            continue
        content_block = blocks[i+1].split('\n\n')[0].strip()  # Trim at first empty line

        # Split at one to three question marks
        split_q_a = re.split(r'\?{1,3}', content_block, maxsplit=1)
        if len(split_q_a) != 2:
            continue  # Skip if can't split properly

        q_part, a_part = map(str.strip, split_q_a)

        # Prepend 'Q: ' or 'A: ' if missing (case insensitive)
        if not re.match(r'^Q:\s*', q_part, re.IGNORECASE):
            q_part = 'Q: ' + q_part
        if not re.match(r'^A:\s*', a_part, re.IGNORECASE):
            a_part = 'A: ' + a_part

        card = {'Decks': deck_line, 'Q': q_part, 'A': a_part}
        lo_qa_card.append(card)

    return lo_qa_card

# def parse_spaced_repetition_file(path):
#     with open(path, 'r', encoding='utf-8') as f:
#         text = f.read()
#
#     cards = []
#
#     # 1) Single-line: Question::Answer
#     for m in re.finditer(r'^(.*?[^:])::(.*)$', text, flags=re.MULTILINE):
#         q = m.group(1).strip()
#         a = m.group(2).strip()
#         cards.append({'type': 'single', 'Q': q, 'A': a})
#
#     # 2) Single-line reversed: Question:::Answer
#     for m in re.finditer(r'^(.*?[^:]):::(.*)$', text, flags=re.MULTILINE):
#         q = m.group(1).strip()
#         a = m.group(2).strip()
#         cards.append({'type': 'single_reversed', 'Q': q, 'A': a})
#
#     # 3) Multi-line style (Separated by ? on its own line)
#     # Question block, then line with ?, then answer block
#     multi_pattern = re.compile(
#         r'(^.+?(?:\n(?!\?).+?)*)\n\?\n(.+?(?:\n(?!\?).+?)*)',
#         flags=re.MULTILINE
#     )
#     for m in multi_pattern.finditer(text):
#         q = m.group(1).strip()
#         a = m.group(2).strip()
#         cards.append({'type': 'multi', 'Q': q, 'A': a})
#
#     return cards



# def parse_spaced_repetition_file_with_decks_v0(path):
#     with open(path, 'r', encoding='utf-8') as f:
#         lines = f.readlines()
#
#     cards = []
#     current_decks = []
#
#     deck_pattern = re.compile(r'^(?:##|#flashcards)\s*(.+)$', re.IGNORECASE)
#     deck_pattern = re.compile(r'^(?:#flashcards)\s*(.+)$', re.IGNORECASE)
#     single_line_pattern = re.compile(r'^(.*?[^:])::(.*)$')
#     single_line_rev_pattern = re.compile(r'^(.*?[^:]):::(.*)$')
#     multiline_sep = '?'
#
#     buffer = []
#     multiline_mode = False
#
#     def add_multiline_card(buffer, decks):
#         text = ''.join(buffer).strip()
#         # Split at multiline_sep on its own line
#         parts = re.split(r'\n\?\n', text, maxsplit=1)
#         if len(parts) == 2:
#             q, a = parts
#             if not q.lower().startswith('q:'):
#                 q = 'Q: ' + q.strip()
#             if not a.lower().startswith('a:'):
#                 a = 'A: ' + a.strip()
#             cards.append({'type': 'multi', 'Q': q, 'A': a, 'Decks': decks.copy()})
#
#     for line in lines:
#         deck_match = deck_pattern.match(line)
#         if deck_match:
#             # Update current deck(s), split by comma if multiple
#             current_decks = [d.strip() for d in deck_match.group(1).split(',')]
#             continue
#
#         if multiline_mode:
#             if line.strip() == '':
#                 # end of multiline flashcard block
#                 add_multiline_card(buffer, current_decks)
#                 buffer = []
#                 multiline_mode = False
#             else:
#                 buffer.append(line)
#         else:
#             # Check if this line is start of multiline flashcard (e.g. question lines)
#             if multiline_sep in line.strip():
#                 multiline_mode = True
#                 buffer = [line]
#             else:
#                 # Try single line patterns
#                 m = single_line_pattern.match(line)
#                 if m:
#                     q, a = m.group(1).strip(), m.group(2).strip()
#                     cards.append({'type': 'single', 'Q': q, 'A': a, 'Decks': current_decks.copy()})
#                     continue
#                 m = single_line_rev_pattern.match(line)
#                 if m:
#                     q, a = m.group(1).strip(), m.group(2).strip()
#                     cards.append({'type': 'single_reversed', 'Q': q, 'A': a, 'Decks': current_decks.copy()})
#                     continue
#
#     # If still in multiline mode at EOF:
#     if multiline_mode and buffer:
#         add_multiline_card(buffer, current_decks)
#
#     return cards

# def parse_spaced_repetition_file_with_decks_v1(path):
#     with open(path, 'r', encoding='utf-8') as f:
#         lines = f.readlines()
#
#     cards = []
#     current_decks = []
#
#     # Match lines starting with '#flashcards' and capture entire line after it optionally with spaces
#     deck_pattern = re.compile(r'^(#flashcards.*)$', re.IGNORECASE)
#
#     single_line_pattern = re.compile(r'^(.*?[^:])::(.*)$')
#     single_line_rev_pattern = re.compile(r'^(.*?[^:]):::(.*)$')
#     multiline_sep = '?'
#
#     buffer = []
#     multiline_mode = False
#     multiline_mode = True
#
#     def add_multiline_card(buffer, decks):
#         text = ''.join(buffer).strip()
#         parts = re.split(r'\n\?\n', text, maxsplit=1)
#         if len(parts) == 2:
#             q, a = parts
#             if not q.lower().startswith('q:'):
#                 q = 'Q: ' + q.strip()
#             if not a.lower().startswith('a:'):
#                 a = 'A: ' + a.strip()
#             cards.append({'type': 'multi', 'Q': q, 'A': a, 'Decks': decks.copy()})
#
#     for line in lines:
#         deck_match = deck_pattern.match(line.strip())
#         if deck_match:
#             # Entire matched line is the deck description (including all hashes)
#             deck_line = deck_match.group(1).strip()
#             # You can split decks by space or comma if needed, or keep as single string list:
#             current_decks = [deck_line]
#             continue
#
#         if multiline_mode:
#             if line.strip() == '':
#                 add_multiline_card(buffer, current_decks)
#                 buffer = []
#                 multiline_mode = False
#             else:
#                 buffer.append(line)
#         else:
#             if multiline_sep in line.strip():
#                 multiline_mode = True
#                 buffer = [line]
#             else:
#                 m = single_line_pattern.match(line)
#                 if m:
#                     q, a = m.group(1).strip(), m.group(2).strip()
#                     cards.append({'type': 'single', 'Q': q, 'A': a, 'Decks': current_decks.copy()})
#                     continue
#                 m = single_line_rev_pattern.match(line)
#                 if m:
#                     q, a = m.group(1).strip(), m.group(2).strip()
#                     cards.append({'type': 'single_reversed', 'Q': q, 'A': a, 'Decks': current_decks.copy()})
#                     continue
#
#     if multiline_mode and buffer:
#         add_multiline_card(buffer, current_decks)
#
#     return cards

# def parse_spaced_repetition_file(path):
#     with open(path, 'r', encoding='utf-8') as f:
#         text = f.read()
#
#     cards = []
#
#     # Split into flashcard blocks by marker lines that start flashcards or note boundaries (customize as needed)
#     # For simplicity, assume entire file is cards separated by blank lines
#     blocks = re.split(r'\n\s*\n', text.strip())
#
#     for block in blocks:
#         # Try multi-line split based on a line with ? or ??
#         m = re.search(r'^\s*\?{1,2}\s*$', block, re.MULTILINE)
#         if m:
#             # Split front and back on that line
#             parts = re.split(r'^\s*\?{1,2}\s*$', block, maxsplit=1, flags=re.MULTILINE)
#             if len(parts) == 2:
#                 front = parts[0].strip()
#                 back = parts[1].strip()
#                 cards.append({'type': 'multiline', 'Q': front, 'A': back})
#                 continue
#
#         # Fallback single line flashcard syntax
#         m_single = re.match(r'^(.*?)::(.*)$', block, re.DOTALL)
#         if m_single:
#             cards.append({'type': 'single', 'Q': m_single.group(1).strip(), 'A': m_single.group(2).strip()})
#             continue
#
#     return cards

# def parse_spaced_repetition_file_with_decks(path):
#     with open(path, 'r', encoding='utf-8') as f:
#         lines = f.readlines()
#
#     cards = []
#     current_decks = []
#
#     # Deck lines start with '#flashcards' and may include multiple tags (all captured)
#     deck_pattern = re.compile(r'^(#flashcards\S.*)$', re.IGNORECASE)
#
#     # Single line flashcard patterns
#     single_line_pattern = re.compile(r'^(.*?[^:])::(.*)$')
#     single_line_rev_pattern = re.compile(r'^(.*?[^:]):::(.*)$')
#
#     buffer = []
#     multiline_mode = True
#
#     def add_multiline_card(buffer, decks):
#         text = ''.join(buffer).strip()
#         parts = re.split(r'\n\?\n', text, maxsplit=1)
#         if len(parts) == 2:
#             front, back = map(str.strip, parts)
#             if not front.lower().startswith('q:'):
#                 front = 'Q: ' + front
#             if not back.lower().startswith('a:'):
#                 back = 'A: ' + back
#             cards.append({'type': 'multiline', 'Q': front, 'A': back, 'Decks': decks.copy()})
#
#     for line in lines:
#         line_stripped = line.strip()
#         deck_match = deck_pattern.match(line_stripped)
#         if deck_match:
#             # Capture the entire deck tag line, including all spaces and hashes
#             current_decks = [deck_match.group(1)]
#             continue
#
#         if multiline_mode:
#             if line_stripped == '':
#                 add_multiline_card(buffer, current_decks)
#                 buffer = []
#                 multiline_mode = False
#             else:
#                 buffer.append(line)
#         else:
#             # Start multiline mode if line contains a line with "?" used as a split
#             if '?' in line_stripped:
#                 buffer = [line]
#                 multiline_mode = True
#             else:
#                 m = single_line_pattern.match(line)
#                 if m:
#                     q, a = m.group(1).strip(), m.group(2).strip()
#                     cards.append({'type': 'single', 'Q': q, 'A': a, 'Decks': current_decks.copy()})
#                     continue
#                 m = single_line_rev_pattern.match(line)
#                 if m:
#                     q, a = m.group(1).strip(), m.group(2).strip()
#                     cards.append({'type': 'single_reversed', 'Q': q, 'A': a, 'Decks': current_decks.copy()})
#                     continue
#
#     # End of file; finalize any buffered multiline card
#     if multiline_mode and buffer:
#         add_multiline_card(buffer, current_decks)
#
#     return cards

def get_lo_qa_card(text):
    lo_flashcard = []

    # Split text into blocks by lines starting with #flashcards (keep markers)
    block_split = re.split(r'(?=^#flashcards[^\n]*)', text, flags=re.MULTILINE)

    for block in block_split:
        lines = block.strip().split('\n')
        if not lines:
            continue

        # First line is the deck line (contains #flashcards and tags)
        deck_line = lines[0].strip()
        # Capture all deck tags as a list (split by whitespace)
        decks = deck_line.split()

        # The rest is the block content
        content = '\n'.join(lines[1:]).strip()
        if not content:
            continue

        # Split block content into flashcards by blank line (or you can customize)
        card_texts = re.split(r'\n\s*\n', content)

        for card_text in card_texts:
            card_text = card_text.strip()
            if not card_text:
                continue

            # Try single-line reversed (Q:::A)
            m_rev = re.match(r'^(.*?):::(.*)$', card_text, flags=re.DOTALL)
            if m_rev:
                q = m_rev.group(1).strip()
                a = m_rev.group(2).strip()
                lo_flashcard.append({'Decks': decks, 'Q': q, 'A': a})
                continue

            # Try single-line (Q::A)
            m = re.match(r'^(.*?)::(.*)$', card_text, flags=re.DOTALL)
            if m:
                q = m.group(1).strip()
                a = m.group(2).strip()
                lo_flashcard.append({'Decks': decks, 'Q': q, 'A': a})
                continue

            # Try multiline separated by a line containing only '?'
            parts = re.split(r'^\?\s*$', card_text, flags=re.MULTILINE)
            if len(parts) == 2:
                q, a = parts[0].strip(), parts[1].strip()
                lo_flashcard.append({'Decks': decks, 'Q': q, 'A': a})
                continue

            # Skip if no known format matched

    return lo_flashcard



# def get_lo_qa_card(rgx_QA_hash, p_QA, QA_tag):
#     lo_p_fn_qa = []
#     lo_qa_card = []
#
#     for root, _, files in os.walk(p_QA):
#         for fname in files:
#             if fname.endswith('.md'):
#                 p_fn = os.path.normpath(os.path.join(root, fname))
#                 with open(p_fn, 'r') as f:
#                     first_line = f.readline()
#                     if first_line.startswith(QA_tag):
#                         lo_p_fn_qa.append(p_fn)
#
#     pattern = r"^#flashcard.*?(?=^#flashcard|\Z)"
#     for p_fn_qa in lo_p_fn_qa:
#         with open(p_fn_qa, 'r', encoding='utf-8') as f:
#             text = f.read()
#
#         blocks = re.findall(pattern, text, re.DOTALL | re.MULTILINE)
#
#         print(f"\n###############\n")
#         for i, block in enumerate(blocks, 1):
#             # print(f"Block {i}:\n{block}\n------")
#             lo_qa_card = parse_flashcards(block)
#             pprint.pprint(lo_qa_card)
#
#         return
#
#         if not lines:
#             continue
#
#         first_line = lines[0].strip()
#         if not first_line.startswith(prefix):
#             continue
#
#         s_deck = first_line[len(prefix):]
#
#         content = ''.join(lines)
#
#         lo_s_qa = [m.group(0) for m in chunk_pattern.finditer(content)]
#
#         for s_QA in lo_s_qa:
#             if '#flashcard' in s_QA:
#                 match = re.search(rgx_QA_hash, s_QA)
#                 QA_hash = match.group(0) if match else ''
#                 lo_qa_card.append({
#                     'QA_deck': s_deck,
#                     'QA_hash': QA_hash,
#                     's_QA': s_QA,
#                     'file_path': p_fn_qa,
#                 })
#
#     return lo_qa_card

def merge_QA_items(lo_qa_entry, lo_qa_card):
    # Set of all QA_deck from lo_qa_card
    so_qa_card_QA_deck = set(qa_card['QA_deck'] for qa_card in lo_qa_card)
    print("so_qa_card_QA_deck:")
    pprint.pprint(so_qa_card_QA_deck)

    # Set of all [QA_deck, QA_hash] pairs where QA_hash is not ''
    so_qa_card_QA_hash = set(
        (qa_card['QA_deck'], qa_card['QA_hash'])
        for qa_card in lo_qa_card if qa_card['QA_hash'] != ''
    )
    print("so_qa_card_QA_hash:")
    pprint.pprint(so_qa_card_QA_hash)

    lo_new_qa_card = []

    for qa_entry in lo_qa_entry:
        qa_pair = (qa_entry['QA_deck'], qa_entry['QA_hash'])
        if qa_pair not in so_qa_card_QA_hash:
            new_qa_card = {
                'QA_deck': qa_entry['QA_deck'],
                's_QA': qa_entry['s_QA'],
                'QA_hash': qa_entry['QA_hash']
            }
            lo_new_qa_card.append(new_qa_card)

    # print("\nlo_new_qa_card:")
    # pprint.pprint(lo_new_qa_card)
    return lo_new_qa_card


def main():
    ini_path = 'tac.ini'
    p_root, ext, p_QA, QA_tag = load_config(ini_path)

    all_files   = find_files_with_extension(p_root, ext)

    # get list of all QA's in *.md but not in QA-files (flashcard|anki| ...)
    lo_qa_entry = get_lo_qa_entry(all_files)

    # get list of all QA's in QA-files (flashcard)
    # lo_qa_card  = get_lo_qa_card(rgx_QA_hash, p_QA, QA_tag)

    lo_p_fn_qa = []
    lo_qa_card = []

    for root, _, files in os.walk(p_QA):
        for fname in files:
            if fname.endswith('.md'):
                p_fn = os.path.normpath(os.path.join(root, fname))
                with open(p_fn, 'r') as f:
                    first_line = f.readline()
                    if first_line.startswith(QA_tag):
                        lo_p_fn_qa.append(p_fn)

    for p_fn_qa in lo_p_fn_qa:
        with open(p_fn_qa, 'r', encoding='utf-8') as f:
            qa_file_text = f.read()
            # lo_qa_card  = parse_spaced_repetition_file(p_fn_qa)
            # lo_qa_card  = parse_spaced_repetition_file_with_decks(p_fn_qa)
            # lo_qa_card  = parse_spaced_repetition_file_with_decks(p_fn_qa)
            lo_qa_card  = get_lo_qa_card(qa_file_text)
            pass


    # all_files   = find_files_with_extension(p_root, ext)
    # lo_qa_entry = get_lo_qa_entry(all_files)
    #
    # lo_qa_card  = get_lo_qa_card(rgx_QA_hash, p_QA)

    # for entry in lo_qa_entry:
    #     print(entry)
    #
    # for qa_card in lo_qa_card:
    #     print(qa_card)

    # lo_qa_card_updated = merge_QA_items(lo_qa_entry, lo_qa_card)

if __name__ == "__main__":
    main()
