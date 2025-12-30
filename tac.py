'''
tac == _T_ransfer (to)  _A_nki _C_ards  ...
... but connections to anki did not work, so the Spaced Repetition version was programmed.

vs 1.xx:  _without_ connecting to anki, but using Spaced Repetition obsidian plugin.

This script serves to extract QA text-blocks in obsidian files to be used in Spaced Repetition flashcards
(aka SR-plugin) (or to be transfered to anki (not yet realized)).

Script scans obsidian notes for QA-text blocks and transfers them into specific obsidian flashcard notes,
that can be used to generate flashcards by obsidian plugin >Spaced Repetition< or by anki (to realize).
The SR-plugin adds certain informations to the entries, to realize the repetition process.

The paths pf the obsidian notes are configured in >tac.ini<

QA-text blocks begin with a specific tag (QA-tag) followed by a Question - Answer section.

Script checks if QA-text blocks already transfered, if not it changes the tag to the SR-format and adds the block.
Every QA-text block gets a individual hash value >QA_ID<, specific of QA-Text, file origin and QA-tag.
The filename of obsidian note is added.

Configuration of SR-plugin:
- let the default flashcard tag >#flashcards< unchanged.

github repository:
    https://github.com/rwrmanns/zotero-obsidian_split_atomic_notes


do_QA = {
    'path'           : file_path,        # f path
    'fn_QA_SR'       : fn,               # filename
    "QA_deck"        : do_QA["QA_deck"], # deck of QA
    "QA"             : s_QA,             # complete string of QA
    "QA_Q"           : QA_Q,             # Question
    "QA_A"           : QA_A,             # Answer
    "QA_TimeStamp"   : QA_TimeStamp,     # timestamp of Spaced Repetition obsidian plugin
    "QA_zotero_hash" : QA_zotero_hash,   # hash of note (from frontmatter - but where does it come from ??)
    "QA_d8_hash"     : QA_d8_hash,       # hash of specific question QA_deck included
    "QA_ID"          : QA_ID             # specific ID of QA + deck.
                                         # if >QA_d8_hash< != third part of  >QA_ID<   => >QA< ond/or deck has changed.
}

'''


import configparser
import deepdiff
import difflib
import frontmatter
import hashlib
import io
import os
import random
import re
import sys
import zoneinfo

from collections import Counter
from datetime import date
from datetime import datetime
from os.path import basename
from pprint import pprint
from re import split


import json

flashcard_sys = 'anki'
#flashcard_sys = 'flashcards'
flashcard_sys = 'spaced_repetition'

p_root        = ''
lo_subdir     = []
ext           = ''
p_fn_QA       = ''

SR_tag        = ''
QA_tag        = ''

cnt_new_QA    = 0

fn_QA_SR      = '' # fn_QA_SR of Spaced_Repetition specific flashcards File  (from >tac.ini<)
fn_anki_QA    = '' # fn_QA_SR of Anki              specific flashcards File  (from >tac.ini<)

fn_prefix     = '_NEW_'

QA_separator  = '...'

rgx_html_comment = re.compile(r'<!--.*?-->', re.DOTALL)

rgx_QA_exclude       = None
rgx_QA_DECK          = None
rgx_d8_hash          = None
rgx_QA_startword     = None
rgx_QA_block         = None
rgx_QA_split         = None
rgx_QA_ID            = None          # tacID: unique identifier of QA + deck
rgx_QA_SR_hash       = None          # hash of deck + s_QA
rgx_html_comment     = None          # Regex that matches HTML comments (including multiline)
rgx_flashcard_backup = None
rgx_norm_QA_deck     = None



def get_rgx_QA_block():
    # gemini

    # 1. Define the base keywords list
    # Note: Added '?' to #flashcards to handle plural/singular mismatch between prompt list and input text
    keywords = [r'#flashcards?', r'#QA']

    # Join keywords for regex OR logic: (#flashcards?|#QA)
    keywords_pattern = '|'.join(keywords)

    # 2. Define the Regex Parts
    # Start Tag: Keywords + optional ext (starting with _ or / per your examples)
    # We use (?:...) for non-capturing groups to keep the result clean
    rgx_start = fr"(?:{keywords_pattern})(?:[_\/][\w\/]{{0,30}})?"

    # Stop Tag / Separator: The literal ___ or --- or the start of a new tag
    # We use a Lookahead (?=...) so we check for the stop tag but do not include it in the match
    rgx_stop_lookahead = fr"(?=^{rgx_start}|^(?:---|___)\s*$|\Z)"

    # 3. Compile the Full Regex
    # Pattern: (Start_Tag)(Content)(Stop_Lookahead)
    # Flags:
    #   re.MULTILINE (m): ^ matches start of lines
    #   re.DOTALL (s): . matches newlines (so we capture multi-line content)
    rgx_QA_block = re.compile(
        fr"(?P<block>^{rgx_start}.*?){rgx_stop_lookahead}",
        re.MULTILINE | re.DOTALL
    )
    return rgx_QA_block, rgx_start


def load_config(ini_path):
    global rgx_QA_exclude
    global rgx_QA_DECK
    global rgx_d8_hash
    global rgx_QA_startword
    global rgx_QA_block
    global rgx_QA_split
    global rgx_QA_ID
    global rgx_QA_SR_hash
    global rgx_html_comment
    global rgx_flashcard_backup
    global rgx_norm_QA_deck

    global p_root
    global lo_subdir
    global ext
    global p_fn_QA
    global SR_tag
    global QA_tag
    global fn_QA_SR
    global fn_anki_QA

    config = configparser.ConfigParser()
    config.read(ini_path)


    p_root      = config['DEFAULT']['p_root']
    subdirs_raw = config['DEFAULT']['lo_subdir']
    lo_subdir   = [subdir.strip() for subdir in subdirs_raw.split(",")]

    ext         = config['DEFAULT']['ext']
    p_fn_QA     = config['DEFAULT']['p_fn_QA']
    SR_tag      = config['DEFAULT']['SR_tag']
    QA_tag      = config['DEFAULT']['QA_tag']
    fn_QA_SR    = config['DEFAULT']['fn_QA_SR']
    fn_anki_QA  = config['DEFAULT']['fn_anki_QA']

    rgx_QA_exclude   = re.compile(config['DEFAULT']['rgx_QA_exclude'], re.MULTILINE | re.DOTALL)
    rgx_QA_DECK      = re.compile(config['DEFAULT']['rgx_QA_DECK'], re.MULTILINE | re.DOTALL)
    # rgx_d8_hash      = re.compile(config['DEFAULT']['rgx_d8_hash'], re.MULTILINE | re.DOTALL)
    rgx_QA_ID        = re.compile(config['DEFAULT']['str_QA_ID'])
    rgx_html_comment = re.compile(r'<!--.*?-->', re.DOTALL)
    rgx_QA_SR_hash   = re.compile(r"([A-Z0-9]{8})(?:_(\d{3}))?(?:_(\d{8}))?")


    #########  rgx_QA_block  ###########
    QA_lo_start_tag  = ['#flashcards', '#QA']
    lo_QA_startword  = [re.escape(sw) for sw in QA_lo_start_tag]
    s_startword_tail = r"[A-Za-z0-9_/\-\\]{0,25}"
    rgx_QA_startword = r"(?:%s)%s" % ("|".join(lo_QA_startword), s_startword_tail)

    # QA_lo_start_tag = ['#flashcards', '#QA']
    # lo_QA_startword = [re.escape(sw) for sw in QA_lo_start_tag]
    # s_startword_tail = r"_[A-Za-z0-9_/\-\\]{0,25}"
    #
    # rgx_QA_startword = rf'^({"|".join(lo_QA_startword)}){s_startword_tail}?$'


    # Escape each tag so '#' and other characters become literal.
    rgx_QA_lo_start_tag = "|".join(re.escape(tag) + r"_[A-Za-z0-9._-]+" for tag in QA_lo_start_tag)  # tag + file-safe chars

    # Compile begin-regex (still matches only at the beginning of a line)
    rgx_QA_block_begin = re.compile(rf"^(?:{rgx_QA_lo_start_tag})", re.MULTILINE)

    # Compile begin-regex (still matches only at the beginning of a line)
    # rgx_QA_block_begin = re.compile(rf"^(?:{rgx_QA_startword})", re.MULTILINE)

    QA_lo_stop_tag = ["Quelle: ", "source: "]

    # Combine:
    # - fixed stopword lines (escaped)
    # - block-begin lines as QA_lo_stop_tag (so a new block ends the previous one)
    rgx_QA_lo_stop_tag = "|".join([re.escape(w) for w in QA_lo_stop_tag] + [rgx_QA_lo_start_tag])

    # MAIN BLOCK EXTRACTION REGEX
    rgx_QA_block = re.compile(
        rf"""
        (?P<begin> {rgx_QA_block_begin.pattern}   # block starts here
        )
        (?P<body>  .*?                            # non-greedy body text
        )
        (?= ^(?:{rgx_QA_lo_stop_tag})             # stop BEFORE stopword/next block
        )
        """,
        re.DOTALL | re.MULTILINE | re.VERBOSE
    )

    rgx_QA_block, rgx_norm_QA_deck = get_rgx_QA_block()

    # Split QA in Q and A
    rgx_QA_split = re.compile(
        r'^'
        r'(?P<QA_Q>.*?)'  # non-greedy: content before separator
        r'(?:'
        r'(?=\nA:\s)'  # A: separator → lookahead (keep it!)
        # r'|' r'\n?\n'  # blank line
        r'|' r'\n\?\n'  # line with ?
        r'|' r'\n\?\?\n'  # line with ??
        r'|' r':::'  # :::
        r'|' r'::'  # ::
        r')'
        r'(?P<QA_A>.*)'  # Answer part, includes A: when present
        r'$',
        re.DOTALL
    )

    rgx_flashcard_backup = re.compile(
        r"""
        \.                        # literal dot
        \d{4}-\d{2}-\d{2}         # YYYY-MM-DD
        (?:_\d{2}-\d{2}-\d{2})?   # optional _hh-mm-ss (two digits)
        $                         # end of string
        """,
        re.VERBOSE,
    )

    # Flashcard tags: or '#flashcards' or some user defined tag.
    # We use: '#flashcards' or 'QA_*'. Something like '#QA_myQuestion' will
    # be splitted into: '#QA/myQuestion'
    # rgx_norm_QA_deck = re.compile(r"^(#QA)_([A-Za-z0-9/_-]+)$", flags=re.IGNORECASE)

    # rgx_d8_hash matches an 8 digit hash preceded by '_'
    rgx_d8_hash = r"_\d{8}"

    return p_root, ext, p_fn_QA, SR_tag


def remove_font_color_tags(text):
    # 1. Pattern for legacy <font color="..."> tags
    # Matches <font [anything] > [content] </font>
    # We use re.IGNORECASE to handle <FONT> or <font>
    # We use re.DOTALL to handle tags spanning multiple lines
    font_tag_pattern = r'<font\b[^>]*>(.*?)</font>'

    # 2. Pattern for <span style="...color:..."> tags
    # Matches <span [anything] style="[anything]color:[anything]" [anything] > [content] </span>
    span_color_pattern = r'<span\b[^>]*\bstyle=[^>]*color:[^>]*>(.*?)</span>'

    # Remove <font> tags first
    # \1 refers to the first capture group (the text inside the tags)
    cleaned_text = re.sub(font_tag_pattern, r'\1', text, flags=re.IGNORECASE | re.DOTALL)

    # Remove <span> tags with color styles
    cleaned_text = re.sub(span_color_pattern, r'\1', cleaned_text, flags=re.IGNORECASE | re.DOTALL)

    return cleaned_text

# # --- Test ---
#
# markdown_input = """
# # Header
# This is normal text.
# This is <font color="red">red text using the font tag</font>.
# This is <span style="color: blue;">blue text using inline css</span>.
# This is <font color='#00FF00'>hex color text</font>.
# Mixed <span style="font-weight:bold; color:green">bold and green</span> text.
# """
#
# result = remove_font_color_tags(markdown_input)
#
# print("-------- Original --------")
# print(markdown_input)
# print("\n-------- Cleaned --------")
# print(result)

def generate_random_hash(length=8):
    return ''.join(random.choices('ABCDEFGHIJKLMNOPQRSTUVWXYZ123456789', k=length))

def get_cleaned_line(line):
    # clean line from whitespaces; purge horizontal lines.
    if not line.strip():
        return False
    if re.search(r"-{3,}", line):  # r"-{3,}" == horizontal line
        return False
    if re.search(r"_{3,}", line):  # r"_{3,}" == horizontal line
        return False
    return True

def get_lo_QA_deck_block(text):
    # QA_deck_block == block of text ...
    # ... beginning with tag indicating deck of one or more following QAs.

    lo_QA_deck_block = []
    matches = [block.group() for block in rgx_QA_block.finditer(text)]
    if not matches:
        return []

    for idx, block_text in enumerate(matches):

        # for example: #ToDo_QA
        if rgx_QA_exclude.search(block_text):
            continue

        lines = block_text.splitlines()

        deck_line = lines[0]
        qa_lines  = lines[1:]

        deck_clean = "\n".join(ln for ln in [deck_line] if get_cleaned_line(ln))
        qa_clean   = "\n".join(ln for ln in qa_lines    if get_cleaned_line(ln))

        # list of decks
        lo_QA_deck = re.findall(rgx_QA_startword, deck_clean)

        lo_QA_deck_block.append({
            "DECK": deck_clean,
            "QA": qa_clean,
            "lo_QA_deck": lo_QA_deck
        })

    return lo_QA_deck_block


def get_lo_d_QA(QA_deck_block ):
    # >QA_deck_block< == block of text beginning with one or more tags (== >deck< entries)
    #    followed by one or more QA-text without >deck< entries.
    # Transform >QA_deck_block< into cartesian product (lo of dict): item == every deck with every QA_text.

    QA_text, lo_QA_deck = QA_deck_block["QA"], QA_deck_block["lo_QA_deck"]
    # print(f'{QA_text = }')
    positions = [m.start() for m in re.finditer(r"^Q: ", QA_text, re.MULTILINE)]
    if not positions:
        return []

    positions.append(len(QA_text))

    lo_s_QA = []
    for i in range(len(positions) - 1):
        start = positions[i]
        end = positions[i + 1]
        chunk = QA_text[start:end].strip()
        if chunk:
            lo_s_QA.append(chunk)

    lo_d_QA = []
    for deck in lo_QA_deck:
        for s_QA in lo_s_QA:
            lo_d_QA.append({
                "QA_deck": deck,
                "s_QA": s_QA
            })
    return lo_d_QA


def get_d8_hash(s_in):
    # calcs SHA256 hash of QA_A and returns last 8 characters as string
    h = hashlib.sha256(s_in.encode("utf-8")).hexdigest()
    return h[-8:]


def get_QA_Q_and_A(s_QA):
    # split s_QA in Q and A
    m = rgx_QA_split.match(s_QA)
    if m:
        QA_Q = m.group("QA_Q").strip()
        QA_A = m.group("QA_A").strip()
    else:
        QA_Q = s_QA.strip()
        QA_A = ""

    return QA_Q, QA_A

def get_QA_ID(QA_A):
    #
    matches = []

    for m in rgx_QA_ID.finditer(QA_A):
        qa_string = m.group(0)
        # print("get_QA_ID: QA_ID = ", qa_string)

        matches.append({
            'QA_string': qa_string,
            'prefix': m.group("prefix"),
            'z_hash': m.group("z_hash"),
            'QA_deck_hash': m.group("QA_deck_hash")
        })
        return matches[0]['QA_string']
    else :
        return None

def b_test_do_QA(do_QA):

    s_QA_deck     = do_QA["QA_deck"]
    s_QA          = do_QA["QA"]
    s_QA_d8_hash  = do_QA["QA_d8_hash"]

    s_deck_and_QA = do_QA["QA_deck"] + ' - ' + s_QA
    QA_d8_hash    = get_d8_hash(s_deck_and_QA)
    QA_ID         = get_QA_ID(s_QA)

    return (QA_d8_hash == s_QA_d8_hash)



def get_normalized_QA_deck(s_QA_deck):
    # normalize QA_deck: Obsidian Plugin Spaced Repetition demands as

    # If >s_QA_deck< begins with: '#flashcards'
    # if s_QA_deck.startswith("#flashcards"): return s_QA_deck

    s_QA_deck = re.sub(r"_+", "_", s_QA_deck)
    s_QA_deck = re.sub(r"_", "/", s_QA_deck)
    return f"{s_QA_deck}"


def get_normalized_lo_d_QA(lo_do_QA, file_path, fn, QA_zotero_hash):
    # extract and purge html comments and hashes
    # normalize Spaced Repetition tag

    lo_do_QA_normalized = []
    for do_QA in lo_do_QA:
        s_QA = do_QA["s_QA"]

        # Purge HTML comments and old hash-like strings
        # s_clean = rgx_html_comment.sub("", s_QA)
        # s_clean = rgx_QA_SR_hash.sub("", s_clean)
        # s_clean = rgx_QA_ID.sub("", s_clean)
        # s_QA    = s_clean.strip()

        # Extract QA_TimeStamp ( is in HTML comment )
        m_comment    = rgx_html_comment.search(s_QA)
        QA_TimeStamp = m_comment.group(0) if m_comment else None

        # Purge HTML comments from s_QA
        s_QA       = rgx_html_comment.sub("", s_QA)
        s_QA       = s_QA.strip()

        # get Q & A
        QA_Q, QA_A = get_QA_Q_and_A(s_QA)

        # normalize Spaced Repetition tag:
        qa_tag     = get_normalized_QA_deck(do_QA["QA_deck"])

        do_QA["QA_deck"] = qa_tag
        # do_QA["QA_deck"] = get_normalized_QA_deck(do_QA["QA_deck"])
        # If there is no "QA_ID" at the end of QA_A
        s_deck_and_QA = do_QA["QA_deck"] + ' - ' + s_QA
        QA_d8_hash = get_d8_hash(s_deck_and_QA)
        QA_ID = get_QA_ID(s_QA)

        m_QA_ID = rgx_QA_ID.search(s_QA)
        QA_ID   = m_QA_ID.group(0) if m_QA_ID else None

        if not QA_ID:
            # Compute new deterministic hash == ID from original s_QA combining QA-text and deck.
            QA_ID = '(' + 'QA_ID_' + QA_zotero_hash + '_' + QA_d8_hash + ')'  # specific ID of QA + deck.

        # Build normalized dict
        do_QA = {
            'path'           : file_path,        # f path
            'fn_QA_SR'       : fn,               # filename
            "QA_deck"        : do_QA["QA_deck"], # deck of QA
            "QA"             : s_QA,             # complete string of QA
            "QA_Q"           : QA_Q,             # Question
            "QA_A"           : QA_A,             # Answer
            "QA_TimeStamp"   : QA_TimeStamp,     # timestamp of Spaced Repetition obsidian plugin
            "QA_zotero_hash" : QA_zotero_hash,   # hash of note (from frontmatter - but where does it come from ??)
            "QA_d8_hash"     : QA_d8_hash,       # hash of specific question QA_deck included
            "QA_ID"          : QA_ID             # specific ID of QA + deck.
                                                 # if >QA_d8_hash< != third part of  >QA_ID<   => >QA< ond/or deck has changed.
        }

        if b_test_do_QA(do_QA):
            lo_do_QA_normalized.append(do_QA)

    return lo_do_QA_normalized

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


def get_lo_fn_path_with_extension(root, lo_subdir, ext):

    def add_path(ext, lo_fn_pth, root_path):
        # print(f'>add_path():< {root_path = } ')
        # 'C:\\Users\\rh\\Meine Ablage\\obsidian_rh_GoogleDrive\\02_Notes_zotero_Annotations_anki\\bleasePaternalismus2016__Annotations__OK\\01_Notes_rh'
        # 'C:\\Users\\rh\\Meine Ablage\\obsidian_rh_GoogleDrive\\02_Notes_zotero_Annotations_anki\\bleasePaternalismus2016__Annotations__OK\\01_Notes_rh'
        list_dir = os.listdir(os.path.normpath(root_path))
        # pprint(list_dir)
        for current_dir, _, filenames in os.walk(root_path):
            for fname in filenames:
                if fname.endswith(ext):
                    path_fn = os.path.normpath(os.path.join(current_dir, fname))
                    lo_fn_pth.append(path_fn)
                    # print(f'{path_fn=}')

    lo_fn_pth = []
    print(f'>get_lo_fn_path_with_extension()<: {root = }')
    if lo_subdir:
        for subdir in lo_subdir:
            root_path = os.path.join(root, subdir)
            # print(f' {subdir =    } \n {root_path = }')
            print(f'  {subdir = }')
            add_path(ext, lo_fn_pth, root_path)
    else:
        add_path(ext, lo_fn_pth, root)

    print()
    return lo_fn_pth


def get_l_s_QA_deck(content, fixed_QA_prefix):
    # rgx_QA_DECK matches the deck-tags for Spaced Repetition
    deck_matches = rgx_QA_DECK.findall(content)
    lo_QA_deck = [m[len(fixed_QA_prefix) + 1:] if m.startswith(fixed_QA_prefix) else m for m in deck_matches]
    if len(lo_QA_deck) == 0:
        lo_QA_deck = ['Default']
    return lo_QA_deck


def files_are_identical(new_file_path, content2):
    if not os.path.isfile(new_file_path):
        return False
    with open(new_file_path, 'r', encoding='utf-8') as f1:
        content1 = f1.read()
    return content1 == content2

def get_QA_zotero_hash_from_frontmatter(file_path, metadata: dict[str, object], post, rgx_QA_SR_hash) -> str:
    # QA_zotero_hash == frontmatter['san']['zotero_hash'] ... to identify note or zotero annotation.
    # Serves to create a unique ID of QA. If not present then will be generated.
    QA_SR_hash = None
    if 'san' in metadata and isinstance(metadata['san'], dict):
        candidate = metadata['san'].get('zotero_hash')
        if candidate and rgx_QA_SR_hash.search(candidate):
            QA_SR_hash = candidate

    if not QA_SR_hash:
        # fake: ['san']['zotero_hash']
        QA_SR_hash = generate_random_hash()
        if 'san' not in metadata or not isinstance(metadata['san'], dict):
            metadata['san'] = {}
        metadata['san']['zotero_hash'] = QA_SR_hash
        post.metadata = metadata
        with open(file_path, 'w', encoding='utf-8') as f:
            f.write(frontmatter.dumps(post))
    return QA_SR_hash

def get_lo_all_QA_hashes(content: str, rgx_QA_SR_hash) -> list:
    if flashcard_sys == 'anki':
        lo_all_QA_hashes = rgx_QA_SR_hash.findall(content)
    elif flashcard_sys == 'spaced_repetition':
        # In
        lo_html_comment  = rgx_html_comment.findall(content)
        lo_all_QA_hashes = []
        for html_comment in lo_html_comment:
            if rgx_QA_SR_hash.findall(html_comment):
                lo_all_QA_hashes += rgx_QA_SR_hash.findall(html_comment)
    else:
        exit('get_lo_all_QA_hashes(): flashcard_sys?')
    return lo_all_QA_hashes



def get_lo_s_QA(content: str) -> list[str]:
    # from *.md notes get QA. Transform them into a flashcard file (obsidian Spaced Repetition / anki ?)
    if flashcard_sys == 'spaced_repetition':

        iter_QA_match  = rgx_QA_block.finditer(content)
        for QA_match in iter_QA_match:
            if QA_match:
                s_lo_QA_deck = QA_match.group('rgx_lo_QA_deck')
                QA_Question  = QA_match.group('QA_Question')
                QA_type      = QA_match.group('QA_type')
                QA_Answer    = QA_match.group('QA_Answer')
                lo_QA_deck   = s_lo_QA_deck.split(' ')
            else:
                return None

        l_qa_match = rgx_QA_block.findall(content)
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


def get_lo_QA_file(file_paths):
    # return list of lo_fn_note that contain QA - text blocks.
    lo_do_QA_files = []
    for file_path in file_paths:
        fn = os.path.basename(file_path)
        try:
            post = frontmatter.load(file_path)
            content_io = io.StringIO(post.content)
            content = content_io.read()
        except Exception as e:
            print(f"Warning: Could not load frontmatter from {file_path}: {e}")
            continue

        # Pattern of QA
        QA_matches =  rgx_QA_block.finditer(content)
        if not QA_matches:
            continue

        d_QA_file = dict()
        d_QA_file['fn_QA_SR']      = fn
        d_QA_file['path']    = file_path
        d_QA_file['post']    = post
        d_QA_file['content'] = content
        lo_do_QA_files.append(d_QA_file)
    return lo_do_QA_files


def get_lo_QA_entry(lo_fn_note):
    # return list of all QA-entries of obsidian notes that are in >lo_fn_note<:
    #  ? qa_entry.QA, possibly qa_entry.QA_zotero_hash, qa_entry.QA_deck ?

    # >lo_do_QA_note< list of all files with QA section.
    lo_do_QA_note      = get_lo_QA_file(lo_fn_note)

    lo_do_QA_entry     = []
    for do_QA_note in lo_do_QA_note:
        # QA == Question-Answer text .
        file_path      = do_QA_note['path']
        fn             = do_QA_note['fn_QA_SR']
        content        = do_QA_note['content']
        post           = do_QA_note['post']

        metadata       = post.metadata
        QA_zotero_hash = get_QA_zotero_hash_from_frontmatter(file_path, metadata, post, rgx_QA_SR_hash)

        # QA_deck_block == block of text beginning with tag indicating deck of one or more QAs.
        lo_QA_deck_block = get_lo_QA_deck_block(content)

        # >lo_do_QA_entry_org< == raw QA text block as is (with Timestamp, Anki-, obsidian- ID or similar ...)
        # Will be cleaned from that. --> >lo_do_QA_entry<
        lo_do_QA_entry_org = []
        # transform multiple QA textblock in multiple dicts of QA: "QA_deck": ..., "s_QA": ...
        for QA_deck_block in lo_QA_deck_block:
            lo_do_QA_entry_org.extend(get_lo_d_QA(QA_deck_block))

        # normalize every d_QA and add hash of Text of QA
        # Normalize and clean QA from Timestamp of Spaced Repetition and ID of tac.py and ...
        # ... add: file_path, fn_QA_SR, QA_zotero_hash
        lo_do_QA_entry.extend(get_normalized_lo_d_QA(lo_do_QA_entry_org, file_path, fn, QA_zotero_hash))

    return lo_do_QA_entry


def get_lo_do_QA_SR(lo_p_fn_SR):
    # get all entries in Spaced Repetition obsidian note == QAs already usable by SR
    # get >lo_flashcard< == all Q&As

    # get FILE NAMES: >lo_fn_SR< == FILES that contain Q&A-entries in _Spaced Repetition_ format.
    # Only this/these files are used by the Spaced Repetition Plugin in Obsidian to define flashcards.
    lo_fn_SR = get_lo_fn_SR()  # List of _FILE names_

    lo_flashcard       = []
    lo_QA_deck_block   = []   # list of dict with:
    lo_do_QA_SR        = []
    lo_do_QA_entry_org = []

    # With every _file_ containing flashcard style QAs:
    for p_fn_flashcard in lo_p_fn_SR:
        with open(p_fn_flashcard, 'r', encoding='utf-8') as f:
            qa_file_text = f.read()

        # print(p_fn_flashcard)
        pass

        qa_file_text = remove_font_color_tags(qa_file_text)

        # Split s_text into blocks by lines starting with '#flashcards'
        lo_block_text = re.split(r'(?=^#flashcards[^\n]*)', qa_file_text, flags=re.MULTILINE)

        # file may contain more than one QA blocks.
        # Block == one or more decks on first line
        #          followed by one or more QA that may be on one or more lines.
        for block_text in lo_block_text:
            lines = block_text.strip().splitlines()
            if not lines:
                continue

            # First line is the deck line (contains #flashcards and tags)
            deck_line = lines[0]
            # QA - lines:
            txt_lines  = lines[1:]
            # >txt_lines< contain Q&A
            # followed by QA_separator (global)
            # followed by fn of obsidian note of origin
            # followed by QA_ID
            # followed by timestamp

            deck_clean = "\n".join(ln for ln in [deck_line] if get_cleaned_line(ln))
            txt_clean  = "\n".join(ln for ln in txt_lines   if get_cleaned_line(ln))

            # get all deck tags
            lo_QA_deck = re.findall(rgx_QA_startword, deck_clean)

            qa_lines   = []
            idx_separ  = 0
            for idx, line in enumerate(txt_lines):
                if line == QA_separator:
                    idx_separ = idx
                    break
                else:
                    qa_lines.append(line)

            qa_clean   = "\n".join(ln for ln in qa_lines if get_cleaned_line(ln))

            fn_QA_SR     = txt_lines[idx_separ + 1],
            QA_ID        = txt_lines[idx_separ + 2],
            QA_TimeStamp = txt_lines[idx_separ + 2],

            lo_QA_deck_block.append({
                "lo_QA_deck"   : lo_QA_deck,
                "DECK"         : deck_clean,
                "QA"           : qa_clean,
                "fn_QA_SR"     : fn_QA_SR,
                "QA_ID"        : QA_ID,
                "QA_TimeStamp" : QA_TimeStamp,
            })

            # do_QA = {
            #     'path': file_path,  # f path
            #     'fn_QA_SR': fn,  # filename
            #     "QA_deck": do_QA["QA_deck"],  # deck of QA
            #     "QA": s_QA,  # complete string of QA
            #     "QA_Q": QA_Q,  # Question
            #     "QA_A": QA_A,  # Answer
            #     "QA_TimeStamp": QA_TimeStamp,  # timestamp of Spaced Repetition obsidian plugin
            #     "QA_zotero_hash": QA_zotero_hash,  # hash of note (from frontmatter - but where does it come from ??)
            #     "QA_d8_hash": QA_d8_hash,  # hash of specific question QA_deck included
            #     "QA_ID": QA_ID  # specific ID of QA + deck.
            #     # if >QA_d8_hash< != third part of  >QA_ID<   => >QA< ond/or deck has changed.
            # }


            # >lo_do_QA_entry_org< == raw QA text block as is (with Timestamp, Anki-, obsidian- ID or similar ...)
            # Will be cleaned from that. --> >lo_do_QA_SR<
            lo_do_QA_entry_org = []
            # transform multiple QA textblock in multiple dicts of QA: "QA_deck": ..., "s_QA": ...
            for QA_deck_block in lo_QA_deck_block:
                lo_do_QA_entry_org.extend(get_lo_d_QA(QA_deck_block))

            # file_path = p_fn_flashcard
            # fn_QA_SR = os.path.basename(file_path)

        if lo_do_QA_entry_org:
            lo_do_QA_SR.extend(get_normalized_lo_d_QA(lo_do_QA_entry_org, file_path = p_fn_flashcard, fn = os.path.basename(p_fn_flashcard), QA_zotero_hash ='flashcar'))
    return lo_do_QA_SR


def get_lo_fn_SR():
    # return list of path of every *.md file that contains  Q&A's in flashcard (== Spaced Repetition) format.
    p_QA     = os.path.join(p_fn_QA, fn_QA_SR)
    str_p_fn_QA = p_QA.replace("\\\\", "\\")
    # print(f'p_QA = {str_p_fn_QA}')
    lo_p_fn_qa = []
    for root, _, files in os.walk(p_QA):
        # print(p_QA)
        # with open(p_QA, 'r', encoding='utf-8') as f:
        for fname in files:
            # print(fname)
            with open(os.path.join(root, fname), 'r', encoding='utf-8') as f:
                if fname.endswith('.md') and not b_filter_backup_flashcard_file(fname, '.md'):
                    # print(fname)
                    p_fn = os.path.normpath(os.path.join(root, fname))
                    with open(p_fn, 'r') as f:
                        first_line = f.readline()
                        if first_line.startswith(SR_tag):
                            print(f'{fname      = }')
                            print(f'{first_line = }')
                            lo_p_fn_qa.append(p_fn)
    if lo_p_fn_qa:
        print('>get_lo_fn_SR()<: Spaced Repetition Files:')
        for ele in lo_p_fn_qa: print('  ', ele)
    else:
        print(f'>get_lo_fn_SR()<: NO Spaced Repetition Files found in: \n  {p_QA}')
        print(f'  expected file:\n  {p_QA}')
    print()
    return lo_p_fn_qa


def get_lo_do_QA_merge(lo_do_qa_entry, lo_do_QA_SR):
    # Add to >lo_do_QA_SR< all items of >lo_do_qa_entry< that are not already present in >lo_do_QA_SR<.

    global cnt_new_QA
    lo_do_QA_merged = []

    # Make a set of all QA_IDs in >lo_do_QA_SR<.
    # If QA_ID of element of >lo_do_qa_entry< is not present in >lo_do_QA_SR<
    #   then add it to >lo_do_QA_merged<.
    so_QA_SR_QA_ID  = set()  # set of all QA_IDs in >lo_do_QA_SR<
    pass
    # Add every QA_ID from >lo_do_QA_SR< (== QA_IDs present in SR-file) to set:
    for do_QA_SR in lo_do_QA_SR:
        so_QA_SR_QA_ID.add(do_QA_SR["QA_ID"])

    for do_qa_entry in lo_do_qa_entry:
        if do_qa_entry["QA_ID"] not in so_QA_SR_QA_ID:
            print ('>>> ', do_qa_entry["fn_QA_SR"])
            do_qa_entry['QA_deck'] = do_qa_entry['QA_deck'].replace(QA_tag, SR_tag)
            lo_do_QA_merged.append(do_qa_entry)
            cnt_new_QA += 1

    # lo_do_QA_merged.extend(lo_do_QA_SR)
    return sort_and_check_lo_do_QA(lo_do_QA_merged)

def do_p_fn_rename_w_timestamp(lo_p_fn_flashcard, p_QA):
    # >lo_p_fn_SR< == a list of paths and >p_fn_QA< a directory path.
    # It renames every element >p_fn_flashcard< of >lo_p_fn_SR< by adding to the tail of the filename
    # a string >.YYYY-MM-DD< which is the actual date and keep the ext, which must be >.md<.
    # If a file with this name already exists add >.YYYY-MM-DD_mm< to it, where 'mm' are minutes.
    tz = zoneinfo.ZoneInfo("Europe/Berlin")
    date_str = datetime.now(tz).strftime("%Y-%m-%d_%H-%M-%S")
    for p_fn in lo_p_fn_flashcard:
        dir_path, fn = os.path.split(p_fn)
        name, ext = os.path.splitext(fn)
        if ext != '.md':
            continue
        new_fn = f"{name}.{date_str}{ext}"
        new_path = os.path.join(dir_path or p_QA, new_fn)
        # counter = 0
        # while os.path.exists(new_path):
        #     hrs  = datetime.now(tz).strftime("%H")
        #     mins = datetime.now(tz).strftime("%M")
        #     new_fn = f"{name}.{date_str}_{hrs}_{mins}{ext}"
        #     new_path = os.path.join(dir_path or p_fn_QA, new_fn)
        #     counter += 1
        #     if counter > 60:
        #         break
        os.rename(p_fn, new_path)


def b_filter_backup_flashcard_file(p_fn, s_extension):
    # Check if the tail of the filename is a string >.YYYY-MM-DD< or a string  >.YYYY-MM-DD_mm< and
    # if the filename ends with the ext >s_extension< and returns True if so.
    base, ext = os.path.splitext(p_fn)
    if ext != s_extension:
        return False
    b_result = rgx_flashcard_backup.search(base) is not None
    return b_result


def get_duplicates_by_key(lo_do_QA, key):
    # lo_do_QA: list of dicts
    # key:      the key you want to check for duplicates, e.g. "QA_ID"
    values = [d[key] for d in lo_do_QA]
    counts = Counter(values)
    return [d for d in lo_do_QA if counts[d[key]] > 1]

def sort_and_check_lo_do_QA(lo_do_QA_flashcard):
    # Check duplicates and sort by x["QA_ID"]
    if not lo_do_QA_flashcard:
        return None

    duplicates = {}
    for i, do in enumerate(lo_do_QA_flashcard):
        qa_id = do["QA_ID"]
        if qa_id in duplicates:
            duplicates[qa_id].append(i)
        else:
            duplicates[qa_id] = [i]

    # If duplicates found => Error and exit.
    for qa_id, indices in duplicates.items():
        if len(indices) > 1:
            print('>sort_and_check_lo_do_QA()<: ')
            print(f"Error: Duplicate QA_ID found.\n")
            break

    b_exit = False
    for qa_id, indices in duplicates.items():
        if len(indices) > 1:
            print('==========\n')
            b_exit = True
            # lo_do_QA_SR = get_duplicates_by_key(lo_do_QA_SR, "QA_ID")
            # lo_do_QA_SR.sort(key=lambda x: x["QA_ID"])

            QA_ID_old = ''
            for do_QA_flashcard in lo_do_QA_flashcard:
                if do_QA_flashcard["QA_ID"] == qa_id:
                    print(f'{do_QA_flashcard["QA_ID"]      = }')
                    print(f'{do_QA_flashcard["fn_QA_SR"]   = }')
                    print(f'{do_QA_flashcard["QA_d8_hash"] = }')
                    print('----------')

    if b_exit:
        print('==========\n', flush=True)
        sys.stdout.flush()
        exit('>sort_and_check_lo_do_QA()<: exit()')

    lo_do_QA_flashcard_sorted = sorted(lo_do_QA_flashcard, key=lambda x: (x["QA_deck"].lower()))
    return lo_do_QA_flashcard_sorted

def get_colorized_string(s_input):
    # <font color="#494429">(QA_ID_ABJFDY5I_04124ebe)</font>
    dark_color = "#494429"
    return f'<font color={dark_color}>' + s_input + '</font>'

def write_QA_SR_file(lo_do_QA_merged, p_QA = p_fn_QA, fn_QA_SR = fn_QA_SR):
    # Check in directory >p_fn_QA< if there is a file >fn_QA_SR<.
    # reads the file by calling >get_lo_do_QA_Spaced_Repetition(lo_p_fn_SR)< which returns a list of dicts >lo_do_QA_SR<.

    # The dictionary has the elements: 'path', 'fn_QA_SR', "QA_deck", "QA", "QA_Q", "QA_A", "QA_TimeStamp", "QA_zotero_hash", "QA_d8_hash", "QA_ID".
    #
    # Sorts the list of dictionaries >lo_do_QA_SR< using the dictionary element >"QA_ID"< as key.
    #
    # If >do_QA_flashcard< was modified (b_modified_lo_do_QA_flashcard == True):
    #    use >do_p_fn_rename_w_timestamp(lo_p_fn_SR, p_fn_QA)< to rename the existing version.
    #
    # Write every element in >lo_do_QA_SR< into the new file separating each element from the ather by adding an empty line.
    # Use the keys:  "QA_deck", "QA_Q", "QA_A", "QA_ID", "QA_TimeStamp"  in this order.

    # Compose the full path >p_fn< of flashcard file; create it if not existing.
    p_fn = os.path.join(p_QA, fn_QA_SR).replace('\\', '/')
    # Initialize flashcard file if it does not exist:
    print(f'>write_QA_SR_file()<: created: \n  {p_fn} ')
    if not os.path.exists(p_fn):
        with open(p_fn, 'w') as f:
            # f.write("#flashcards\n")
            f.write("")
            print(f'>write_QA_SR_file()<: created: \n  {p_fn}\n')

    # new QA-entries ?
    if not lo_do_QA_merged:   # no new QA-entries
        print(f'>write_QA_SR_file()<: \n  No new QA-entries')
        return None

    # Read the existing flashcard file
    lo_p_fn_SR = [p_fn]
    lo_do_QA_SR = get_lo_do_QA_SR(lo_p_fn_SR)

    # The function sorts the list >lo_do_QA_SR< of dictionaries >do_QA_flashcard< by the element of >do_QA_flashcard< with the key >"QA_ID"<.
    # If there are two or more dictionaries >do_QA_flashcard< with identical value in key >"QA_ID"< then print these values and exit.
    lo_do_QA_SR = sort_and_check_lo_do_QA(lo_do_QA_SR)

    # The function sorts the list >lo_do_QA_merged< of dictionaries >do_QA_flashcard< by the element of >do_QA_flashcard< with the key >"QA_ID"<.
    # If there are two or more dictionaries >do_QA_flashcard< with identical value in key >"QA_ID"< then print these values and exit.
    lo_do_QA_merged    = sort_and_check_lo_do_QA(lo_do_QA_merged)

    # For every element >do_QA_merged< in >lo_do_QA_merged<, which is a list of dictionaries, the program
    #   checks if it is present in >lo_do_QA_SR<. If not it appends this element to >lo_do_QA_SR<.
    b_modified_lo_do_QA_flashcard = False
    # There are QA
    for do_QA_merged in lo_do_QA_merged:
        if lo_do_QA_SR:
            if not any(d["QA_ID"] == do_QA_merged["QA_ID"] for d in lo_do_QA_SR):
                lo_do_QA_SR.append(do_QA_merged)
                b_modified_lo_do_QA_flashcard = True
        else:
            lo_do_QA_SR = []
            lo_do_QA_SR.append(do_QA_merged)
            b_modified_lo_do_QA_flashcard = True

    if b_modified_lo_do_QA_flashcard:
        do_p_fn_rename_w_timestamp(lo_p_fn_SR, p_QA)


    if lo_do_QA_SR:
        # lo_do_QA_SR.sort(key=lambda x: x["QA_ID"])
        lo_do_QA_flashcard_sorted = sort_and_check_lo_do_QA(lo_do_QA_SR)

        with open(p_fn, 'w', encoding='utf-8') as f:
            for do in lo_do_QA_flashcard_sorted:
                QA_ID = do.get("QA_ID", "")
                QA_Q  = do.get("QA_Q", "")
                QA_A  = do.get("QA_A", "")
                # print(QA_ID)
                lines = [
                    str(do.get("QA_deck", "")),
                    str(do.get("QA_Q", "")),
                    '?',
                    str(do.get("QA_A", "")),
                    QA_separator,
                    # get_colorized_string(str(do.get("fn_QA_SR", ""))),
                    # get_colorized_string(str(do.get("QA_ID", ""))),
                    str(do.get("fn_QA_SR", "")),
                    str(do.get("QA_ID", "")),
                    str(do.get("QA_TimeStamp", ""))
                ]
                SR_entry = '\n'.join(lines) + '\n\n'
                f.write(SR_entry)

def main():
    # gets all obsidian notes in >p_root< and makes flashcard - obsidian note (or anki connection).
    #
    # (Too complicated? Simply could have scanned all files for QA entries and written new QA-file?
    #  No! Because if QA in QA-file then there is a time stamp, that must be preserved.
    #  Therefor new QA-entries are appended to existing QA-file.)


    ini_path = 'tac.ini'
    load_config(ini_path)

    # find all obsidian notes in >p_root< or in >lo_subdir< of >p_root< (both are globals defined in >tac.ini<):
    lo_fn_note    = get_lo_fn_path_with_extension(p_root, lo_subdir, ext)

    # get >lo_do_QA_entry< == list of all QA-entries in *.md but not in QA-files (flashcard|anki| ...)
    #   n.b.: see composition of >do_QA< == Q&A-entry in the header of >tac.py<.
    lo_do_QA_entry = get_lo_QA_entry(lo_fn_note)

    # get FILE NAMES: >lo_fn_SR< == FILES that contain Q&A-entries in _Spaced Repetition_ format.
    # Only this/these files are used by the Spaced Repetition Plugin in Obsidian to define flashcards.
    lo_fn_SR = get_lo_fn_SR()  # List of _FILE names_

    # >lo_do_QA_SR< == list of dict of all Q&A in flashcard FILE.
    # This file contains all the hitherto known QA-entries. It will be extended by new QA-entries, if any.
    #   Every entry in the SR-flashcard file has the desk-tag, the QA-text and an ID (like : 'QA_ID_6CIRLAJZ_723fcae1').
    #   The plugin Space Repetition adds a time stamp (like: <!--SR:!2025-12-30,1,230-->)

    # read existing QA_SR entries in flashcard FILE
    lo_do_QA_SR = get_lo_do_QA_SR(lo_fn_SR)

    # Merge QA from *.md and from QA-file
    lo_do_QA_merged = get_lo_do_QA_merge(lo_do_QA_entry, lo_do_QA_SR)

    write_QA_SR_file(lo_do_QA_merged, p_QA = p_fn_QA, fn_QA_SR= fn_QA_SR)
    print("Total QA_flashcard entries:  ", len(lo_do_QA_SR))
    print("Total QA entries in md-notes:", len(lo_do_QA_entry))
    print("New   QA entries in md-notes:", cnt_new_QA)

if __name__ == "__main__":
    main()

# ToDo:
#  - Clean the regexs' in >load_config(ini_path)<
#  - remove the regexs' from >load_config(ini_path)<
#  - add anki support
