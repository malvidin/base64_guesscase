#!/usr/bin/env python3
import base64
import itertools
import re


# Attempts to decode base64 encoded strings with flattened case,
# either all uppercase, all lowercase, or any mix of the two.
# Assumes that the output only has printable ASCII characters.

def guesscase(input_bytes, validation_regex=re.compile(b"^[ \t\r\n\x20-\x7E]{1,3}$"), max_length=60):
    """

    :param input_bytes: Bytes of likely Base64 data with suspected modified case
    :param validation_regex:  Compiled regex for ASCII characters
    :param max_length: Truncate to this length so the number of permutations is manageable.
    :return: list of list of bytes, or a message string if the decoding fails validation.
    """
    # Each base64 bytes chunk must have 4 characters, so split it on those boundaries

    max_length = 4 * (max_length // 4)
    input_bytes = input_bytes[:max_length]
    n = 4
    modlen = len(input_bytes) % n
    modleninv = 4 - modlen
    assert modlen == 0, ('input length is not a multiple of 4, it has {} extra characters or is missing {} characters'
                         .format(modlen, modleninv))
    splitstring = slice_iterator(input_bytes, n)
    possible = []
    for s in splitstring:
        all_case = []
        for i in range(0, len(s)):
            bothcase = {s[i:i + 1], s[i:i + 1].swapcase()}
            all_case.append(bothcase)
        valid = []
        for chunk in [b''.join(y for y in x) for x in itertools.product(*all_case)]:
            decoded = base64.b64decode(chunk)
            if validation_regex.match(decoded):
                valid.append(decoded)
        if len(valid) > 0:
            possible.append(valid)
        else:
            return "No ASCII matches returned for at least one block of encoded text"
    return possible


def slice_iterator(inputstring, n):
    for i in range(0, len(inputstring), n):
        splitstring = inputstring[i:i + n]
        yield splitstring


def _re_scorer(input_bytes, byte_regex):
    """
    Maximum score is 100, when the entire string matches the regular expression.

    :param input_bytes:
    :return: integer score between 0 and 100
    """
    if type(byte_regex) is bytes:
        byte_regex = re.compile(byte_regex)
    elif type(byte_regex.pattern) is not bytes:
        byte_regex = re.compile(bytes(byte_regex.pattern))
    byte_len = len(input_bytes)
    match_len = 0
    if byte_len < 4:
        return 0
    else:
        match_list = byte_regex.findall(input_bytes)
        for match in match_list:
            match_len += len(match)
        re_score = int(100 * match_len / byte_len)
        return re_score


def upper_scorer(input_bytes):
    return _re_scorer(input_bytes,
                      re.compile(b'[A-Z ]+'))


def lower_scorer(input_bytes):
    return _re_scorer(input_bytes,
                      re.compile(b'[a-z ]+'))


def sentencecase_scorer(input_bytes):
    return _re_scorer(input_bytes,
                      re.compile(b'[ ]{0,5}\b[A-Za-z][a-z]\b{0,50}[ ]{0,5}'))


def url_scorer(input_bytes):
    count_punc = (input_bytes.count(b'.') + input_bytes.count(b'/'))
    score = count_punc + _re_scorer(input_bytes,
                       re.compile(b'(?P<basic_url>(?:https?://|www[.])[-a-z.]{3,200}(?:[/#?][-/%_A-Za-z0-9]{0,5000})?)'))
    return min(100, int(score))


def print_possible_decoding(possible_list, scorers=None, max_len=45, max_count=20):
    if scorers is None:
        scorers = [lambda input_bytes: 0]
    scorer_count = len(scorers)
    joined_dict = {}
    list_subset = possible_list[:max_len]
    for x in itertools.product(*list_subset):
        x_key = b''.join(y for y in x)
        x_score = 0
        for scorer in scorers:
            x_score += scorer(x_key)
        joined_dict[x_key] = int(x_score / scorer_count)

    # Sort based on scoring
    sorted_list = []
    for x_key, x_score in joined_dict.items():
        sorted_list.append((x_key, x_score,))

    sorted_list.sort(key=lambda t: t[1], reverse=True)
    for x_key, x_score in sorted_list[:max_count]:
        print("The following scored {score} out of 100".format(score=x_score))
        print(x_key)
    return sorted_list


def base64_substrings(inputbytes, split=76, padding_chars=b'='):
    # Use split for the maximum number of bytes of Base64 encoded data on a single line
    split_half = split // 2 if split else 1
    input_len = len(inputbytes)
    assert input_len >= 6
    from base64 import b64encode
    null = b'\x00'
    out_list = []
    for i in range(3):
        j = i if i is 0 else i + 1
        padded_bytes = null * i + inputbytes
        be = b64encode(padded_bytes)
        # Trim trailing characters that might be impacted by padding, and leading characters from null
        be = be[j:]
        if be.endswith(padding_chars):
            if be.endswith(padding_chars*2):
                be = be[:-3]
            else:
                be = be[:-2]
        encoded_len = len(be)
        if split and split_half <= encoded_len:
            chunk_count = - ( - encoded_len // split_half)  # ceiling division without import math
            chunk_len = - ( - encoded_len // chunk_count)  # ceiling division without import math
            tmp_list = [ be[k:k+chunk_len] for k in range(0, encoded_len, chunk_len) ]
            out_list.extend(tmp_list)
        else:
            out_list.append(be)
    return out_list


if __name__ == "__main__":
    guess_list = guesscase(b'AHR0CHM6LY9NAXRODWIUY29TL21HBHZPZGLUL2JHC2U2NF9NDWVZC2NHC2U=')
    if type(guess_list) is list:
        print_possible_decoding(guess_list, scorers=[url_scorer, lower_scorer])
