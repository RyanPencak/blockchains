import random
import hashlib

def sha256_2_string(string_to_hash):
    """ Returns the SHA256^2 hash of a given string input
    in hexadecimal format.

    Args:
        string_to_hash (str): Input string to hash twice

    Returns:
        str: Output of double-SHA256 encoded as hexadecimal string.
    """

    # (hint): feed binary data directly between the two SHA256 rounds
    hash1 = hashlib.sha256(string_to_hash.encode())
    hash1_dig = hash1.digest()
    hash2 = hashlib.sha256(hash1_dig)
    hash2_dig = hash2.hexdigest()

    return hash2_dig

def encode_as_str(list_to_encode, sep = "|"):
    """ Encodes a list as a string with given separator.

    Args:
        list_to_encode (:obj:`list` of :obj:`Object`): List of objects to convert to strings.
        sep (str, optional): Separator to join objects with.
    """
    return sep.join([str(x) for x in list_to_encode])

def nonempty_intersection(list1, list2):
    """ Returns true iff two lists have a nonempty intersection. """
    return len(list(set(list1) & set(list2))) > 0
