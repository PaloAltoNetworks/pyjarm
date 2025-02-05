import pytest
from collections import namedtuple
from typing import List

from jarm.constants import ALL, NO_1_3
from jarm.ciphers.ciphers import CipherSet, ALL_LIST, NO_1_3_LIST, CIPHERS

def test_cipherset_namedtuple():
    assert CipherSet._fields == ('name', 'values')
    cs = CipherSet('test', [b'\x00\x01'])
    assert cs.name == 'test'
    assert cs.values == [b'\x00\x01']

def test_all_list_content():
    assert isinstance(ALL_LIST, List)
    assert all(isinstance(item, bytes) for item in ALL_LIST)
    assert len(ALL_LIST) == 74
    assert b'\x00\x16' in ALL_LIST
    assert b'\x00\x05' in ALL_LIST

def test_no_1_3_list_content():
    assert isinstance(NO_1_3_LIST, List)
    assert all(isinstance(item, bytes) for item in NO_1_3_LIST)
    assert len(NO_1_3_LIST) == 69
    assert b'\x00\x16' in NO_1_3_LIST
    assert b'\x00\x05' in NO_1_3_LIST

def test_all_list_no_1_3_list_differences():
    all_set = set(ALL_LIST)
    no_1_3_set = set(NO_1_3_LIST)
    difference = all_set - no_1_3_set
    assert difference == {b'\x13\x02', b'\x13\x01', b'\x13\x05', b'\x13\x04', b'\x13\x03'}

def test_ciphers_dictionary():
    assert isinstance(CIPHERS, dict)
    assert len(CIPHERS) == 2
    assert ALL in CIPHERS
    assert NO_1_3 in CIPHERS

def test_ciphers_all():
    assert CIPHERS[ALL].name == ALL
    assert CIPHERS[ALL].values == ALL_LIST

def test_ciphers_no_1_3():
    assert CIPHERS[NO_1_3].name == NO_1_3
    assert CIPHERS[NO_1_3].values == NO_1_3_LIST

def test_cipherset_immutability():
    with pytest.raises(AttributeError):
        CIPHERS[ALL].name = "New Name"
    
    with pytest.raises(AttributeError):
        CIPHERS[ALL].values.append(b'\x00\x00')

def test_all_list_no_duplicates():
    assert len(ALL_LIST) == len(set(ALL_LIST))

def test_no_1_3_list_no_duplicates():
    assert len(NO_1_3_LIST) == len(set(NO_1_3_LIST))

def test_ciphers_keys_match_constants():
    assert set(CIPHERS.keys()) == {ALL, NO_1_3}

def test_cipherset_representation():
    cs = CipherSet('test', [b'\x00\x01'])
    assert repr(cs) == "CipherSet(name='test', values=[b'\\x00\\x01'])"
    assert str(cs) == "CipherSet(name='test', values=[b'\\x00\\x01'])"

def test_all_list_order():
    assert ALL_LIST[0] == b'\x00\x16'
    assert ALL_LIST[-1] == b'\x00\x05'

def test_no_1_3_list_order():
    assert NO_1_3_LIST[0] == b'\x00\x16'
    assert NO_1_3_LIST[-1] == b'\x00\x05'

def test_ciphers_values_type():
    for cipher_set in CIPHERS.values():
        assert isinstance(cipher_set, CipherSet)
        assert isinstance(cipher_set.name, str)
        assert isinstance(cipher_set.values, List)
        assert all(isinstance(value, bytes) for value in cipher_set.values)
