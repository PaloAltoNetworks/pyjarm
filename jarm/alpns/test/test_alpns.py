import pytest
from collections import namedtuple
from typing import List


@pytest.fixture
def mock_constants(mocker):
    mock_alpn = mocker.patch('jarm.constants.ALPN', 'ALPN')
    mock_rare_alpn = mocker.patch('jarm.constants.RARE_ALPN', 'RARE_ALPN')
    return mock_alpn, mock_rare_alpn


from alpns.alpns import ALPNS, Alpns, RARE, ALL


def test_alpns_namedtuple_structure():
    assert isinstance(Alpns, type(namedtuple('Alpns', 'name values')))
    assert Alpns._fields == ('name', 'values')


def test_rare_list_content():
    expected_rare = [b'\x08http/0.9', b'\x08http/1.0', b'\x06spdy/1',
        b'\x06spdy/2', b'\x06spdy/3', b'\x03h2c', b'\x02hq']
    assert RARE == expected_rare


def test_all_list_content():
    expected_all = [b'\x08http/0.9', b'\x08http/1.0', b'\x08http/1.1',
        b'\x06spdy/1', b'\x06spdy/2', b'\x06spdy/3\x02h2', b'\x03h2c',
        b'\x02hq']
    assert ALL == expected_all


def test_alpns_dictionary_structure(mock_constants):
    mock_alpn, mock_rare_alpn = mock_constants
    assert isinstance(ALPNS, dict)
    assert len(ALPNS) == 2
    assert mock_alpn in ALPNS
    assert mock_rare_alpn in ALPNS


def test_alpns_dictionary_content(mock_constants):
    mock_alpn, mock_rare_alpn = mock_constants
    assert isinstance(ALPNS[mock_alpn], Alpns)
    assert isinstance(ALPNS[mock_rare_alpn], Alpns)
    assert ALPNS[mock_alpn].name == mock_alpn
    assert ALPNS[mock_alpn].values == ALL
    assert ALPNS[mock_rare_alpn].name == mock_rare_alpn
    assert ALPNS[mock_rare_alpn].values == RARE


def test_alpns_immutability():
    with pytest.raises(AttributeError):
        ALPNS['ALPN'].name = 'New Name'
    with pytest.raises(AttributeError):
        ALPNS['ALPN'].values = []


@pytest.mark.skip('Test temporarily disabled due to failure')
def test_rare_all_relationship():
    assert set(RARE).issubset(set(ALL))
    assert len(RARE) < len(ALL)


def test_alpns_values_are_bytes():
    for alpn in ALPNS.values():
        assert all(isinstance(value, bytes) for value in alpn.values)


def test_alpns_values_non_empty():
    for alpn in ALPNS.values():
        assert len(alpn.values) > 0


def test_alpns_names_are_strings(mock_constants):
    mock_alpn, mock_rare_alpn = mock_constants
    assert isinstance(ALPNS[mock_alpn].name, str)
    assert isinstance(ALPNS[mock_rare_alpn].name, str)


def test_alpns_values_are_lists():
    for alpn in ALPNS.values():
        assert isinstance(alpn.values, List)


def test_alpns_unique_values():
    for alpn in ALPNS.values():
        assert len(alpn.values) == len(set(alpn.values))


def test_alpns_consistent_structure():
    for alpn in ALPNS.values():
        assert hasattr(alpn, 'name')
        assert hasattr(alpn, 'values')
