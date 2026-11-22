"""yaml_min — the guaranteed-fallback parser behind scope files."""

import pytest

from cyberagent.yaml_min import YamlMinError, loads, loads_min


def test_scalars():
    assert loads_min("a: 1") == {"a": 1}
    assert loads_min("a: -7") == {"a": -7}
    assert loads_min("a: 2.5") == {"a": 2.5}
    assert loads_min("a: true") == {"a": True}
    assert loads_min("a: false") == {"a": False}
    assert loads_min("a: null") == {"a": None}
    assert loads_min("a: ~") == {"a": None}
    assert loads_min("a: hello world") == {"a": "hello world"}
    assert loads_min("a: 'quoted: value'") == {"a": "quoted: value"}
    assert loads_min("a: 'it''s'") == {"a": "it's"}
    assert loads_min('a: "dq"') == {"a": "dq"}


def test_comments_and_blanks():
    text = "# top\n\na: 1  # trailing\n# gone\nb: 2\n"
    assert loads_min(text) == {"a": 1, "b": 2}


def test_nested_mappings():
    assert loads_min("a:\n  b:\n    c: 1\n  d: 2\n") == {"a": {"b": {"c": 1}, "d": 2}}


def test_block_lists():
    assert loads_min("a:\n  - 1\n  - 2\n") == {"a": [1, 2]}
    assert loads_min("a:\n  - x\n  - 'y'\n") == {"a": ["x", "y"]}


def test_list_of_mappings_with_inline_start():
    text = (
        "scope:\n"
        "  - host: a\n"
        "    reason: r\n"
        "  - host: b\n"
        "    reason: s\n"
    )
    assert loads_min(text) == {
        "scope": [{"host": "a", "reason": "r"}, {"host": "b", "reason": "s"}]
    }


def test_list_item_as_pure_block():
    assert loads_min("a:\n  -\n    b: 1\n    c: 2\n") == {"a": [{"b": 1, "c": 2}]}


def test_scope_file_shape():
    text = (
        "scope:\n"
        "  - host: 127.0.0.1\n"
        "    reason: local dev\n"
        "    ports:\n"
        "      - 22\n"
        "      - 8000-8008\n"
        "    owner: numsalam\n"
        "    expires: 2027-12-31\n"
    )
    entry = loads_min(text)["scope"][0]
    assert entry["host"] == "127.0.0.1"
    assert entry["ports"] == [22, "8000-8008"]
    assert entry["owner"] == "numsalam"
    assert entry["expires"] == "2027-12-31"


def test_empty_and_comment_only():
    assert loads_min("") is None
    assert loads_min("# only a comment\n") is None


@pytest.mark.parametrize(
    "text",
    [
        "\ta: 1",                    # tab indentation
        "  a: 1",                    # top-level indentation
        "a: [1, 2]",                 # flow style
        "a: 1\na: 2",                # duplicate key
        'a: "unterminated',          # unterminated quote
        "a: 1\n- b",                 # list item inside a mapping
        "a:\n  - b: 1\n  c: 2",      # mixed list/map at one indent
        "a:\n  - b: 1\n    b: 2",    # duplicate key inside a list item
    ],
)
def test_out_of_subset_fails_closed(text):
    with pytest.raises(YamlMinError):
        loads_min(text)


def test_loads_agrees_on_simple_docs():
    text = "scope:\n  - host: a\n    reason: r\n    ports:\n      - 22\n"
    assert loads(text) == loads_min(text)
    assert loads("a:\n  - 1\n  - 2\n") == {"a": [1, 2]}
