"""Guard: all shipped source must be valid under Python 3.11.

The lab VM runs Python 3.11 (Debian 12); development happens on Windows with
Python 3.12. Some 3.12 syntax is accepted locally but is a SyntaxError on the
VM, so it passes the whole Windows suite and only surfaces when kdetect is
imported on the VM (it bit us once: a multi-line expression inside an f-string
replacement field, PEP 701).

Two checks, because the two 3.12 features that catch people need different
detectors when running *on* 3.12:

* Grammar-level 3.12 additions (PEP 695 type params/aliases, `except*` shape,
  ...) are rejected by ``ast.parse(feature_version=(3, 11))``.
* f-string tokenization (PEP 701) is NOT downgraded by ``feature_version`` -- a
  multi-line replacement field still parses on 3.12. We catch it at the token
  level: a non-triple-quoted f-string whose FSTRING_START and FSTRING_END sit on
  different physical lines is invalid on 3.11.

Both run on 3.12 (dev) and are harmlessly inert where a construct can't exist;
on 3.11 the real parser is the backstop.
"""
import ast
import io
import tokenize
from pathlib import Path

import pytest

_ROOT = Path(__file__).resolve().parents[2]
_PY_FILES = sorted((_ROOT / "src").rglob("*.py")) + sorted((_ROOT / "tests").rglob("*.py"))
_IDS = [str(p.relative_to(_ROOT)) for p in _PY_FILES]


def _multiline_nontriple_fstrings(src: str) -> list[int]:
    """Start lines of non-triple-quoted f-strings that span >1 physical line.

    Uses the 3.12+ FSTRING_* tokens; returns [] on interpreters without them
    (there the construct cannot parse in the first place)."""
    start_tok = getattr(tokenize, "FSTRING_START", None)
    end_tok = getattr(tokenize, "FSTRING_END", None)
    if start_tok is None or end_tok is None:
        return []
    bad: list[int] = []
    open_line: int | None = None
    open_prefix = ""
    for tok in tokenize.generate_tokens(io.StringIO(src).readline):
        if tok.type == start_tok:
            open_line, open_prefix = tok.start[0], tok.string
        elif tok.type == end_tok and open_line is not None:
            triple = open_prefix.endswith('"""') or open_prefix.endswith("'''")
            if not triple and tok.end[0] != open_line:
                bad.append(open_line)
            open_line = None
    return bad


@pytest.mark.parametrize("path", _PY_FILES, ids=_IDS)
def test_grammar_is_python_311(path):
    ast.parse(path.read_text(encoding="utf-8"),
              filename=str(path), feature_version=(3, 11))


@pytest.mark.parametrize("path", _PY_FILES, ids=_IDS)
def test_no_multiline_fstring_fields(path):
    lines = _multiline_nontriple_fstrings(path.read_text(encoding="utf-8"))
    assert not lines, (
        f"{path.relative_to(_ROOT)} has a multi-line f-string (PEP 701, 3.12-only) "
        f"at line(s) {lines}; compute the value on its own line instead. "
        f"This is a SyntaxError on the Python 3.11 lab VM."
    )
