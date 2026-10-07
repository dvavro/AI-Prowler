"""
tests/e2e/test_str_line_replace_filetypes_e2e.py
====================================================
Deep-dive E2E coverage for str_replace_in_file and line_replace_in_file
across different file types and real-world edge cases these tools' own
docstrings specifically call out (CRLF preservation, encoding, backslash
auto-correction, ambiguous-match detection, dedent behavior).

WHY THIS SUITE EXISTS SEPARATELY FROM test_file_editing_e2e.py
------------------------------------------------------------------
test_file_editing_e2e.py already covers the basic happy path for both
tools on a single plain .txt file. This suite goes deeper on the SAME two
tools specifically, testing:
  1. Multiple realistic file types (.py, .json, .md, .html, .js, .css,
     .csv, .xml, .yaml) — confirming the edit lands correctly AND the
     surrounding syntax/structure of that file type is not corrupted
     (e.g. JSON still parses, XML is still well-formed after the edit).
  2. CRLF line-ending preservation — both tools' own source code reads
     the file in binary first specifically to detect and preserve the
     original line-ending convention (_read_text_preserving_endings /
     _apply_line_ending) rather than silently converting CRLF -> LF on
     write, which would show as a spurious full-file diff in git for
     every edited Windows-style file. This is directly testable and
     worth locking in as a permanent regression check.
  3. Unicode/emoji content preservation through an edit.
  4. Backslash auto-correction (str_replace_in_file's own documented
     "BACKSLASH FIX v7.0.1" — automatically retries de-doubled/re-doubled
     backslash variants when old_str's escaping doesn't match the file).
  5. Structural failure modes: ambiguous match (old_str appears 2+ times,
     must report line numbers and refuse), zero match (clear diagnostic),
     dry_run (no write occurs), dedent=True for Python indentation.
  6. Binary file rejection.

SAFETY MODEL
------------
One dedicated sandbox directory (_e2e_sandbox_multitype_editing), created
fresh and destroyed at the end. Every file used lives only there.

REQUIREMENTS
------------
No ANTHROPIC_API_KEY needed.

RUN
---
  run_e2e_mcp_tool.bat -k str_line_replace_filetypes
"""
from __future__ import annotations

import json
import os
import shutil
import sys
import xml.etree.ElementTree as ET
from pathlib import Path

import pytest

INSTALL_DIR = Path(os.environ.get("AI_PROWLER_SRC",
                                   r"C:\Program Files\AI-Prowler"))
WRITABLE_TEST_DIR = Path(os.environ.get(
    "AI_PROWLER_WRITABLE_TEST_DIR",
    r"C:\Users\david\AI-Prowler-V900_to_V910_work\AI-Prowler",
))
SANDBOX = WRITABLE_TEST_DIR / "_e2e_sandbox_multitype_editing"

if str(INSTALL_DIR) not in sys.path:
    sys.path.insert(0, str(INSTALL_DIR))


@pytest.fixture(scope="session")
def mcp_module():
    import ai_prowler_mcp as m
    return m


@pytest.fixture(scope="session", autouse=True)
def _sandbox_lifecycle():
    shutil.rmtree(SANDBOX, ignore_errors=True)
    SANDBOX.mkdir(parents=True, exist_ok=True)
    yield
    shutil.rmtree(SANDBOX, ignore_errors=True)


# ═══════════════════════════════════════════════════════════════════════
# str_replace_in_file across file types — each test writes a realistic
# file of that type, makes one surgical edit, then verifies BOTH that the
# edit landed correctly AND that the file's own syntax/structure is still
# intact (parses as valid JSON/XML, etc. where applicable).
# ═══════════════════════════════════════════════════════════════════════
@pytest.mark.mcp_tool_e2e
class TestStrReplaceAcrossFileTypes:

    def test_01_python_file(self, mcp_module):
        target = SANDBOX / "sample.py"
        target.write_text(
            'def greet(name):\n'
            '    message = "Hello, placeholder!"\n'
            '    return message\n',
            encoding="utf-8",
        )
        result = mcp_module.str_replace_in_file(
            filepath=str(target),
            old_str='message = "Hello, placeholder!"',
            new_str='message = f"Hello, {name}!"',
        )
        assert "✅" in result, f"str_replace_in_file failed on .py: {result}"
        content = target.read_text(encoding="utf-8")
        assert 'f"Hello, {name}!"' in content
        assert "def greet(name):" in content and "return message" in content, (
            "Surrounding Python code was corrupted by the edit"
        )
        compile(content, str(target), "exec")  # must still be valid Python

    def test_02_json_file_stays_valid(self, mcp_module):
        target = SANDBOX / "sample.json"
        target.write_text(
            json.dumps({"name": "placeholder", "count": 1}, indent=2),
            encoding="utf-8",
        )
        result = mcp_module.str_replace_in_file(
            filepath=str(target),
            old_str='"name": "placeholder"',
            new_str='"name": "ZTEST_updated"',
        )
        assert "✅" in result, f"str_replace_in_file failed on .json: {result}"
        data = json.loads(target.read_text(encoding="utf-8"))
        assert data["name"] == "ZTEST_updated"
        assert data["count"] == 1, "Unrelated JSON key was corrupted"

    def test_03_markdown_file(self, mcp_module):
        target = SANDBOX / "sample.md"
        target.write_text(
            "# Title\n\n"
            "## Placeholder Section\n\n"
            "Some body text that must survive.\n",
            encoding="utf-8",
        )
        result = mcp_module.str_replace_in_file(
            filepath=str(target),
            old_str="## Placeholder Section",
            new_str="## Updated Section",
        )
        assert "✅" in result, f"str_replace_in_file failed on .md: {result}"
        content = target.read_text(encoding="utf-8")
        assert "## Updated Section" in content
        assert "# Title" in content and "Some body text that must survive." in content

    def test_04_html_file_nested_tags(self, mcp_module):
        target = SANDBOX / "sample.html"
        target.write_text(
            "<html><body>\n"
            "  <div class=\"outer\"><span>placeholder text</span></div>\n"
            "</body></html>\n",
            encoding="utf-8",
        )
        result = mcp_module.str_replace_in_file(
            filepath=str(target),
            old_str="<span>placeholder text</span>",
            new_str="<span>updated text</span>",
        )
        assert "✅" in result, f"str_replace_in_file failed on .html: {result}"
        content = target.read_text(encoding="utf-8")
        assert "<span>updated text</span>" in content
        assert '<div class="outer">' in content, "Enclosing tag was corrupted"

    def test_05_javascript_file(self, mcp_module):
        target = SANDBOX / "sample.js"
        target.write_text(
            "function greet(name) {\n"
            "  const msg = `Hello, placeholder!`;\n"
            "  return msg;\n"
            "}\n",
            encoding="utf-8",
        )
        result = mcp_module.str_replace_in_file(
            filepath=str(target),
            old_str="const msg = `Hello, placeholder!`;",
            new_str="const msg = `Hello, ${name}!`;",
        )
        assert "✅" in result, f"str_replace_in_file failed on .js: {result}"
        content = target.read_text(encoding="utf-8")
        assert "`Hello, ${name}!`" in content
        assert "function greet(name) {" in content and "return msg;" in content

    def test_06_css_file(self, mcp_module):
        target = SANDBOX / "sample.css"
        target.write_text(
            ".button {\n"
            "  color: placeholder;\n"
            "  padding: 10px;\n"
            "}\n",
            encoding="utf-8",
        )
        result = mcp_module.str_replace_in_file(
            filepath=str(target),
            old_str="color: placeholder;",
            new_str="color: #336699;",
        )
        assert "✅" in result, f"str_replace_in_file failed on .css: {result}"
        content = target.read_text(encoding="utf-8")
        assert "color: #336699;" in content
        assert "padding: 10px;" in content, "Unrelated CSS property was corrupted"

    def test_07_csv_file_column_count_preserved(self, mcp_module):
        target = SANDBOX / "sample.csv"
        target.write_text(
            "name,city,amount\n"
            "placeholder,Daytona Beach,125.00\n"
            "Maria Gonzalez,Daytona Beach,150.00\n",
            encoding="utf-8",
        )
        result = mcp_module.str_replace_in_file(
            filepath=str(target),
            old_str="placeholder,Daytona Beach,125.00",
            new_str="ZTEST Customer,Daytona Beach,125.00",
        )
        assert "✅" in result, f"str_replace_in_file failed on .csv: {result}"
        content = target.read_text(encoding="utf-8")
        lines = content.strip().splitlines()
        assert len(lines) == 3, "CSV row count changed unexpectedly"
        for line in lines:
            assert line.count(",") == 2, (
                f"CSV column count corrupted on line: {line!r}"
            )
        assert "ZTEST Customer,Daytona Beach,125.00" in content
        assert "Maria Gonzalez,Daytona Beach,150.00" in content

    def test_08_xml_file_stays_well_formed(self, mcp_module):
        target = SANDBOX / "sample.xml"
        target.write_text(
            '<?xml version="1.0"?>\n'
            "<root>\n"
            "  <item id=\"1\">placeholder</item>\n"
            "  <item id=\"2\">keep me</item>\n"
            "</root>\n",
            encoding="utf-8",
        )
        result = mcp_module.str_replace_in_file(
            filepath=str(target),
            old_str='<item id="1">placeholder</item>',
            new_str='<item id="1">updated</item>',
        )
        assert "✅" in result, f"str_replace_in_file failed on .xml: {result}"
        content = target.read_text(encoding="utf-8")
        root = ET.fromstring(content)  # raises if not well-formed
        items = root.findall("item")
        assert items[0].text == "updated"
        assert items[1].text == "keep me", "Unrelated XML element was corrupted"

    def test_09_yaml_file_indentation_preserved(self, mcp_module):
        """YAML is indentation-sensitive — the edit must not shift any
        other line's leading whitespace even by one column."""
        target = SANDBOX / "sample.yaml"
        target.write_text(
            "service:\n"
            "  name: placeholder\n"
            "  settings:\n"
            "    port: 8080\n"
            "    debug: false\n",
            encoding="utf-8",
        )
        result = mcp_module.str_replace_in_file(
            filepath=str(target),
            old_str="  name: placeholder",
            new_str="  name: ztest-service",
        )
        assert "✅" in result, f"str_replace_in_file failed on .yaml: {result}"
        content = target.read_text(encoding="utf-8")
        assert "  name: ztest-service" in content
        assert "    port: 8080" in content and "    debug: false" in content, (
            "YAML indentation of unrelated lines was shifted by the edit"
        )

    def test_10_unicode_and_emoji_content_preserved(self, mcp_module):
        target = SANDBOX / "sample_unicode.txt"
        target.write_text(
            "Customer: José García 🏠\n"
            "Notes: PLACEHOLDER — café visit at 3pm ☕\n"
            "Status: ✅ Confirmed\n",
            encoding="utf-8",
        )
        result = mcp_module.str_replace_in_file(
            filepath=str(target),
            old_str="Notes: PLACEHOLDER — café visit at 3pm ☕",
            new_str="Notes: Updated — café visit moved to 4pm ☕",
        )
        assert "✅" in result, f"str_replace_in_file failed on unicode content: {result}"
        content = target.read_text(encoding="utf-8")
        assert "Updated — café visit moved to 4pm ☕" in content
        assert "José García 🏠" in content, "Unrelated unicode content was corrupted"
        assert "✅ Confirmed" in content

    def test_11_crlf_line_endings_preserved(self, mcp_module):
        """str_replace_in_file's own source specifically reads files in
        binary first to detect CRLF vs LF and re-applies the ORIGINAL
        convention on write — confirm this actually happens, since a
        silent CRLF->LF conversion would show as a spurious full-file
        diff for every Windows-style file edited."""
        target = SANDBOX / "sample_crlf.txt"
        target.write_bytes(
            b"line one\r\n"
            b"PLACEHOLDER line\r\n"
            b"line three\r\n"
        )
        result = mcp_module.str_replace_in_file(
            filepath=str(target),
            old_str="PLACEHOLDER line",
            new_str="updated line",
        )
        assert "✅" in result, f"str_replace_in_file failed on CRLF file: {result}"
        raw = target.read_bytes()
        assert b"\r\n" in raw, (
            "REGRESSION: CRLF line endings were not preserved after the edit"
        )
        crlf_count = raw.count(b"\r\n")
        assert crlf_count == 3, (
            f"Expected all 3 lines to still use CRLF, found "
            f"{crlf_count} CRLF occurrences"
        )
        assert b"updated line" in raw
        assert b"line one" in raw and b"line three" in raw

    def test_12_dedent_true_reindents_python_correctly(self, mcp_module):
        target = SANDBOX / "sample_dedent.py"
        target.write_text(
            "class Foo:\n"
            "    def bar(self):\n"
            "        old_value = 1\n"
            "        return old_value\n",
            encoding="utf-8",
        )
        # Passed with NO leading indentation, relying on dedent=True to
        # re-indent to match old_str's own first-line indent (8 spaces).
        result = mcp_module.str_replace_in_file(
            filepath=str(target),
            old_str="        old_value = 1\n        return old_value",
            new_str="new_value = 2\nreturn new_value",
            dedent=True,
        )
        assert "✅" in result, f"str_replace_in_file with dedent failed: {result}"
        content = target.read_text(encoding="utf-8")
        assert "        new_value = 2" in content, (
            f"dedent=True did not correctly re-indent to 8 spaces: {content!r}"
        )
        assert "        return new_value" in content
        compile(content, str(target), "exec")  # must still be valid Python

    def test_13_backslash_auto_correction(self, mcp_module):
        """str_replace_in_file's own documented 'BACKSLASH FIX v7.0.1' —
        automatically retries de-doubled/re-doubled backslash variants
        when old_str's escaping doesn't match the file verbatim."""
        target = SANDBOX / "sample_paths.py"
        target.write_text(
            'PATH = "C:\\\\Users\\\\test\\\\file.txt"\n',  # C:\Users\test\file.txt on disk
            encoding="utf-8",
        )
        # Deliberately pass old_str with the WRONG escape level (single
        # backslashes instead of the doubled ones actually in the file) —
        # the tool should auto-correct rather than fail outright.
        result = mcp_module.str_replace_in_file(
            filepath=str(target),
            old_str='PATH = "C:\\Users\\test\\file.txt"',
            new_str='PATH = "C:\\Users\\test\\updated.txt"',
        )
        assert "✅" in result, (
            f"str_replace_in_file's backslash auto-correction did not "
            f"succeed on a mismatched escape level: {result}"
        )
        content = target.read_text(encoding="utf-8")
        assert "updated.txt" in content

    def test_14_ambiguous_match_reports_line_numbers_and_refuses(self, mcp_module):
        target = SANDBOX / "sample_ambiguous.txt"
        target.write_text(
            "first PLACEHOLDER here\n"
            "second PLACEHOLDER here\n",
            encoding="utf-8",
        )
        result = mcp_module.str_replace_in_file(
            filepath=str(target), old_str="PLACEHOLDER", new_str="UPDATED")
        assert "⚠️" in result or "❌" in result, (
            f"Expected a refusal for an ambiguous (2x) match: {result}"
        )
        # Should report BOTH line numbers so the caller can disambiguate.
        assert "1" in result and "2" in result, (
            f"Expected both matching line numbers to be reported: {result}"
        )
        # File must be unchanged.
        assert target.read_text(encoding="utf-8") == (
            "first PLACEHOLDER here\nsecond PLACEHOLDER here\n"
        )

    def test_15_zero_match_gives_clear_diagnostic(self, mcp_module):
        target = SANDBOX / "sample_zero_match.txt"
        target.write_text("actual content here\n", encoding="utf-8")
        result = mcp_module.str_replace_in_file(
            filepath=str(target),
            old_str="this text does not exist anywhere",
            new_str="replacement",
        )
        assert "⚠️" in result or "❌" in result or "not found" in result.lower(), (
            f"Expected a clear zero-match diagnostic: {result}"
        )
        assert target.read_text(encoding="utf-8") == "actual content here\n"

    def test_16_dry_run_makes_no_changes(self, mcp_module):
        target = SANDBOX / "sample_dryrun.txt"
        original = "keep this PLACEHOLDER exactly\n"
        target.write_text(original, encoding="utf-8")
        result = mcp_module.str_replace_in_file(
            filepath=str(target),
            old_str="PLACEHOLDER",
            new_str="CHANGED",
            dry_run=True,
        )
        assert "DRY RUN" in result or "dry run" in result.lower(), (
            f"Expected dry_run output to be clearly labeled: {result}"
        )
        assert target.read_text(encoding="utf-8") == original, (
            "dry_run=True must never actually modify the file"
        )

    def test_17_binary_file_rejected(self, mcp_module):
        target = SANDBOX / "sample_binary.dat"
        target.write_bytes(bytes(range(256)))  # guaranteed binary-looking content
        result = mcp_module.str_replace_in_file(
            filepath=str(target), old_str="anything", new_str="anything2")
        assert "binary" in result.lower(), (
            f"Expected a clean binary-file rejection: {result}"
        )


# ═══════════════════════════════════════════════════════════════════════
# line_replace_in_file across file types — line-number-based replacement,
# same file-type-diversity and structural-integrity approach as above.
# ═══════════════════════════════════════════════════════════════════════
@pytest.mark.mcp_tool_e2e
class TestLineReplaceAcrossFileTypes:

    def test_01_python_multiline_range(self, mcp_module):
        target = SANDBOX / "lr_sample.py"
        target.write_text(
            "def foo():\n"       # line 1
            "    x = 1\n"        # line 2
            "    y = 2\n"        # line 3
            "    return x + y\n",  # line 4
            encoding="utf-8",
        )
        # Replace lines 2-3 (2 lines) with 3 new lines — confirms the
        # tool handles a line-count CHANGE correctly, not just 1-for-1.
        result = mcp_module.line_replace_in_file(
            filepath=str(target),
            start_line=2, end_line=3,
            new_content="    x = 10\n    y = 20\n    z = 30",
        )
        assert "✅" in result, f"line_replace_in_file failed on .py: {result}"
        content = target.read_text(encoding="utf-8")
        assert "x = 10" in content and "y = 20" in content and "z = 30" in content
        assert "def foo():" in content and "return x + y" in content
        compile(content, str(target), "exec")

    def test_02_json_file_stays_valid(self, mcp_module):
        target = SANDBOX / "lr_sample.json"
        original = json.dumps(
            {"a": 1, "b": "placeholder", "c": 3}, indent=2)
        target.write_text(original, encoding="utf-8")
        lines = original.splitlines()
        b_line_num = next(
            i + 1 for i, l in enumerate(lines) if '"b"' in l)
        result = mcp_module.line_replace_in_file(
            filepath=str(target),
            start_line=b_line_num, end_line=b_line_num,
            new_content='  "b": "ZTEST_updated",',
        )
        assert "✅" in result, f"line_replace_in_file failed on .json: {result}"
        data = json.loads(target.read_text(encoding="utf-8"))
        assert data["b"] == "ZTEST_updated"
        assert data["a"] == 1 and data["c"] == 3

    def test_03_single_line_replacement(self, mcp_module):
        target = SANDBOX / "lr_single.txt"
        target.write_text("line1\nline2\nline3\n", encoding="utf-8")
        result = mcp_module.line_replace_in_file(
            filepath=str(target), start_line=2, end_line=2,
            new_content="LINE2_REPLACED")
        assert "✅" in result, f"line_replace_in_file failed: {result}"
        content = target.read_text(encoding="utf-8")
        assert content == "line1\nLINE2_REPLACED\nline3\n"

    def test_04_crlf_line_endings_preserved(self, mcp_module):
        target = SANDBOX / "lr_crlf.txt"
        target.write_bytes(b"alpha\r\nbeta\r\ngamma\r\n")
        result = mcp_module.line_replace_in_file(
            filepath=str(target), start_line=2, end_line=2,
            new_content="BETA_UPDATED")
        assert "✅" in result, f"line_replace_in_file failed on CRLF file: {result}"
        raw = target.read_bytes()
        crlf_count = raw.count(b"\r\n")
        assert crlf_count == 3, (
            f"Expected CRLF preserved on all 3 lines, "
            f"found {crlf_count} occurrences: {raw!r}"
        )
        assert b"BETA_UPDATED" in raw

    def test_05_dedent_true_reindents_correctly(self, mcp_module):
        target = SANDBOX / "lr_dedent.py"
        target.write_text(
            "class Foo:\n"
            "    def bar(self):\n"
            "        old_line = 1\n"
            "        return old_line\n",
            encoding="utf-8",
        )
        result = mcp_module.line_replace_in_file(
            filepath=str(target), start_line=3, end_line=4,
            new_content="new_line = 2\nreturn new_line",
            dedent=True,
        )
        assert "✅" in result, f"line_replace_in_file with dedent failed: {result}"
        content = target.read_text(encoding="utf-8")
        assert "        new_line = 2" in content, (
            f"dedent=True did not re-indent to match start_line's indent: {content!r}"
        )
        assert "        return new_line" in content
        compile(content, str(target), "exec")

    def test_06_out_of_range_line_rejected(self, mcp_module):
        target = SANDBOX / "lr_short.txt"
        target.write_text("only one line\n", encoding="utf-8")
        result = mcp_module.line_replace_in_file(
            filepath=str(target), start_line=5, end_line=5,
            new_content="won't be written")
        assert "⚠️" in result or "❌" in result or "beyond end of file" in result.lower(), (
            f"Expected a clean out-of-range rejection: {result}"
        )
        assert target.read_text(encoding="utf-8") == "only one line\n"

    def test_07_dry_run_makes_no_changes(self, mcp_module):
        target = SANDBOX / "lr_dryrun.txt"
        original = "keep\nthis\nexactly\n"
        target.write_text(original, encoding="utf-8")
        result = mcp_module.line_replace_in_file(
            filepath=str(target), start_line=2, end_line=2,
            new_content="CHANGED", dry_run=True,
        )
        assert "dry run" in result.lower() or "DRY RUN" in result, (
            f"Expected dry_run output to be clearly labeled: {result}"
        )
        assert target.read_text(encoding="utf-8") == original, (
            "dry_run=True must never actually modify the file"
        )

    def test_08_expand_range_more_lines_than_removed(self, mcp_module):
        """Replacing a SMALLER range with MORE lines than were removed —
        confirms the splice logic handles a net line-count INCREASE."""
        target = SANDBOX / "lr_expand.txt"
        target.write_text("A\nB\nC\nD\n", encoding="utf-8")
        result = mcp_module.line_replace_in_file(
            filepath=str(target), start_line=2, end_line=2,
            new_content="B1\nB2\nB3",
        )
        assert "✅" in result, f"line_replace_in_file expand-range failed: {result}"
        content = target.read_text(encoding="utf-8")
        assert content == "A\nB1\nB2\nB3\nC\nD\n"

    def test_09_shrink_range_fewer_lines_than_removed(self, mcp_module):
        """The inverse — replacing a LARGER range with FEWER lines,
        confirming a net line-count DECREASE also splices correctly."""
        target = SANDBOX / "lr_shrink.txt"
        target.write_text("A\nB\nC\nD\nE\n", encoding="utf-8")
        result = mcp_module.line_replace_in_file(
            filepath=str(target), start_line=2, end_line=4,
            new_content="MERGED",
        )
        assert "✅" in result, f"line_replace_in_file shrink-range failed: {result}"
        content = target.read_text(encoding="utf-8")
        assert content == "A\nMERGED\nE\n"
