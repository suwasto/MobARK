"""M8 Phase C: the rebuild pipeline - applied edits -> resigned TEST APK.

``build_apk`` runs the five stages over a **fresh copy** of the pristine
apktool decode (the on-disk baseline never mutates; edits are DB diffs
overlaid onto the copy - owner decision, Aug 10 2026): apply → ``apktool b``
→ ``zipalign -f 4`` → ``apksigner sign`` → ``apksigner verify`` gate. Every
stage fails loudly: a :class:`RebuildError` carries the failing stage + the
specific reason (the tool's stderr tail) - never a silent broken APK
(decision 8).

Signing uses **one install-scoped TEST keystore** (decision 7): generated
once into ``data_dir`` (0600, with a random passphrase stored alongside in a
0600 file), reused for every rebuild. The output is a *test build* - the
filename always carries the ``-resigned-test-`` label (decision 9), and the
certificate is self-signed MASA, never the app's real identity.

All tools are subprocess-only (apktool / zipalign / apksigner / keytool are
Apache-2.0; keytool ships in the bundled JRE) - never imported.
"""
from __future__ import annotations

import hashlib
import os
import secrets
import shutil
from dataclasses import dataclass
from pathlib import Path

from app.analysis import apktool
from app.analysis.subprocess import resolve_binary, run_tool, tail
from app.config import settings


class RebuildError(Exception):
    """A pipeline step failed - carries the failing stage + specific reason
    (the RQ job writes both to ``builds.stage``/``builds.error``)."""

    def __init__(self, stage: str, message: str):
        super().__init__(message)
        self.stage = stage


@dataclass
class BuildArtifact:
    """A finished resigned TEST APK (metadata for the builds table)."""

    name: str
    path: Path
    sha256: str
    cert_sha256: str


_KEYSTORE_ALIAS = "masa-test"
_KEYSTORE_VALIDITY_DAYS = 10000


# ---- install-scoped test keystore ------------------------------------------


def keystore_path() -> Path:
    return settings.data_dir / "masa-test.jks"


def _passfile_path() -> Path:
    return settings.data_dir / "masa-test.jks.pass"


def _write_0600(path: Path, data: str | bytes) -> None:
    """Write a secret file with 0600 from the start (no write-then-chmod
    window where the contents are world-readable under a loose umask)."""
    path.parent.mkdir(parents=True, exist_ok=True)
    flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC
    with os.fdopen(os.open(path, flags, 0o600), "wb") as fh:
        fh.write(data if isinstance(data, bytes) else data.encode("utf-8"))


def _keytool_binary() -> str:
    """keytool ships in the bundled JRE (on PATH in the container); on the
    host it resolves from PATH too, unless MASA_KEYTOOL_CMD is set."""
    bin_path = resolve_binary("keytool", "keytool_cmd")
    if bin_path is None:
        raise RebuildError(
            "signing", "keytool not found - it ships with the JRE (set MASA_KEYTOOL_CMD)"
        )
    return bin_path


def ensure_keystore() -> tuple[Path, str]:
    """The install-scoped TEST keystore, generating it once on first use.

    Returns ``(path, passphrase)``. The passphrase is a fresh random token
    written next to the keystore (both 0600); subsequent calls reuse the
    stored pair - one keystore per MASA install, exactly like the BYOK key
    store precedent. Never the app's real identity: this is a self-signed
    dev keystore for resigned test builds only.
    """
    ks = keystore_path()
    pf = _passfile_path()
    if ks.is_file() and pf.is_file():
        return ks, pf.read_text().strip()
    if ks.is_file() and not pf.is_file():
        # Crash between keytool and the passfile write: the keystore's
        # passphrase is unknowable - remove it so the regeneration below
        # can run (keytool refuses to overwrite an existing keystore).
        ks.unlink(missing_ok=True)

    passphrase = secrets.token_urlsafe(24)
    cmd = [
        _keytool_binary(),
        "-genkeypair",
        "-keystore", str(ks),
        "-storepass", passphrase,
        "-keypass", passphrase,
        "-alias", _KEYSTORE_ALIAS,
        "-keyalg", "RSA",
        "-keysize", "2048",
        "-validity", str(_KEYSTORE_VALIDITY_DAYS),
        "-dname", "CN=MASA Test Signer, OU=MASA, O=MASA, C=US",
        "-storetype", "JKS",
        "-noprompt",
    ]
    result = run_tool(cmd, timeout=settings.rebuild_timeout_seconds)
    if result.returncode != 0:
        raise RebuildError(
            "signing",
            "keytool failed to create the test keystore: "
            f"{tail(result.stderr) or tail(result.stdout)}",
        )
    _write_0600(pf, passphrase + "\n")
    os.chmod(ks, 0o600)  # keytool created it - tighten perms after the fact
    return ks, passphrase


# ---- tool resolution --------------------------------------------------------


def _zipalign_binary() -> str:
    bin_path = resolve_binary(
        "zipalign", "zipalign_cmd", tools_subdir="build-tools/zipalign"
    )
    if bin_path is None:
        raise RebuildError(
            "zipping",
            "zipalign not found - it ships in the image's build-tools "
            "(set MASA_ZIPALIGN_CMD)",
        )
    return bin_path


def _apksigner_binary() -> str:
    bin_path = resolve_binary(
        "apksigner", "apksigner_cmd", tools_subdir="build-tools/apksigner"
    )
    if bin_path is None:
        raise RebuildError(
            "signing",
            "apksigner not found - it ships in the image's build-tools "
            "(set MASA_APKSIGNER_CMD)",
        )
    return bin_path


# ---- paths ------------------------------------------------------------------


def build_dir(scan_id: int, build_id: int) -> Path:
    """Per-build working copy of the decoded tree (deleted/rebuilt each run)."""
    return settings.data_dir / "work" / str(scan_id) / "builds" / str(build_id)


def artifact_dir(scan_id: int) -> Path:
    """Where signed test artifacts live (re-downloadable - decision 8)."""
    return settings.data_dir / "artifacts" / str(scan_id)


def artifact_stem(scan: object, build_id: int) -> str:
    """``<original-stem>-resigned-test-<build_id>`` - the persistent label
    (decision 9) travels in the filename AND the download attachment name."""
    filename = getattr(scan, "filename", "app.apk")
    stem = Path(filename).stem or "app"
    return f"{stem}-resigned-test-{build_id}"


# ---- edit overlay -----------------------------------------------------------


def apply_edits(tree_root: Path, edits: list) -> None:
    """Overlay applied edits onto the fresh copy of the decoded tree.

    Each edit's ``file_path`` is apktool-root-relative (smali/..., res/...,
    AndroidManifest.xml). Writes are traversal-guarded - an edit path that
    escapes the tree root is refused, never followed. A missing target file
    fails loudly (the edit references a file that is not in the decode).
    """
    root = tree_root.resolve()
    for edit in edits:
        target = (tree_root / edit.file_path).resolve()
        if not target.is_relative_to(root):
            raise RebuildError(
                "applying",
                f"edit {edit.id} escapes the decoded tree: {edit.file_path!r}",
            )
        if not target.is_file():
            raise RebuildError(
                "applying",
                f"edit {edit.id}: {edit.file_path!r} not found in the decoded tree",
            )
        target.write_text(edit.new_content, encoding="utf-8")


# ---- pipeline ---------------------------------------------------------------


def _run(cmd: list[str], stage: str) -> object:
    """Run one pipeline step; a timeout/non-zero exit becomes a loud
    RebuildError tagged with the failing stage (decision 8)."""
    result = run_tool(cmd, timeout=settings.rebuild_timeout_seconds)
    if result.timed_out:
        raise RebuildError(stage, f"{cmd[0]} timed out after {settings.rebuild_timeout_seconds}s")
    if result.returncode != 0:
        raise RebuildError(
            stage,
            f"{cmd[0]} exited {result.returncode}: {tail(result.stderr) or tail(result.stdout)}",
        )
    return result


def cert_sha256(apk: Path) -> str:
    """The signer certificate's SHA-256 digest of an APK (``apksigner verify
    --print-certs``). Used by the verify gate and Phase E's fingerprint
    comparison (resigned vs the original APK's cert must differ)."""
    result = _run(
        [_apksigner_binary(), "verify", "--print-certs", str(apk)], "signing"
    )
    for line in (result.stdout or "").splitlines():
        if "SHA-256 digest:" in line:
            digest = line.split("SHA-256 digest:", 1)[1].strip()
            if digest:
                return digest.lower()
    raise RebuildError(
        "signing",
        "apksigner verify passed but printed no certificate SHA-256 digest",
    )


def build_apk(scan, edits: list, build_id: int, on_stage=None) -> BuildArtifact:
    """Run the full rebuild pipeline for one build row.

    ``on_stage(stage)`` is called before each stage so the RQ job can persist
    ``builds.stage`` live (queued -> applying -> rebuilding -> zipping ->
    signing -> done). Raises :class:`RebuildError` on any failure; the job
    maps it to ``builds.status=failed`` + stage + error.
    """
    if not apktool.is_ready(scan.id):
        raise RebuildError(
            "applying", "apktool decode not ready - run the decode first"
        )

    # 1. applying - a fresh copy of the pristine decode, then the edit overlay
    if on_stage:
        on_stage("applying")
    src = apktool.decoded_root(scan.id)
    work = build_dir(scan.id, build_id)
    if work.exists():
        shutil.rmtree(work)
    shutil.copytree(src, work, symlinks=True)
    apply_edits(work, edits)

    # 2. rebuilding - apktool b back to an unsigned APK
    if on_stage:
        on_stage("rebuilding")
    artifacts = artifact_dir(scan.id)
    artifacts.mkdir(parents=True, exist_ok=True)
    unsigned = artifacts / f"{artifact_stem(scan, build_id)}-unsigned.apk"
    try:
        # apktool b is part of the rebuild pipeline - bound it by the rebuild
        # step deadline (the decode default is separate). The awkward-APK
        # contract (Phase E): a tree apktool cannot assemble back - e.g. an
        # edit that introduced invalid smali - is a loud 'rebuilding' failure
        # wrapped into the pipeline's stage-tagged error (never an untagged
        # ApktoolError escaping build_apk, never a silent broken APK).
        try:
            apktool.build(work, unsigned, timeout=settings.rebuild_timeout_seconds)
        except apktool.ApktoolError as exc:
            raise RebuildError("rebuilding", str(exc)) from exc

        # 3. zipping - zipalign runs BEFORE signing (v2+ signature blocks
        # preserve the alignment; signing afterwards is the correct order)
        if on_stage:
            on_stage("zipping")
        aligned = artifacts / f"{artifact_stem(scan, build_id)}-aligned.apk"
        _run([_zipalign_binary(), "-f", "4", str(unsigned), str(aligned)], "zipping")

        # 4. signing - the install-scoped TEST keystore
        if on_stage:
            on_stage("signing")
        ks, passphrase = ensure_keystore()
        signed = artifacts / f"{artifact_stem(scan, build_id)}.apk"
        _run(
            [
                _apksigner_binary(),
                "sign",
                "--ks", str(ks),
                "--ks-pass", f"pass:{passphrase}",
                "--key-pass", f"pass:{passphrase}",
                "--ks-key-alias", _KEYSTORE_ALIAS,
                "--out", str(signed),
                str(aligned),
            ],
            "signing",
        )

        # 5. verify gate - the artifact must pass apksigner verify (decision
        # 9 contract); a signed-but-invalid APK is a failed build
        digest = cert_sha256(signed)
        sha256 = _sha256_file(signed)
        return BuildArtifact(
            name=signed.name, path=signed, sha256=sha256, cert_sha256=digest
        )
    finally:
        # Intermediate unsigned/aligned copies are throwaway - only the
        # signed artifact is re-downloadable.
        unsigned.unlink(missing_ok=True)
        (artifacts / f"{artifact_stem(scan, build_id)}-aligned.apk").unlink(
            missing_ok=True
        )


def _sha256_file(path: Path) -> str:
    """Streaming SHA-256 - APKs can be 100+ MB; never read the whole file
    into memory for a hash."""
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()
