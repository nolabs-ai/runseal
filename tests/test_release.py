"""Exercise release publication ordering without contacting GitHub."""

import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest


FAKE_GH = r'''#!/usr/bin/env python3
import hashlib, json, os, pathlib, shutil, sys
root = pathlib.Path(os.environ["RELEASE_TEST_ROOT"])
args = sys.argv[1:]
with (root / "calls").open("a") as log:
    log.write(json.dumps(args) + "\n")
if args[:2] == ["release", "view"]:
    state = root / "state"
    if not state.exists():
        sys.exit(1)
    if args[args.index("--json") + 1] == "databaseId":
        print("42")
    else:
        print(state.read_text())
elif args[:1] == ["api"]:
    if args[1] != "repos/nolabs-ai/runseal/releases/42":
        sys.exit(2)
    assets = []
    for file in (root / "remote").iterdir():
        asset = {"name": file.name, "state": "uploaded",
                 "digest": "sha256:" + hashlib.sha256(file.read_bytes()).hexdigest()}
        if os.environ.get("RELEASE_TEST_MISSING_DIGEST"):
            asset.pop("digest")
        assets.append(asset)
    print(json.dumps({"id": 42, "tag_name": "v0.3.4",
                      "draft": (root / "state").read_text() == "true",
                      "assets": assets}))
elif args[:2] == ["release", "create"]:
    if (root / "state").exists():
        sys.exit(1)
    (root / "state").write_text("true")
elif args[:2] == ["release", "upload"]:
    for file in args[3:-1]:
        shutil.copyfile(file, root / "remote" / pathlib.Path(file).name)
    if os.environ.get("RELEASE_TEST_EXTRA_ASSET"):
        (root / "remote" / "unexpected.tar.gz").write_bytes(b"unverified")
elif args[:2] == ["release", "download"]:
    destination = pathlib.Path(args[args.index("--dir") + 1])
    for file in (root / "remote").iterdir():
        shutil.copyfile(file, destination / file.name)
    if os.environ.get("RELEASE_TEST_TAMPER"):
        (destination / "SHA256SUMS").write_text("tampered")
elif args[:2] == ["attestation", "verify"]:
    if os.environ.get("RELEASE_TEST_BAD_ATTESTATION"):
        sys.exit(1)
    if os.environ.get("RELEASE_TEST_CHANGE_MANIFEST"):
        (root / "remote" / "SHA256SUMS").write_text("changed after download")
    if os.environ.get("RELEASE_TEST_PUBLISH_DURING_VERIFICATION"):
        (root / "state").write_text("false")
elif args[:2] == ["release", "edit"]:
    (root / "state").write_text("false")
else:
    sys.exit(2)
'''


class ReleaseTests(unittest.TestCase):
    def run_release(self, state=None, **extra):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "remote").mkdir()
            gh = root / "gh"
            gh.write_text(FAKE_GH)
            gh.chmod(0o700)
            if state is not None:
                (root / "state").write_text(state)
            asset = root / "runseal-v0.3.4-x86_64-unknown-linux-gnu.tar.gz"
            asset.write_bytes(b"test release artifact")
            sums = root / "SHA256SUMS"
            sums.write_text(f"{hashlib.sha256(asset.read_bytes()).hexdigest()}  {asset.name}\n")
            env = dict(os.environ, PATH=f"{root}:{os.environ['PATH']}",
                       RELEASE_TEST_ROOT=str(root), GITHUB_REPOSITORY="nolabs-ai/runseal",
                       **extra)
            script = Path(__file__).resolve().parents[1] / "scripts/publish-release.sh"
            result = subprocess.run(["bash", str(script), "v0.3.4", str(asset), str(sums)],
                                    env=env, capture_output=True, text=True)
            calls = [json.loads(line) for line in (root / "calls").read_text().splitlines()]
            return result, calls

    def test_new_release_is_verified_before_publication(self):
        result, calls = self.run_release()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("--draft", calls[1])
        self.assertIn("--verify-tag", calls[1])
        self.assertEqual(calls[-1], ["release", "edit", "v0.3.4", "--draft=false"])
        verifications = [call for call in calls if call[:2] == ["attestation", "verify"]]
        self.assertEqual(len(verifications), 2)
        for call in verifications:
            self.assertEqual(call[call.index("--source-ref") + 1], "refs/tags/v0.3.4")
            self.assertIn("--deny-self-hosted-runners", call)
            self.assertEqual(call[call.index("--repo") + 1], "nolabs-ai/runseal")
            self.assertEqual(call[call.index("--signer-repo") + 1], "nolabs-ai/runseal")
        manifests = [i for i, call in enumerate(calls) if call[:1] == ["api"]]
        self.assertEqual(len(manifests), 2)
        self.assertEqual(manifests[-1], len(calls) - 2)

    def test_existing_draft_can_be_completed(self):
        result, calls = self.run_release("true")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertFalse(any(call[:2] == ["release", "create"] for call in calls))

    def test_published_release_is_never_modified(self):
        result, calls = self.run_release("false")
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(len(calls), 1)

    def test_tampered_download_is_not_published(self):
        result, calls = self.run_release(RELEASE_TEST_TAMPER="1")
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(any(call[:2] == ["release", "edit"] for call in calls))

    def test_extra_draft_asset_is_not_published(self):
        result, calls = self.run_release("true", RELEASE_TEST_EXTRA_ASSET="1")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("asset set changed", result.stderr)
        self.assertFalse(any(call[:2] == ["release", "edit"] for call in calls))

    def test_missing_api_digest_is_not_published(self):
        result, calls = self.run_release(RELEASE_TEST_MISSING_DIGEST="1")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("SHA-256 digests", result.stderr)
        self.assertFalse(any(call[:2] == ["release", "edit"] for call in calls))

    def test_changed_manifest_after_verification_is_not_published(self):
        result, calls = self.run_release(RELEASE_TEST_CHANGE_MANIFEST="1")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("SHA-256 digests", result.stderr)
        self.assertEqual(sum(call[:1] == ["api"] for call in calls), 2)
        self.assertFalse(any(call[:2] == ["release", "edit"] for call in calls))

    def test_published_during_verification_is_not_modified(self):
        result, calls = self.run_release(RELEASE_TEST_PUBLISH_DURING_VERIFICATION="1")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("identity or asset set changed", result.stderr)
        self.assertFalse(any(call[:2] == ["release", "edit"] for call in calls))

    def test_failed_attestation_is_not_published(self):
        result, calls = self.run_release(RELEASE_TEST_BAD_ATTESTATION="1")
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(any(call[:2] == ["release", "edit"] for call in calls))


if __name__ == "__main__":
    unittest.main()
