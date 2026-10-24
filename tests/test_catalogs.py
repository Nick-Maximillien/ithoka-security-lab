import shutil
import tempfile
import unittest
from pathlib import Path

import yaml

from lab.construction import resolve_resources
from lab.foundation import (
    CAPABILITIES_FILE,
    LabError,
    load_catalog,
    load_materials,
    require_available_capability,
    require_available_image,
)


ROOT = Path(__file__).resolve().parents[1]


class CatalogTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name) / "repo"
        catalog_dir = self.root / "lab" / "catalog"
        catalog_dir.mkdir(parents=True)
        shutil.copy(CAPABILITIES_FILE, catalog_dir / "capabilities.yaml")
        shutil.copy(
            ROOT / "lab" / "catalog" / "materials.yaml",
            catalog_dir / "materials.yaml",
        )

    def tearDown(self):
        self.temporary.cleanup()

    def _write_materials(self, materials):
        (self.root / "lab" / "catalog" / "materials.yaml").write_text(
            yaml.safe_dump({"schema_version": 1, "materials": materials}),
            encoding="utf-8",
        )

    @staticmethod
    def _material(**overrides):
        entry = {
            "id": "alpine-runtime",
            "revision": "3.20.0",
            "kind": "container-image",
            "availability": "available",
            "image": "alpine:3.20",
            "source": "approved test fixture",
        }
        entry.update(overrides)
        return entry

    def test_capabilities_are_distinct_from_materials(self):
        capabilities = load_catalog(
            self.root / "lab" / "catalog" / "capabilities.yaml",
            "capabilities",
        )
        self.assertIn("docker.compose", capabilities)
        self.assertEqual(
            capabilities["docker.compose"]["adapter"],
            "docker-compose",
        )
        self.assertIn("construct", capabilities["docker.compose"]["operations"])
        with self.assertRaisesRegex(LabError, "does not support operation"):
            require_available_capability("docker.compose", "export", self.root)
        with self.assertRaisesRegex(LabError, "material is not registered"):
            resolve_resources(
                {"resources": [{
                    "id": "backend",
                    "kind": "container-image",
                    "material_id": "docker.compose",
                }]},
                self.root,
            )

    def test_empty_material_catalog_is_valid(self):
        self.assertEqual(load_materials(self.root), {})

    def test_catalogs_reject_duplicate_ids(self):
        self._write_materials([self._material(), self._material()])
        with self.assertRaisesRegex(LabError, "duplicate catalog identifier"):
            load_materials(self.root)

        path = self.root / "lab" / "catalog" / "capabilities.yaml"
        catalog = load_catalog(path, "capabilities")
        duplicate = next(iter(catalog.values()))
        path.write_text(
            yaml.safe_dump({
                "schema_version": 1,
                "capabilities": [duplicate, duplicate],
            }),
            encoding="utf-8",
        )
        with self.assertRaisesRegex(LabError, "duplicate catalog identifier"):
            load_catalog(path, "capabilities")

    def test_capabilities_reject_malformed_entries(self):
        path = self.root / "lab" / "catalog" / "capabilities.yaml"
        path.write_text(
        yaml.safe_dump({
            "schema_version": 1,
            "capabilities": [{
                "id": "invalid.capability",
                "revision": "1.0.0",
                "adapter": "test",
                "availability": "available",
                "permissions": [],
                "validation": "test",
            }],
        }),
        encoding="utf-8",
        )
        with self.assertRaisesRegex(LabError, "missing required keys"):
            load_catalog(path, "capabilities")

    def test_materials_reject_invalid_digest_and_availability(self):
        for entry, expected in (
            (self._material(digest="sha256:bad"), "SHA-256 digest"),
            (self._material(availability="planned"), "availability is invalid"),
            (self._material(revision=""), "must be a non-empty string"),
        ):
            with self.subTest(entry=entry):
                self._write_materials([entry])
                with self.assertRaisesRegex(LabError, expected):
                    load_materials(self.root)

    def test_resource_resolution_rejects_unknown_and_unavailable_materials(self):
        unknown = {
            "resources": [{
                "id": "image",
                "kind": "container-image",
                "material_id": "missing-image",
            }]
        }
        with self.assertRaisesRegex(LabError, "material is not registered"):
            resolve_resources(unknown, self.root)

        self._write_materials([self._material(availability="unavailable")])
        with self.assertRaisesRegex(LabError, "not currently available"):
            resolve_resources({
                "resources": [{
                    "id": "image",
                    "kind": "container-image",
                    "material_id": "alpine-runtime",
                }]
            }, self.root)

    def test_approved_material_resolution_and_image_lookup(self):
        material = self._material(
            digest="sha256:" + "a" * 64,
        )
        self._write_materials([material])
        resolved = resolve_resources({
            "resources": [{
                "id": "runtime",
                "kind": "container-image",
                "material_id": "alpine-runtime",
                "digest": material["digest"],
            }]
        }, self.root)
        self.assertEqual(resolved[0]["status"], "approved-material")
        self.assertEqual(resolved[0]["digest"], material["digest"])
        self.assertEqual(
            require_available_image("alpine:3.20", self.root)["id"],
            "alpine-runtime",
        )
        with self.assertRaisesRegex(LabError, "does not match material"):
            resolve_resources({
                "resources": [{
                    "id": "runtime",
                    "kind": "container-image",
                    "material_id": "alpine-runtime",
                    "digest": "sha256:" + "b" * 64,
                }]
            }, self.root)

        self._write_materials([self._material()])
        with self.assertRaisesRegex(LabError, "does not match material"):
            resolve_resources({
                "resources": [{
                    "id": "runtime",
                    "kind": "container-image",
                    "material_id": "alpine-runtime",
                    "digest": "sha256:" + "a" * 64,
                }]
            }, self.root)

    def test_unknown_workspace_image_is_not_assumed_approved(self):
        with self.assertRaisesRegex(LabError, "not registered"):
            require_available_image("alpine:3.20", self.root)


if __name__ == "__main__":
    unittest.main()
