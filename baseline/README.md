# Baseline

The baseline is the versioned intended configuration, not proof of runtime state. Runtime checks must compare rendered Compose output and Docker inspection with [baseline-manifest.yaml](baseline-manifest.yaml). Images are locally built from the pinned Python and Alpine tags; their resulting digests are recorded only after a controlled build.