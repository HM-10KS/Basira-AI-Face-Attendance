# Validation record

This source package was checked on Windows with Python 3.14.7 and Flask 3.1.3.

The automated suite covers application authentication and CSRF, face-enrollment business rules, unknown and ambiguous matches, stability gating, session roster snapshots, duplicate prevention including concurrent SQLite writes, session closure, late arrivals, disabled persons, manual corrections and audit records, threshold validation, CSV formula escaping, backup format, and static resource routes.

The face engine in API tests is a deterministic test double. These tests do not measure model accuracy, exercise a real camera, or validate neural-network inference. OpenCV, NumPy, model downloads and live camera operation could not be exercised in the authoring environment. No recognition accuracy or latency result is claimed.

`Setup_Windows.cmd` downloads the actual dependencies and model files, verifies the published SHA-256 values and attempts a real model load before it reports success. Live attendance and independent accuracy evaluation must then be performed on the target computer. See README_AR.md and PROJECT_AR.md.

No personal data, real face images, pretrained model weights, installed virtual environment or test database is included in the source ZIP.
