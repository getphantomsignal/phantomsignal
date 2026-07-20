# Releasing PhantomSignal

How a release is cut, and the one-time PyPI setup that makes the automated
publish work.

## How a release works

Releases are driven by a git tag. Pushing a tag matching `v*.*.*` triggers
[`.github/workflows/publish.yml`](../.github/workflows/publish.yml), which:

1. **Build** — builds the sdist + wheel and **verifies the tag matches the
   package version** (`phantomsignal.__version__` must equal the tag minus its
   `v`). A mismatch fails the run.
2. **Publish** — uploads the artifacts to PyPI using **trusted publishing**
   (OIDC — no stored API token), running in the GitHub Environment named `pypi`.

### Cutting a release

```bash
# 1. Bump the version in BOTH places (they must match the tag)
#    - phantomsignal/__init__.py  → __version__ = "X.Y.Z"
#    - setup.py                   → version="X.Y.Z"
# 2. Move CHANGELOG [Unreleased] → [X.Y.Z] — <date>, add a fresh [Unreleased]
# 3. Commit, merge to main, then tag main:
git tag -a vX.Y.Z <main-commit> -m "PhantomSignal vX.Y.Z — <headline>"
git push origin vX.Y.Z
# 4. Publish a GitHub Release (the workflow does NOT create one):
gh release create vX.Y.Z --title "vX.Y.Z — <headline>" --notes-file notes.md --latest
```

---

## One-time: configure the PyPI trusted publisher

Until this is done the **Publish to PyPI** step fails on every tag (the Build
step still succeeds). Trusted publishing lets GitHub Actions authenticate to
PyPI via OIDC, so there is no API token to store or rotate.

The trusted-publisher config on PyPI **must exactly match** this repo's
workflow:

| Field | Value |
|-------|-------|
| PyPI project name | `phantomsignal` |
| Owner | `getphantomsignal` |
| Repository name | `phantomsignal` |
| Workflow name | `publish.yml` &nbsp;*(filename only, not a path)* |
| Environment name | `pypi` |

### Steps

1. **Log in to PyPI** at <https://pypi.org> as an owner/maintainer of the
   `phantomsignal` project.

2. **Open the project's publishing settings:**
   <https://pypi.org/manage/project/phantomsignal/settings/publishing/>
   (Project → *Manage* → *Publishing*).

3. Under **"Add a new trusted publisher" → GitHub**, fill in exactly:
   - **Owner:** `getphantomsignal`
   - **Repository name:** `phantomsignal`
   - **Workflow name:** `publish.yml`
   - **Environment name:** `pypi`

   Then **Add**.

   > **New/unclaimed project?** If `phantomsignal` doesn't exist on PyPI yet,
   > use <https://pypi.org/manage/account/publishing/> to add a
   > **pending** publisher with the same four values — it becomes active and
   > claims the name on the first successful upload.

4. **Create the GitHub environment** so the workflow's `environment: pypi`
   resolves cleanly (and you can add protection rules):
   GitHub → repo **Settings → Environments → New environment → `pypi`**.
   Optionally require a reviewer or restrict it to tag pushes.
   *(No secrets are needed — OIDC replaces the token.)*

### Verify it works

Re-run the publish for a tag that already built successfully (artifacts are
retained), or cut a fresh patch release:

```bash
# Re-run only the failed jobs of a previous tag run:
gh run list --workflow=publish.yml --limit 1        # find the run id
gh run rerun <run-id> --failed

# …or re-trigger from scratch by re-pushing the tag:
git push origin :refs/tags/vX.Y.Z && git push origin vX.Y.Z
```

A green **Publish to PyPI** job and the new version live at
<https://pypi.org/project/phantomsignal/> confirm success.

---

## Notes / gotchas

- **Version must match the tag** — the Build step enforces it; bump
  `__init__.py` *and* `setup.py` before tagging.
- **`v1.27.0` and earlier tags** built fine but never reached PyPI because the
  trusted publisher wasn't configured — after the setup above, use the re-run
  step to push the latest version, or just ship it in the next release.
- The workflow doesn't open a GitHub Release; create it with
  `gh release create` (see above).
- Trusted publishing needs `permissions: id-token: write` on the publish job —
  already set in `publish.yml`.
