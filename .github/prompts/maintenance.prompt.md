---
description: "Update the Lambda base image digest and pinned Python dependency versions and open a pull request"
tools:
  [
    "search/codebase",
    "search",
    "edit/editFiles",
    "execute/runInTerminal",
    "execute/getTerminalOutput",
  ]
---

# Maintenance

Perform maintenance on the `Dockerfile` and pinned Python dependencies. Update the Lambda base image digest and pinned Python versions together, and open a single pull request. Read the current image, tag, and package list from the repository; do not assume specific versions.

## Objective

In one pull request, for the image and Python dependencies already declared in this repository:

1. Update the pinned base image digest to the latest published digest for the image and tag in the `FROM` line (for `linux/amd64`).
2. Refresh pinned Python dependency versions to the latest compatible versions while preserving the existing package list.

Always read current values from source files before updating.

## Required Outcome

1. Create a single maintenance branch.
2. Update the Lambda base image digest in the `FROM` line in `Dockerfile`.
3. Update pinned Python dependency versions in `src/var/task/requirements.txt`.
4. If the pinned `pip` version in `Dockerfile` is no longer current, update it as part of the same change.
5. When version assertions are affected, update `test/container-structure-test.yml` to keep expected versions aligned.
6. Commit changes using Conventional Commits.
7. Push the branch and open a pull request with a clear title and description.

## Execution Steps

1. Create a maintenance branch.

   ```bash
   git checkout -b "chore/maintenance-dockerfile-$(date +%Y%m%d-%H%M%S)"
   ```

2. Update the base image digest.

   - Read the base image reference (`<image>:<tag>`) from the `FROM` line in `Dockerfile`.
   - Pull that exact image for `linux/amd64`.

   ```bash
   IMAGE="$(grep -oP '(?<=^FROM )[^@[:space:]]+' Dockerfile)"
   docker pull --platform linux/amd64 "$IMAGE"
   ```

   - Retrieve the current repository digest.

   ```bash
   docker image inspect --format='{{ index .RepoDigests 0 }}' "$IMAGE"
   ```

   - Update the `@sha256:...` digest in `Dockerfile`, keeping image repository and tag unchanged.

3. Update pinned Python dependencies.

   - Read pinned packages from `src/var/task/requirements.txt`.
   - Update versions to the latest compatible values while preserving the same package names.
   - Keep all dependencies pinned with explicit versions.

4. Review `Dockerfile` and `src/var/task/requirements.txt` to confirm package names and image tag are unchanged (only digest and versions may differ).

5. If any version assertions are affected (for example `pip --version` in `test/container-structure-test.yml`), update expected outputs accordingly.

6. Commit the changes using [Conventional Commits](https://www.conventionalcommits.org/) (`build` type).

7. Push the branch and open the pull request with GitHub CLI.

   - The `git commit`, `git push`, and `gh` steps need local Git/GitHub credentials and network access.
   - Set an explicit PR title: a Conventional Commit `build:` summary matching the commit.
   - Write PR description to a temporary file and pass it with `--body-file`.

   ```bash
   git push -u origin <branch>
   gh pr create --base main --head <branch> --title "<title>" --body-file <body-file>
   ```

   - Report the URL of the created pull request.

## Guardrails

- Keep the base image repository and tag unchanged; only update digest.
- Keep platform assumption aligned to `linux/amd64`.
- Do not add or remove Python packages.
- Keep all package installs pinned to explicit versions.
- Deliver updates in one branch and one pull request.
- Use Conventional Commits (`build` type) for commit message and PR title.
