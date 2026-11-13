# Docker Hub CI/CD Setup Guide

This repository uses GitHub Actions to automatically build and push Docker images to Docker Hub when PRs are merged to `main`.

## Setting Up Docker Hub Authentication

Since you're sharing this repository with collaborators, credentials are stored securely in GitHub Secrets rather than in the code.

### Step 1: Create a Docker Hub Access Token

1. Log in to [Docker Hub](https://hub.docker.com/)
2. Click your username (top right) then **Account Settings**
3. Go to **Security** then **Access Tokens**
4. Click **New Access Token**
5. Give it a description (e.g., "GitHub Actions - make-some-noise")
6. Select **Read, Write, Delete** permissions
7. Click **Generate** and **copy the token** (you won't see it again!)

### Step 2: Add Secrets to GitHub Repository

1. Go to your GitHub repository: https://github.com/TheLawsOfChaos/make-some-noise
2. Navigate to **Settings** then **Secrets and variables** then **Actions**
3. Click **New repository secret** and add:

   | Secret Name | Value |
   |-------------|-------|
   | `DOCKERHUB_USERNAME` | Your Docker Hub username (e.g., `thelawsofchaos`) |
   | `DOCKERHUB_TOKEN` | The access token you created in Step 1 |

### Important Security Notes

- **Never commit credentials** to the repository
- **Use access tokens**, not your Docker Hub password
- Access tokens can be revoked without changing your main password
- Collaborators with write access to the repo can trigger builds, but they cannot see or access your Docker Hub credentials

## How Versioning Works

Each image has its own version in `versions.json` (`frontend` and `backend`). On a push to `main`, `docker-publish.yml`:

1. Builds only the image whose files changed (`frontend/`, `backend/`, the matching Dockerfile, or that service's section of `docker-compose.yml`).
2. Picks the version, in this order: a manual "Run workflow" override; a `frontend:x.y.z` or `backend:x.y.z` token in the commit message; otherwise the patch number in `versions.json` plus one.
3. Pushes `<image>:<version>` and `<image>:latest` for `linux/amd64` and `linux/arm64`.
4. Commits the new `versions.json` back to `main` with `[skip ci]`.

The backend bakes its version into `/api/health` from `versions.json` at build time. `docker-compose.release.yml` should be bumped by hand when a release is meant for it.

## Workflow Triggers

### On Pull Request (docker-build-test.yml)
- Runs gofmt, go vet and the Go tests with the race detector
- Builds the frontend (type check included)
- Builds both images without pushing, in a build cache scope the publish workflow does not read
- Shows the versions that `main` currently carries

### On Push to Main (docker-publish.yml)
- Builds and pushes the changed images as above
- Only the job that commits `versions.json` has write access to the repository

### Manual Trigger
- Actions, "Build and Push Docker Images", "Run workflow"
- Tick the image(s) to build and optionally give a version

## Pinned actions

Every `uses:` is pinned to a commit SHA with the tag in a comment. To update one, change both.

## Published Images

After successful merge, images are available at:
- `thelawsofchaos/makesomenoise-frontend:<version>`
- `thelawsofchaos/makesomenoise-frontend:latest`
- `thelawsofchaos/makesomenoise-backend:<version>`
- `thelawsofchaos/makesomenoise-backend:latest`

## Troubleshooting

### "unauthorized: incorrect username or password"
- Verify `DOCKERHUB_USERNAME` is correct
- Regenerate your Docker Hub access token and update `DOCKERHUB_TOKEN`

### Build fails but works locally
- Check the GitHub Actions logs for specific errors
- Ensure all files needed for the build are committed (not in `.gitignore`)

### Wrong version published
- Put `backend:x.y.z` or `frontend:x.y.z` in the merge commit message, or run the workflow by hand with a version
