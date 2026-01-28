# Docker Hub CI/CD Setup Guide

This repository uses GitHub Actions to automatically build and push Docker images to Docker Hub when PRs are merged to `main`.

## Setting Up Docker Hub Authentication

Since you're sharing this repository with collaborators, credentials are stored securely in GitHub Secrets rather than in the code.

### Step 1: Create a Docker Hub Access Token

1. Log in to [Docker Hub](https://hub.docker.com/)
2. Click your username (top right) → **Account Settings**
3. Go to **Security** → **Access Tokens**
4. Click **New Access Token**
5. Give it a description (e.g., "GitHub Actions - make-some-noise")
6. Select **Read, Write, Delete** permissions
7. Click **Generate** and **copy the token** (you won't see it again!)

### Step 2: Add Secrets to GitHub Repository

1. Go to your GitHub repository: https://github.com/TheLawsOfChaos/make-some-noise
2. Navigate to **Settings** → **Secrets and variables** → **Actions**
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

The CI/CD pipeline determines the version tag in this order:

1. **Manual Override**: When using "Run workflow" manually, you can specify a version
2. **PR Title**: Include a version in your PR title (recommended):
   - `Release v1.2.3 - New feature`
   - `v1.2.3: Bug fixes`
   - `1.2.3 Update dependencies`
3. **VERSION File**: Falls back to the `VERSION` file in the repo root
4. **Commit SHA**: Last resort - uses `0.0.0-<short-sha>`

### Version Format

- Versions should follow semantic versioning: `MAJOR.MINOR.PATCH`
- Pre-release versions are supported: `1.2.3-beta.1`
- The `v` prefix is optional and will be stripped: `v1.2.3` → `1.2.3`

## Workflow Triggers

### On Pull Request (docker-build-test.yml)
- Builds both images to verify they compile
- Shows what version would be published
- Does NOT push to Docker Hub

### On Push to Main (docker-publish.yml)
- Triggered when PR is merged
- Builds and pushes both images to Docker Hub
- Tags: `<version>` and `latest`
- Builds for both `linux/amd64` and `linux/arm64`

### Manual Trigger
- Go to Actions → "Build and Push Docker Images"
- Click "Run workflow"
- Optionally specify a version override

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
- Check your PR title includes the version in the right format
- Update the `VERSION` file before merging if not using PR title versioning
