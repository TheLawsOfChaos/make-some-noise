# Make Some Noise - Frontend

The React web interface for the Make Some Noise event generator, served by nginx, which also proxies `/api` to the backend container. It is for people: picking sources, previewing events, configuring destinations and watching a run. Pipelines use the backend image alone.

## Quick Start

### Using Docker Compose

```bash
docker compose up -d
# UI on http://localhost:3000 (bound to 127.0.0.1)
```

### Standalone

The image expects a host named `backend` on port 8080 on the same container network:

```bash
docker network create msn
docker run -d --name makesomenoise-backend --network msn --network-alias backend \
  -e API_TOKEN=change-me -v "$PWD/config:/config" -v "$PWD/output:/tmp/output" \
  thelawsofchaos/makesomenoise-backend:1.1.0
docker run -d --name makesomenoise-frontend --network msn \
  -p 127.0.0.1:3000:3000 -e API_TOKEN=change-me \
  --cap-drop ALL --security-opt no-new-privileges:true \
  thelawsofchaos/makesomenoise-frontend:1.1.0
```

## Configuration

| Variable | Default | Meaning |
|---|---|---|
| `API_TOKEN` | empty | attached by nginx as `Authorization: Bearer` to every proxied `/api` call; must match the backend's `API_TOKEN` |

The backend address is fixed in `nginx.conf.template` (`http://backend:8080`). There is no build-time API URL; the UI always calls `/api` on its own origin.

Because nginx attaches the token, anyone who can open the UI can use the API. Keep port 3000 on a trusted network.

## Pages

- **Dashboard**: backend health and source counts
- **Generate**: pick a source and template, preview one event, send a counted batch to a destination
- **Noise Generator**: choose sources, templates and weights, set the rate and destinations, start and stop the run, watch sent, errors, dropped and the sources the run skipped
- **Destinations**: create, edit, test and delete destinations (HEC tokens are never shown back; leave the field as is to keep the stored one)
- **Templates**: the custom template store (stored and listed; generation does not use them yet)

## Architecture

- React 18, TypeScript, Vite 6, Tailwind, axios, React Router 6
- nginx 1.29 (unprivileged image, runs as the nginx user) serving the build and proxying `/api`
- One Playwright test for the theme toggle (`npm test` needs a running dev server)

## Troubleshooting

- **"Failed to connect to backend API"**: the backend container is not healthy or not reachable as `backend:8080` on the container network.
- **401 on every page**: the frontend's `API_TOKEN` does not match the backend's.
- **Blank page after an upgrade**: hard refresh; the asset names change per build.
- Browser console and `docker logs makesomenoise-frontend` show proxy errors.

## License

Apache License 2.0, see [LICENSE](https://github.com/TheLawsOfChaos/make-some-noise/blob/main/LICENSE).
