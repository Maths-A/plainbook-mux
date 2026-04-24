# Plainbook Mux

Plainbook Mux is a multi-session launcher and proxy for [Plainbook](https://github.com/lucadealfaro/plainbook), a natural-language notebook system where users describe what they want in plain language and AI generates the code behind the scenes.

Plainbook Mux packages that no-code notebook workflow into a launch page and admin control plane for isolated sessions, making it easier to run studies, demos, and collaborative notebook experiences as a streamlined alternative to Google Colab-style workflows.

## Summary

- What it is: a web multiplexer that creates and routes isolated Plainbook instances per user/session.
- Why it was built: to make notebook work more accessible, reproducible, and scalable for user studies and demos without requiring each participant to set everything up manually.
- How it was built: Python + Bottle backend, access-code driven template loading, per-instance isolation, and optional Docker/Cloud Run child-instance orchestration.

## Key Features

- Public launch flow with access codes.
- Admin dashboard for monitoring and control.
- Session lifecycle APIs (start/list/stop/stop all).
- Runtime isolation for process backend.
- Optional Docker backend.
- Optional Google Cloud Run backend.
- Access-code and generated-code management.
- Study template mapping with local/HTTP/GCS template sources.

## Project Structure

- `src/app.py`: main mux web server and launcher logic.
- `src/instance_entrypoint.py`: entrypoint for child container instances.
- `src/templates/`: HTML templates (`user_page.html`, `admin_login.html`, `admin_page.html`).
- `src/static/css/`: page stylesheets.
- `src/static/js/`: page JavaScript.
- `Dockerfile`: image build for running mux in a container.
- `requirements.txt`: Python dependencies.

## Tech Stack

- Python 3.12
- Bottle
- Plainbook (user_studies branch)
- Docker (optional backend)
- Google Cloud Run + GCS (optional backend/storage)

## Local Run (Process Backend)

1. Create and activate a virtual environment.

```bash
python -m venv .venv
source .venv/bin/activate
```

2. Install dependencies.

```bash
pip install -r requirements.txt
```

3. Set required environment variables.

```bash
export MUX_ADMIN_PASSWORD="change-this-password"
```

4. Optional local settings.

```bash
export MUX_HOST="127.0.0.1"
export MUX_PORT="5050"
```

5. Start the server.

```bash
python src/app.py
```

6. Open the app.

- User page: http://127.0.0.1:5050/
- Admin page: http://127.0.0.1:5050/admin

## Run With Docker

Build:

```bash
docker build -t plainbook-mux:latest .
```

Run:

```bash
docker run --rm -p 5050:5050 \
  -e MUX_ADMIN_PASSWORD="change-this-password" \
  plainbook-mux:latest
```

## Configuration

Important environment variables:

- `MUX_ADMIN_PASSWORD`: admin login password.
- `MUX_HOST`: mux bind host.
- `MUX_PORT`: mux bind port.
- `PLAINBOOK_INSTANCE_BACKEND`: `process`, `docker`, or `cloud-run`.
- `PLAINBOOK_INSTANCE_IMAGE`: required for `docker` and `cloud-run` child instances.
- `PLAINBOOK_CLOUD_RUN_PROJECT`: GCP project id.
- `PLAINBOOK_CLOUD_RUN_REGION`: Cloud Run region.
- `PLAINBOOK_UPLOAD_KEY_JSON`: inline JSON credentials (preferred over files).
- `PLAINBOOK_UPLOAD_KEY_FILE`: credential file path.
- `GCS_STUDY_BUCKET`: bucket for study uploads.
- `PLAINBOOK_ACCESS_CODE_GCS_BUCKET`: bucket for access-code config.
- `PLAINBOOK_ACCESS_CODE_GCS_PREFIX`: prefix for access-code config objects.

## Cloud Run Deployment

1. Build and push image.

```bash
gcloud auth configure-docker us-docker.pkg.dev
docker build -t us-docker.pkg.dev/PROJECT_ID/REPOSITORY/plainbook-mux:latest .
docker push us-docker.pkg.dev/PROJECT_ID/REPOSITORY/plainbook-mux:latest
```

2. Deploy mux service.

```bash
gcloud run deploy plainbook-mux \
  --image us-docker.pkg.dev/PROJECT_ID/REPOSITORY/plainbook-mux:latest \
  --region REGION \
  --platform managed \
  --allow-unauthenticated \
  --set-env-vars MUX_ADMIN_PASSWORD=change-this-password,PLAINBOOK_INSTANCE_BACKEND=cloud-run,PLAINBOOK_INSTANCE_IMAGE=us-docker.pkg.dev/PROJECT_ID/REPOSITORY/plainbook-mux:latest,PLAINBOOK_CLOUD_RUN_PROJECT=PROJECT_ID,PLAINBOOK_CLOUD_RUN_REGION=REGION
```

## Why This Project Matters
- Reduces per-participant setup time for studies.
- Gives controlled isolation and reproducibility.
- Supports local development and cloud-scale execution with the same app.

## Contributors
- [Mathis Aubert](https://github.com/Maths-A), UC Santa Cruz.
- [Luca de Alfaro](https://github.com/lucadealfaro), UC Santa Cruz.