# Plainbook Mux

Plainbook multiplexer (Mux) is a Bottle-based launcher that starts and proxies [Plainbook](https://github.com/lucadealfaro/plainbook) instances for users.
It provides a public launch page, an admin dashboard, and optional container backends (local Docker or Cloud Run).
Plainbook Multiplexer can be deployed as a platform for user studies and, in the future, for production use.

## Features

- Public launch flow for user sessions.
- Password-protected admin panel.
- Process backend for local development.
- Optional per-instance container backend.
- Optional Google Cloud Run child-instance orchestration.

## Project Structure

- `app.py`: main mux web server and launcher logic.
- `instance_entrypoint.py`: entrypoint for child container instances.
- `Dockerfile`: image build for running mux in a container.
- `requirements.txt`: Python dependencies.

## Requirements

- Python 3.11+ (3.12 recommended).
- `pip`.
- Optional: Docker (for container backend and containerized run).
- Optional: Google Cloud SDK and access to a GCP project (for Cloud Run backend).

## Run Locally (Process Backend)

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
python app.py
```

6. Open:

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

Key environment variables:

- `MUX_ADMIN_PASSWORD`: admin login password (strongly recommended).
- `MUX_HOST`: mux bind host (default `0.0.0.0` in container).
- `MUX_PORT`: mux bind port (default `5050`).
- `PLAINBOOK_INSTANCE_BACKEND`: `process`, `docker`, or `cloud-run`.
- `PLAINBOOK_INSTANCE_IMAGE`: required for `docker` and `cloud-run` child instances.
- `PLAINBOOK_CLOUD_RUN_PROJECT`: GCP project id for Cloud Run backend.
- `PLAINBOOK_CLOUD_RUN_REGION`: Cloud Run region.
- `PLAINBOOK_UPLOAD_KEY_JSON`: JSON credentials inline (avoid storing key files in repo).
- `PLAINBOOK_UPLOAD_KEY_FILE`: path to credentials file on deployment environment.
- `GCS_STUDY_BUCKET`: bucket for study uploads.

## Cloud Deployment (Google Cloud Run)

This section assumes you already have a Google Cloud project and billing enabled.

1. Build and push the mux image:

```bash
gcloud auth configure-docker us-docker.pkg.dev
docker build -t us-docker.pkg.dev/PROJECT_ID/REPOSITORY/plainbook-mux:latest .
docker push us-docker.pkg.dev/PROJECT_ID/REPOSITORY/plainbook-mux:latest
```

2. Deploy mux service:

```bash
gcloud run deploy plainbook-mux \
	--image us-docker.pkg.dev/PROJECT_ID/REPOSITORY/plainbook-mux:latest \
	--region REGION \
	--platform managed \
	--allow-unauthenticated \
	--set-env-vars MUX_ADMIN_PASSWORD=change-this-password,PLAINBOOK_INSTANCE_BACKEND=cloud-run,PLAINBOOK_INSTANCE_IMAGE=us-docker.pkg.dev/PROJECT_ID/REPOSITORY/plainbook-mux:latest,PLAINBOOK_CLOUD_RUN_PROJECT=PROJECT_ID,PLAINBOOK_CLOUD_RUN_REGION=REGION
```

## Contributors
* [Mathis Aubert](https://github.com/Maths-A), UC Santa Cruz. 
* [Luca de Alfaro](https://github.com/lucadealfaro), UC Santa Cruz. 