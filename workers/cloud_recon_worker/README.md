# Cloud Recon Worker

The `cloud_recon_worker` is a specialized worker within the A.A.P.T. framework responsible for performing reconnaissance on cloud environments (AWS, Azure, GCP).

## Features

- **Cloud Asset Enumeration**: Identifies public-facing cloud assets such as storage buckets, databases, and serverless functions.
- **Security Assessment**: Uses tools like Prowler to detect misconfigurations and security vulnerabilities.
- **Integration with A.A.P.T.**: Consumes tasks from the orchestrator and publishes results in the standardized A.A.P.T. JSON schema.

## Configuration

The worker can be configured using the following environment variables:

- `RABBITMQ_HOST`: The hostname of the RabbitMQ server.
- `RABBITMQ_USER`: The username for RabbitMQ.
- `RABBITMQ_PASS`: The password for RabbitMQ.
- `AWS_PROFILE`: (Optional) The AWS profile to use for Prowler scans (default: `default`).
- `AZURE_SUBSCRIPTION_ID`: (Optional) The Azure subscription ID for Prowler scans.
- **Note on GCP**: Prowler for GCP typically relies on `gcloud` authentication configured in the environment.

## Usage

1.  Ensure the worker is enabled in your `docker-compose.yml` or Kubernetes configuration.
2.  The orchestrator will automatically dispatch tasks to this worker when cloud-related targets are identified.
3.  Results will be published to the `results_queue` and processed by the `state_manager`.
