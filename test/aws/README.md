# AWS Secrets Manager export E2E

Run `task export/aws/test/e2e` to start an isolated, digest-pinned Kumo instance,
wait for the Secrets Manager API, run the race-enabled SDK test, and tear it down.
Docker and localhost port 4566 are required. No real AWS credentials are used.
This task also runs in `task all/test` and a dedicated GitHub Actions job.

The test reads a verified SecretMap Artifact with hostile metadata, builds a plan
using an explicit `/safe/` prefix, and applies it through the production adapter.
It verifies exact values after create, update, repeated apply, and returning to an
older value. A guarded HTTP transport checks the configured endpoint and signing
region, an attacker endpoint records unexpected traffic, and ListSecrets checks
that only planned names exist.

The planner accepts only a semantic SecretMap and explicit prefix options. Use
`secretmap.ReadArtifact` to reject unsupported schemas and verify plaintext before
planning. Prefixes can have a leading/trailing slash; a separator is appended when
needed. Keys are concatenated verbatim, without path cleaning. Names use the AWS
ASCII character set and must contain 1–512 bytes. Values use SecretString and must
contain 1–65,536 UTF-8 bytes; empty values are rejected without changing SecretMap.

For AWS, callers configure an SDK Secrets Manager client from
`config.LoadDefaultConfig(ctx)` and pass it to `aws.Apply(ctx, client, plan)`.
Only the test harness sets the Kumo BaseEndpoint. Region, credentials, endpoint,
account, role, retry policy, and transport never come from Artifact metadata or
Plan. The adapter uses CreateSecret and falls back to PutSecretValue only on a
typed ResourceExistsException. It validates the whole plan first and stops at the
first API failure; previous writes remain applied. Reapplying preserves current
values but may create additional AWS versions. No deletion, rollback, or exact
version idempotency is promised.

Kumo verifies the real SDK request path, not AWS IAM, KMS, production credentials,
service quotas, or every service error behavior. These remain outside this phase.

References: [AWS CreateSecret API](https://docs.aws.amazon.com/secretsmanager/latest/apireference/API_CreateSecret.html),
[Kumo](https://github.com/sivchari/kumo).
