# Group-Scoped Bucket Access

Rollout procedure for granting S3 bucket access through Cognito user pool groups, where each group
is named after the bucket it grants.

| | |
|---|---|
| **Affects** | Lambda proxy, `CognitoLongLivedRole`, user pool groups |
| **Client upgrade** | Not required — existing installs keep working |
| **Downtime** | None; credentials issued before the change keep their old access until expiry |
| **Executed by** | Administrator with IAM, Lambda and Cognito write access |

## What changes

Before this change, every authenticated user assumes `CognitoLongLivedRole` and inherits whatever
that role's S3 policy grants — one policy, one set of buckets, identical for everyone.

After it, the role holds a *superset* covering every managed bucket, and the Lambda narrows each
individual session at `AssumeRole` time by passing an inline session policy naming only the caller's
group-buckets. Effective access is the intersection of the two, so a bucket the role can reach but
the user's groups do not cover is denied.

The Lambda establishes who the caller is by passing their ID token to `cognito-identity:GetId`.
Cognito must verify that token's signature and expiry to federate on it, so a successful call proves
the token is genuine — at which point the `cognito:groups` claim inside it can be trusted. This
needs no JWT library, no new dependency in the deployment package, and no change to what the client
sends, which is why existing users do not have to upgrade.

| Component | Change | Applied by |
|---|---|---|
| `lambda_function.py` | Validate token via `GetId`, read `cognito:groups`, build session policy, pass it to `assume_role` | Deploy (step 4) |
| `lambda-execution-policy.json` | Adds `cognito-identity:GetId` | Deploy (step 4) — reapplied automatically |
| `admin.py` | Adds `IDENTITY_POOL_ID` and `USER_POOL_ID` to the Lambda environment | Deploy (step 4) |
| `CognitoLongLivedRole` | `S3AccessPolicy` widened to a bucket-prefix wildcard | Manual (step 3) |
| User pool groups | One group per bucket, named exactly as the bucket | Manual (step 2) |
| Identity Pool authenticated role | Must carry **no** S3 permissions | Manual (step 0) |

## Procedure

Run these in order. Step 0 is a gate, not a formality — the rest of the change provides no
enforcement if it fails.

### Step 0 — Audit the Identity Pool authenticated role

!!! danger "Stop if this fails"
    The client falls back to Identity Pool credentials whenever the Lambda call fails, and
    `cogauth login --no-lambda-proxy` skips the Lambda entirely. Both paths hand the user the
    Identity Pool authenticated role with no session policy and no group scoping. If that role has
    any S3 access, every user can reach every bucket it grants and this change enforces nothing.

```bash
aws cognito-identity get-identity-pool-roles \
  --identity-pool-id <IDENTITY_POOL_ID>

# take the authenticated role name from the output, then:
aws iam list-role-policies --role-name <AUTH_ROLE_NAME>
aws iam list-attached-role-policies --role-name <AUTH_ROLE_NAME>
```

Expected: only `cognito-identity:GetCredentialsForIdentity` and `lambda:InvokeFunction`. Anything
S3-related must go — most likely a leftover from `cogadmin policy create-s3-policy`, which attaches
to this role.

```bash
aws iam delete-role-policy \
  --role-name <AUTH_ROLE_NAME> --policy-name <POLICY_NAME>
```

### Step 1 — Pull the repo changes and install

Administrator machine only. Users do **not** reinstall — the change is backward compatible with the
client they already have.

```bash
git pull
uv sync
```

Confirm `admin-config.json` carries both pool IDs. If `user_pool_id` is missing there, the deploy
falls back to `~/.cognito-cli-config.json`, so a machine that has run `cogauth configure` will still
resolve it.

### Step 2 — Create one group per bucket

The group name *is* the bucket name — exact match, no prefix. Group names must therefore be valid S3
bucket names: 3–63 characters, lowercase letters, digits, hyphens and dots.

```bash
aws cognito-idp create-group \
  --user-pool-id <USER_POOL_ID> --group-name acme-reports

aws cognito-idp admin-add-user-to-group \
  --user-pool-id <USER_POOL_ID> --username alice --group-name acme-reports

# verify
aws cognito-idp admin-list-groups-for-user \
  --user-pool-id <USER_POOL_ID> --username alice
```

!!! warning "Namespace warning"
    Every group in this pool is now interpreted as a bucket grant. Do not create groups here for
    unrelated purposes — an `admins` group would be read as a request for a bucket named `admins`.

### Step 3 — Widen the role policy to the superset

Because access is an intersection, any bucket missing from the role policy is denied even when the
user's group grants it. A prefix wildcard makes this one-time — new buckets are covered
automatically and the session policy does the real gating.

```bash
cat > /tmp/s3-super.json <<'EOF'
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": "s3:ListBucket",
      "Resource": "arn:aws:s3:::acme-*"
    },
    {
      "Effect": "Allow",
      "Action": ["s3:GetObject", "s3:PutObject", "s3:DeleteObject"],
      "Resource": "arn:aws:s3:::acme-*/*"
    }
  ]
}
EOF

aws iam put-role-policy --role-name CognitoLongLivedRole \
  --policy-name S3AccessPolicy --policy-document file:///tmp/s3-super.json
```

Replace `acme-*` with your actual bucket naming convention. Keep it as tight as the convention
allows — this is the ceiling on what any session policy can grant.

!!! warning "Order matters"
    Between this step and step 4 the role is wide open to every matching bucket for every user,
    because no session policy exists yet. Keep the gap short, or do step 4 first and accept that
    users see denials until this lands.

### Step 4 — Deploy the Lambda

This pushes the new handler code, reapplies the execution role policy with
`cognito-identity:GetId`, and sets the two new environment variables.

```bash
cogadmin lambda deploy \
  --region ap-southeast-1 \
  --access-key-id <AKIA...> \
  --secret-access-key <SECRET>
```

!!! note "Why the keys are needed"
    Environment variables are only pushed when a non-empty secret access key is supplied. Deploy
    without them and the code updates but `IDENTITY_POOL_ID` and `USER_POOL_ID` never arrive, so the
    Lambda fails at runtime and every user silently drops to the one-hour fallback.

Confirm all five variables are present before moving on:

```bash
aws lambda get-function-configuration \
  --function-name cognito-credential-proxy \
  --query 'Environment.Variables'
```

Expect `DEFAULT_ROLE_ARN`, `IAM_USER_ACCESS_KEY_ID`, `IAM_USER_SECRET_ACCESS_KEY`,
`IDENTITY_POOL_ID`, `USER_POOL_ID`. If you ever set these by hand, pass all five — the call replaces
the whole block.

## Verification

Run all three from a machine with the **old, un-upgraded client** — that is the configuration real
users are on. Log in fresh before each case; scoping is fixed at login, so a stale session proves
nothing.

### Must succeed — user syncs a bucket their group covers

```bash
cogauth login -u alice
aws s3 sync s3://acme-reports/data ./local-folder
```

Login reports the upgrade to longer-lived credentials, and objects download normally. This proves
the session policy is being built, not just applied.

### Must be denied — same user syncs a bucket their group does not cover

```bash
aws s3 sync s3://acme-finance ./local-folder
```

Expect `fatal error: An error occurred (AccessDenied) when calling the ListObjectsV2 operation`.
This is the change working. If it succeeds, the session policy is absent or too broad — check
CloudWatch for the policy the Lambda generated.

### Must degrade safely — user belonging to no groups

```bash
cogauth login -u bob
aws s3 sync s3://acme-reports ./local-folder
```

Login prints `⚠️ Lambda proxy failed` followed by `Keeping Identity Pool credentials`, and the sync
is denied. The warning is expected — the old client cannot render a better message. Confirm the real
reason is in CloudWatch, and confirm the sync is *denied*; if it succeeds, step 0 was not completed.

!!! note "Also worth checking"
    `aws s3 ls` with no bucket argument will now fail for everyone — listing all buckets needs
    account-wide `s3:ListAllMyBuckets`, which cannot be scoped per user. `aws s3 ls s3://acme-reports/`
    works as normal.

## Rollback

!!! danger "Reverse the order"
    Reverting only the Lambda leaves the widened role policy with nothing narrowing it — every user
    would get every `acme-*` bucket, which is broader than before the change. Narrow the role first,
    then revert the code.

1. Restore `S3AccessPolicy` on `CognitoLongLivedRole` to the single-bucket document captured before
   step 3.
2. Redeploy the previous handler:
   `cogadmin lambda deploy --lambda-code <path-to-old-lambda_function.py> ...`
3. Leave the groups in place. They are inert once the Lambda stops reading them, and removing them
   loses the membership data.

Users already holding credentials are unaffected by either direction until those credentials expire.

## Known behaviour after the change

- **Membership changes take up to 12 hours to bite.** The session policy is fixed at `AssumeRole`
  time, so removing someone from a group does not touch credentials already issued. Lower
  `--duration` at login if you need a tighter revocation window.
- **Adding a user to a group takes effect at their next login**, since the client authenticates fresh
  every time and the group claim is minted with the token.
- **Roughly 20 buckets per user is the ceiling.** Inline session policies cap at 2048 characters.
  Beyond that the Lambda must switch to pre-created managed policies passed as `PolicyArns`.
- **Failures are indistinguishable from outages to the user.** Any Lambda error surfaces as the same
  `Lambda proxy failed` warning, so CloudWatch is the only place the real cause appears.
