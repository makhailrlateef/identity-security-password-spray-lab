# Investigation: simulated identity alert

**Analyst:** Makhail Lateef  
**Run date:** September 24, 2026  
**Scope:** Synthetic data; offline simulation using a supplied Python detector on Windows. No live tenant or real accounts were accessed.

## Summary

I ran and validated a Python detection rule against synthetic sign-in logs. The suspicious dataset produced an alert for three distinct accounts with failed sign-ins from `198.51.100.10` between 12:00 and 12:05 UTC on September 1, 2026.

Reviewing the source events showed a successful sign-in for `alex@example.test` from the same IP at 12:06 UTC. This pattern is consistent with possible password spraying and warrants further investigation. The available fields do not establish whether the successful sign-in was authorized or whether an account was compromised.

All 12 automated tests passed. The benign dataset produced no alert. Increasing the distinct-user threshold from three to four also produced no alert against the original suspicious dataset.

## Timeline

The following timestamps belong to the synthetic events on **September 1, 2026**, not the lab execution date.

| UTC time | User | Source IP | Result | Relevance |
|---|---|---|---|---|
| 12:00 | alex@example.test | 198.51.100.10 | Failure | First failed sign-in from the source under investigation. |
| 12:01 | drew@example.test | 203.0.113.20 | Success | Different source IP; does not contribute to the failure rule. |
| 12:02 | blair@example.test | 198.51.100.10 | Failure | Second distinct account with a failure from the same source. |
| 12:05 | casey@example.test | 198.51.100.10 | Failure | Third distinct account; the detection threshold is met. |
| 12:06 | alex@example.test | 198.51.100.10 | Success | Success following the failures; requires contextual investigation. |

## Detection

- **Rule and threshold:** Flag the first qualifying window per source IP containing failed sign-ins for at least three distinct users within a rolling ten-minute window.
- **Why it matched:** Alex, Blair, and Casey each had a failed sign-in from `198.51.100.10` within five minutes. The alert reported three distinct users and three failed attempts.
- **Why the benign file did not match:** Repeated failures for Drew counted as one distinct account. The other accounts' failures were too far apart to form a qualifying ten-minute window. The detector returned `[]`.
- **Evidence:** The generated `evidence/my-alerts.json` file and terminal output reviewed during the lab. Screenshots showed the 12 passing tests, suspicious alert, source-event table, benign result, and four-user threshold result.
- **Success review:** The detector counts failures only. I identified Alex's later success by reviewing the CSV in PowerShell.

Commands used:

```powershell
py -3 -m unittest discover -s tests -v
py -3 src/detect.py data/spray.csv --output evidence/my-alerts.json
py -3 src/detect.py data/benign.csv
Import-Csv data/spray.csv | Format-Table -AutoSize
```

## Assessment

- **Suspicious observations:** A single source failed against three different accounts in a short period, followed by a successful sign-in for one of those accounts from the same source.
- **Plausible benign explanation:** Multiple legitimate users could share a public IP and make password errors. Alex's successful sign-in could be a legitimate retry. These possibilities require corroborating evidence.
- **What these logs cannot establish:** They do not show the passwords attempted, who controlled the source, why authentication failed, whether MFA was completed, or what happened after the successful sign-in. Password spraying and account compromise remain hypotheses.
- **Additional evidence needed:** Authentication failure codes, MFA details, device information, location, account privileges, expected source IPs, user confirmation, and audit activity following the success.

## Threshold experiment

- **Change made:** Increased the minimum number of distinct accounts from three to four while keeping the ten-minute window and source dataset unchanged.
- **Expected result:** No alert, because only three distinct accounts had failed sign-ins from the source.
- **Observed result:** The detector returned `[]`, matching the expectation.
- **Security tradeoff:** A higher threshold can reduce noise but may miss suspicious activity involving fewer accounts. In this scenario, the same pattern stopped generating an alert after the threshold change. An empty result does not establish that activity is safe.

```powershell
py -3 src/detect.py data/spray.csv --min-users 4
```

## Response recommendation

In a real environment, I would first investigate Alex's successful sign-in at 12:06 UTC. I would compare its device, authentication details, source, and location with expected activity, confirm the sign-in with the user, and inspect subsequent account actions. I would also review Blair and Casey for additional suspicious activity.

Evidence of unauthorized access would justify escalation and containment under the organization's incident response procedures. Potential actions include revoking sessions, resetting affected credentials, and reviewing authentication methods and account privileges. Source-IP blocking would require consideration of shared infrastructure and business impact.

**Actions actually performed:** Ran the local detector and automated tests, reviewed synthetic events, compared benign and suspicious results, and changed the detection threshold. No accounts were modified, sessions revoked, or IPs blocked.

## Lessons learned

- **Key lesson:** Counting distinct users helps distinguish failures spread across accounts from repeated mistakes against one account. Reviewing later successful sign-ins adds context that the failure alert alone does not provide.
- **Limitation:** This rule can miss attacks spread across multiple IPs or longer periods. It also emits only the first qualifying window per IP per run and cannot determine whether an account was compromised.
- **Proposed improvement:** Add a correlation step that identifies successful sign-ins for affected accounts after a qualifying failure window, then test both suspicious and legitimate retry scenarios. This improvement has not yet been implemented.

## Project contribution

This was a guided lab using supplied code and synthetic datasets. My completed work covered local setup, execution, validation, event review, and threshold testing. This report was prepared with AI assistance from the observed results. It does not claim a live Microsoft Entra ID or Microsoft Sentinel deployment.
