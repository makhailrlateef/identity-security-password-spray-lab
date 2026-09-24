# Prepare your GitHub project

Suggested repository name: **identity-security-password-spray-lab**.

Suggested description: **A beginner identity-security lab with Python detection, synthetic sign-in logs, validation tests, and an incident investigation.**

## Before publishing

1. Run the walkthrough yourself.
2. Complete `docs/MY-INVESTIGATION.md` in your own words.
3. Add your generated `evidence/my-alerts.json`, your test screenshot, and the scenario you changed.
4. Keep the reference evidence clearly identified as preparation output.
5. Make sure screenshots and files contain no real credentials, tenant data, or personal account details.

Create a GitHub repository and upload the project contents so README.md appears at the repository root. Upload the extracted files, not only the ZIP. Keep the `data`, `docs`, `src`, `tests`, and `evidence` folders. Omit `__pycache__` if your machine generated it; .gitignore helps when using Git, but manual uploads still need review.

## Portfolio wording after completing it

“Implemented and tested a Python detection for possible password spraying using synthetic identity logs; investigated a subsequent successful sign-in and documented detection limits and threshold tradeoffs.”

If you used the supplied code, describe it as a guided lab and explain your own modifications. Do not describe the project as a live Azure deployment or production incident response.

## Be ready to answer

- Why count distinct users instead of total failures?
- How does the rolling window differ from fixed ten-minute buckets?
- Why is a successful sign-in insufficient to prove compromise?
- How could a shared IP cause a false positive?
- What would this detection miss?
- What did you change and how did you validate it?
