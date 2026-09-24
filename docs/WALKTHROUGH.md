# Walkthrough

Allow about 30–60 minutes. Your goal is to explain why the alert happened, not just run a script.

## 1. Open the project

Extract the ZIP. Open the inner `entra-signin-detection-lab` folder containing `README.md`. On Windows, right-click inside the folder and choose **Open in Terminal**, or open PowerShell and use `cd` with the quoted folder path.

Check Python:

```powershell
py -3 --version
```

Use Python 3.10 or newer. On macOS/Linux use `python3` in place of `py -3` throughout.

## 2. Inspect the input

Open `data/spray.csv` in a text editor. Each row represents one synthetic sign-in event.

| Field | Meaning |
|---|---|
| `timestamp` | Time with a timezone; Z means UTC |
| `user` | Account being accessed |
| `ip_address` | Source of the sign-in attempt |
| `result` | success or failure |

Before running the detector, write down the source IP you would investigate and why. Find the row that makes the incident more concerning than failed logins alone.

## 3. Validate the code

```powershell
py -3 -m unittest discover -s tests -v
```

Expected: **12 tests, OK**. Tests cover the two datasets, unsorted events, the exact ten-minute boundary, events outside the window, separate IPs, successes, threshold changes, empty input, invalid thresholds, and malformed CSV.

Save a screenshot of your own successful run as `evidence/my-tests.png` if you want it in your portfolio.

## 4. Detect the suspicious pattern

```powershell
py -3 src/detect.py data/spray.csv --output evidence/my-alerts.json
```

Expected: one alert, IP `198.51.100.10`, three distinct users, three failures, 12:00–12:05 UTC. Compare your output with `evidence/expected-alerts.json`.

The 12:06 successful sign-in is not included in the alert because the detector evaluates failures. Find it in the CSV and add it to your investigation timeline.

## 5. Test a benign case

```powershell
py -3 src/detect.py data/benign.csv
```

Expected: `[]`. Three failures for Drew count as one distinct user. The other accounts fail too far apart to create a qualifying window.

Explain why a simple “three failures” rule would be noisier than this rule.

## 6. Tune the rule

```powershell
py -3 src/detect.py data/spray.csv --min-users 4
py -3 src/detect.py data/spray.csv --window-minutes 4
```

Both return `[]`. The first needs another distinct account. The second excludes the first failed sign-in before the third occurs.

Now copy `data/spray.csv` to `data/my-scenario.csv`. Add a fourth failed sign-in from the suspicious IP at 12:04 UTC for `erin@example.test`. Rerun with `--min-users 4` against your new file. Expect one alert. Keep the original fixtures unchanged so their tests remain reproducible.

## 7. Write your findings

Copy `docs/INVESTIGATION-TEMPLATE.md` to `docs/MY-INVESTIGATION.md`. Fill it in before reading the answer key. Include:

- The account and IP evidence.
- Why the successful sign-in matters without assuming compromise.
- One plausible benign explanation.
- Evidence you would request from a real tenant.
- Your threshold experiment and what it changed.

## 8. Publish when ready

Follow `docs/PUBLISHING.md`. Your strongest addition is your own analysis and the modified scenario you tested.

## Troubleshooting

| Problem | Fix |
|---|---|
| `py` is not recognized | Try `python --version`; if unavailable, install Python from python.org and reopen the terminal. |
| Cannot find `src/detect.py` | Run commands from the folder containing README.md, src, data, and tests. |
| `No module named src` while testing | Run the exact discovery command from the project root. |
| CSV error | Check the named line, required headers, IP address, timezone, and success/failure spelling. |
| Export path does not exist | Use the supplied `evidence` folder or create the desired parent folder first. |
| No alert after an edit | Check distinct users, the source IP, timestamp spacing, and result values. |

## Cleanup

The lab creates only local files. Delete the extracted folder when finished if you no longer need it. There are no cloud resources to tear down.
