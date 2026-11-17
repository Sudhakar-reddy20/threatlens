# ThreatLens demo capture guide

This guide helps create genuine visual evidence for a portfolio or recruiter review. Capture your own terminal run; do not present synthetic examples as real incidents.

## 1. Prepare a clean local run

From the repository root:

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -e ".[dev]"
python -m pytest -v
threatlens analyze sample_logs/auth.log --year 2026
```

The sample dataset is synthetic and uses documentation-only IP ranges.

## 2. Capture a terminal screenshot

On macOS, use **Shift + Command + 4** to capture a selected area, or **Shift + Command + 5** for screen-recording controls.

For a clean recording:
- Increase terminal font size until the command and relevant alert output are readable.
- Show the command, detection identifiers, severity, source address, and output file paths.
- Avoid showing personal paths, tokens, private log data, unrelated windows, or notifications.
- Keep the recording short and focused on one complete run.
- Clearly label the dataset as synthetic.

## 3. Add the evidence to the repository

Create an `assets/` folder and add files such as:

- `assets/threatlens-terminal-demo.png` — readable terminal result.
- `assets/threatlens-terminal-demo.gif` — short screen recording converted to GIF, if the text remains legible.

Use descriptive alt text when embedding them in the README:

```markdown
![ThreatLens analyzing the synthetic SSH authentication dataset](assets/threatlens-terminal-demo.png)
```

## 4. Capture the investigation report

If you include JSON or CSV screenshots, use only generated reports from the synthetic sample dataset. Remove local usernames and filesystem paths if they reveal personal information.

## Evidence integrity

- Never fabricate test results, alerts, screenshots, or incident claims.
- Keep the original sample log and generated report available for reproducibility.
- A detection alert is an investigation lead, not proof of compromise.
- Do not publish customer, employer, or third-party logs without explicit authorization.
