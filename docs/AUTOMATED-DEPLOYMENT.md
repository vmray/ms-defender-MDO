# VMRay Defender for Office 365 (MDO) Azure Connector — Deployment Guide

This repository contains the components and instructions to deploy the VMRay connector for Microsoft Defender for Office 365 (MDO). The connector polls Defender for O365 alerts, submits the related URLs (and User-Reported-Phishing attachments) to the VMRay sandbox, and enriches the Defender alerts and incidents with the analysis results.

---

## Introduction

### Microsoft Defender for Office 365 + VMRay

This project integrates Microsoft Defender for Office 365 with VMRay (FinalVerdict / TotalInsight). It:

- **Understands attacker intent** — full visibility into the next stage of a phishing attack (URLs *and* any payloads they download).
- **Streamlines alert triage** — posts VMRay verdicts, malware names, classifications, and VTI data directly onto the Defender alert.
- **Covers User-Reported Phishing** — fetches both the URLs and the attachment for user-reported spam/phishing, so kits that bypass email security get caught by VMRay dynamic analysis.
- **Enhances protection** — adds VMRay IOCs to Microsoft Defender indicators.
- **Accelerates incident response** — links to comprehensive VMRay sandbox reports.

### Solution Overview

The connector is a single **time-triggered Azure Function App** (`VMRay_O365`) plus Azure Storage:

1. The Function App continuously polls the Defender portal for O365 alerts on a configurable interval.
2. It extracts URLs from the alert (and, for User-Reported Phishing/Spam, uploads the attachment), skipping URLs matched by the exclusion regex or already analyzed within the resubmit window.
3. It submits the sample to VMRay and waits for the analysis result.
4. Results are posted as a **comment on the Defender alert** (and, if enabled, on the parent **incident** with dedup), verdict/threat-name **tags** are added to the incident, and IOCs are added as Defender **indicators**.

![solution_overview](../Images/MDOArchitecture.png)

#### Known limitations

- **Teams alerts:** URLs cannot currently be extracted from Teams alerts (Defender/Graph API limitation).
- **Email attachments:** only analyzed for User-Reported Phishing/Spam. For other alerts the attachment is inaccessible once the email is removed or quarantined.

### About VMRay

VMRay is a leading provider of automated malware analysis and advanced threat detection. Using hypervisor-based sandboxing, VMRay delivers deep visibility into sophisticated and evasive threats.

---

## Prerequisites

| Requirement | Why |
|---|---|
| **Azure Subscription** | To host the Function App and Storage |
| **Global Administrator** (in your Microsoft 365 / Entra tenant) | The connector uses **application permissions** (WindowsDefenderATP + Microsoft Graph) that require tenant-wide admin consent |
| **Microsoft Defender for Office 365** | The source of the alerts being enriched |
| **VMRay FinalVerdict / TotalInsight** | The sandbox that analyzes the samples |
| **VMRay Connector API key** | Created in the VMRay Console (see below). Used to configure the Function App |
| **PowerShell environment** | Azure Cloud Shell (PowerShell) is the recommended way to run the script |

### Create a VMRay Connector API key

In the VMRay Console:

1. Create a dedicated user for this API key (so the key isn't deleted if an employee leaves).
2. Create a role that allows *"View shared submission, analysis and sample"* and *"Submit sample, manage own jobs, reanalyse old analyses and regenerate analysis reports"*.
3. Assign the role to the user.
4. Sign in as that user and create an API key under **Settings → Analysis → API Keys**.
5. Save the key — you'll paste it into the script during Phase 2.

---

## Deployment Overview

The entire Azure-side deployment is driven by a single interactive PowerShell script that handles two phases:

| Phase | What it does | Manual? |
|---|---|---|
| **0. Pre-flight** | Loads modules, connects to Microsoft Graph + Azure, offers a subscription picker, creates/reuses the resource group | Automated |
| **1. App Registration** | Creates (or reuses) the Entra App Registration, adds the WindowsDefenderATP + Microsoft Graph **application** permissions, mints a client secret | Automated |
| **1.5. Admin consent** | Grants admin consent **programmatically** if you have the directory role; otherwise prints a one-time URL for a Global Admin to click (can be deferred) | Auto, or **manual click** |
| **2. Function App** | Deploys the Function App (Flex Consumption or Premium) via ARM. The connector uses a **managed identity** for storage, so there is no manual "copy the storage key" step | Automated |

**Total customer-side effort: one PowerShell command + (only if you can't self-grant) one admin-consent click.**

Unlike the Defender-for-Endpoint connector, MDO has **no Logic App**, **no Live Response / Intune toggles**, and **no storage-key step** — it's the simplest of the three to deploy.

---

## Quick Start — Cloud Shell

### Step 1 — Open Cloud Shell

1. Sign in to the [Azure Portal](https://portal.azure.com) with your tenant administrator account.
2. Click the **`>_`** Cloud Shell icon in the top-right toolbar.
3. Choose **PowerShell** if prompted.

### Step 2 — Upload the deployment script

Click **Manage files → Upload** in the Cloud Shell toolbar and upload:

- `Scripts/Deploy-VMRayMDOConnector.ps1`

The ARM templates (Flex + Premium) are fetched directly from GitHub by the script — no need to upload them.

### Step 3 — Run the deployment script

```powershell
./Deploy-VMRayMDOConnector.ps1
```

The script is fully interactive — it prompts for everything it needs. Default values appear in brackets; press Enter to accept.

> **Offline / local override:** If you've customized a template or your environment can't reach GitHub, upload the JSON alongside the script and pass it explicitly:
> ```powershell
> ./Deploy-VMRayMDOConnector.ps1 -FunctionTemplateFile ~/azuredeploy.json
> ```
> The local file takes precedence over the default GitHub URL.

You'll be asked (in order):

| Prompt | What to enter |
|---|---|
| Confirm tenant + subscription | If only one subscription is accessible, press Enter to confirm. If multiple are accessible, the script offers a picker — choose 1 for the current one, or 2 to pick another. |
| Resource group name | Existing RG, or a new name (created if missing). |
| Azure region | **Only asked if the RG is new.** If you reused an existing RG, its location is used automatically. |
| Create new or use existing App Registration? | Choose **1 (new)** for a first-time deployment. |
| Display name for the new App Registration | Press Enter for default (`VMRay-MDO-Connector-App`). |
| **Open the printed consent URL → sign in as a Global Admin → click Accept** | (Only if the script couldn't grant consent programmatically.) |
| Consent step: `[1] verify now`  or  `[2] Skip` | Choose **1** if consent was just granted (verifies, waits up to 90s). Choose **2** to defer — the URL is reprinted at the end to forward to an admin. |
| Which Function App hosting plan? | **1 Flex Consumption** (check region support) or **2 Premium**. |
| Function App base name | Press Enter for default (`VMRayDefenderO365`). Must be **< 20 characters**, letters/numbers/hyphens. A 3-char uniqueness hash is appended automatically. |
| Log Analytics workspace | Pick one from the list, or paste a full `/subscriptions/.../workspaces/...` Resource ID. |
| VMRay Base URL | **1** `https://eu.cloud.vmray.com`, **2** `https://us.cloud.vmray.com`, or **3** to enter your own. |
| VMRay API Key | Paste your VMRay connector API key (input hidden; required). |
| Configure advanced connector settings? | Press Enter for **No** (sensible defaults). Choose **Yes** to set polling interval, resubmit window, indicators, tags, comments, URP attachment analysis, verdict, alert severities, and URL exclusion regex. |
| Proceed with Function App deployment? | Press Enter to confirm. |

A Flex or Premium Function App deploy can take several minutes with little console output while Kudu unpacks the package — this is normal, don't cancel.

### Step 4 — Verify

See the [Verification](#verification) section.

---

## Re-deployment / Reusing an Existing App Registration

If you already have an App Registration from a previous deployment (e.g., re-running after a failure, or sharing one App Reg):

When prompted *"How do you want to handle the App Registration?"*, choose **option 2 — Use an existing App Registration** (or pass `-AppId`).

The script will:

1. Look up the App Registration by Client ID.
2. Ensure the required WindowsDefenderATP + Graph application permissions are present (adds any missing ones).
3. Ask whether to paste your existing client secret or mint a fresh one.
4. Verify admin consent is already granted (or run the consent step if not).
5. Continue with the Function App deployment as normal.

You can also run one phase at a time with the skip flags:

```powershell
# Re-run only the Function App phase, reusing an existing App Reg
./Deploy-VMRayMDOConnector.ps1 -AppId "abc1234-..." -SkipAppReg

# Re-run only the App Registration phase
./Deploy-VMRayMDOConnector.ps1 -SkipFunctionApp
```

The script is idempotent, and includes safeguards for same-RG re-deploys (it pre-clears the stale storage role assignment and the leftover `WaitSection` deployment script that would otherwise conflict).

---

## App Registration Permissions (for reference)

The script adds these **application** permissions automatically. Listed here so you can verify them in Entra ID → App registrations → your app → API permissions.

### WindowsDefenderATP

| Permission | Why |
|---|---|
| `Alert.ReadWrite.All` | Retrieve alerts and enrich them with sample information |
| `Ti.ReadWrite.All` | Retrieve and submit indicators |

### Microsoft Graph

| Permission | Why |
|---|---|
| `SecurityAlert.ReadWrite.All` | Read and write all security alerts |
| `SecurityIncident.ReadWrite.All` | Read and write all security incidents |
| `ThreatHunting.Read.All` | Run hunting queries (to locate URLs related to an email) |
| `Mail.Read` | Read mail (to fetch User-Reported-Phishing attachments) |

---

## Verification

The connector is a **time-triggered poller** — once deployed, it starts fetching Defender for O365 alerts on its polling interval automatically. There is nothing to "turn on."

To confirm it's working end-to-end:

1. In the Azure Portal, open the Function App whose name starts with `vmraydefendero365`.
2. Under **Functions**, choose **VMRay_O365** → **Invocations and more** → the **Invocations** tab.
3. Find an execution by start time and review its logs — you should see alerts being fetched, URLs/attachments extracted, and samples submitted to VMRay.
4. Open your VMRay portal (e.g., `https://us.cloud.vmray.com`) → **Submissions**. New submissions should appear as alerts are processed.
5. Back in Defender, the processed alert should carry a VMRay enrichment comment (and, if configured, incident comments/tags and Defender indicators).

If an alert has no URL, or the function errors, the alert is annotated accordingly — useful for debugging.

---

## Troubleshooting

### Consent verification didn't see all permissions granted

**What's happening:** After Accept, Microsoft's grant database takes 10-90 seconds (occasionally longer) to propagate to the Graph API the script uses to verify. The script checks immediately, then retries up to 90 seconds.

**What to do:** the script offers a recovery menu:

1. **Wait another 90s and re-check** — the most common fix; propagation is often just slow.
2. **Re-open the consent URL** — if the first Accept click may not have registered (try an InPrivate/Incognito window).
3. **I've confirmed consent in the Portal — continue as granted** — if you can see the green checkmarks under Entra ID → App registrations → your app → API permissions, but Graph hasn't caught up.
4. **Skip** — defer and forward the URL to an admin later.

### A permission shows "not found" at Phase 1

**Symptom:** a yellow *"WARNING: '<permission>' not found on Microsoft Graph / WindowsDefenderATP. It will be skipped."*

**Cause:** the script resolves each permission's GUID from the resource service principal's published app-roles at runtime. If Microsoft renamed a role value, or the resource SP isn't present in your tenant, it's skipped rather than failing the whole run.

**Fix:** verify the missing permission manually in Entra ID → App registrations → API permissions, and grant admin consent for it.

### Function App deployment fails with "internal server error"

**Symptom:** the ARM deployment fails, and the failed resource is the code-push extension (`onedeploy` on Flex, `zipdeploy` on Premium).

**Cause:** the extension polls Kudu synchronously with a fixed timeout. On a slow deploy Kudu keeps working in the background but the extension reports a `500`. It's usually transient.

**Fix:** re-run the deployment. It's idempotent, and because the infrastructure already exists the retry is faster. If it fails again on the *same* resource, check the deployment's operation details for the real inner error.

### Managed identity replication ("PrincipalNotFound")

**What's happening:** on a same-RG re-deploy, ARM reaches the storage role assignment before the Function App's new managed identity has replicated to Entra ID.

**What the script does:** it retries the Function App deployment up to 3 times, waiting 60s between attempts for replication to catch up. Usually no action needed.

### Function App base name rejected

**Symptom:** *"Must be fewer than 20 characters; letters, numbers and hyphens only."*

**Cause:** the base name plus the appended uniqueness hash must stay within Azure's limits. Choose a shorter name.

### Multiple App Registrations with the same name

The script warns if an App Registration with your chosen display name already exists and lets you either reuse the name or enter a different one — so previous test deployments won't silently create duplicates.

---

## Summary — Comparison with the Original (Manual) Flow

| Step | Original (manual portal flow) | New (script-driven) |
|---|---|---|
| App Registration + permissions + secret | ~20 portal clicks | Automated |
| Admin consent | Manual click | Auto (or manual click, unavoidable) |
| Function App deployment | Portal "Deploy to Azure" + fill ~30 fields | Auto via script (essentials prompted, rest defaulted) |
| Storage configuration | (Managed identity — nothing to do) | (Managed identity — nothing to do) |
| **Total manual interactions** | ~25+ clicks across multiple pages | **1-2 actions** (1 PowerShell command + at most 1 consent click) |

The single-command deployment is the recommended path for all new installations. The legacy step-by-step guide in the original `Readme.md` remains available for reference.
