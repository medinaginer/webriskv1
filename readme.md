# GCP API Snippets and Authentication

This README contains useful code snippets for working with Google Cloud Platform (GCP) APIs using Python, focusing on authentication, lookup, and update operations.

## Web Risk API
The Web Risk API is a Google Cloud service that lets you check URLs against Google's constantly updated lists of unsafe web resources. These resources include social engineering sites (phishing and deceptive sites) and sites that host malware or unwanted software.

## Application Default Credentials

GCP uses Application Default Credentials (ADC) for authentication. To use ADC:

1. Install the Google Cloud SDK
2. Run `gcloud auth application-default login`
3. set the client Quota gcloud auth application-default set-quota-project PROJECT_ID 