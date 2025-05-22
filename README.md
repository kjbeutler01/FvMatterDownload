# FvMatterDownload

A small command line tool for downloading all documents from a Filevine project.
The script `download_documents.py` authenticates with Filevine using a Personal
Access Token (PAT) and saves every document from the specified project to your
local machine.

## Requirements

- Python 3
- Packages listed in `requirements.txt`

Install the dependencies with:

```bash
pip install -r requirements.txt
```

## Authentication

The script needs a PAT, Client ID and Client Secret. These can be supplied as
command line flags or via environment variables:

- `FILEVINE_PAT`
- `FILEVINE_CLIENT_ID`
- `FILEVINE_CLIENT_SECRET`

If they are not provided, you will be prompted to enter them interactively.

## Usage

```bash
python3 download_documents.py --project-id <PROJECT_ID> [--env US|CA] \
    [--download-dir PATH]
```

Example using environment variables for credentials:

```bash
export FILEVINE_PAT=your_pat
export FILEVINE_CLIENT_ID=your_client_id
export FILEVINE_CLIENT_SECRET=your_client_secret
python3 download_documents.py --project-id 12345 --env US --download-dir ./docs
```

Run with `--verbose` to enable debug logging and see progress for each file. By
default files are downloaded to a `downloads` directory and have sanitized
filenames that include the document ID for uniqueness.

## Features

- Interactive or fully scripted use through CLI flags
- Handles pagination and retries failed requests
- Works with either the US or CA Filevine environment
- Optional progress bar using `tqdm`

All downloaded documents will be placed in the chosen directory.
