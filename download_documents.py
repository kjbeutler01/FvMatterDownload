#!/usr/bin/env python3
"""filevine_download_documents.py

Download all documents from a Filevine project’s Docs section via CLI.

Features
--------
* Supports both interactive prompts and command-line arguments (via argparse).
* Fallback to environment variables for secrets (FILEVINE_PAT, FILEVINE_CLIENT_ID, FILEVINE_CLIENT_SECRET).
* Configurable Filevine environment (US or CA), project ID, and download directory.
* Authenticates with PAT to obtain a bearer token.
* Retrieves User ID and Org ID.
* Robust pagination handling with explicit list detection.
* Retries on transient HTTP errors.
* Sanitizes filenames and appends document ID to ensure uniqueness.
* Optional progress bar via tqdm.
* Uses Python logging for verbosity control.

Dependencies: requests, tqdm
Install: pip install requests tqdm

Usage:
  python3 filevine_download_documents.py --project-id 12345 --env US --download-dir downloads
  export FILEVINE_PAT=... FILEVINE_CLIENT_ID=... FILEVINE_CLIENT_SECRET=...
  python3 filevine_download_documents.py --project-id 12345
"""
import os
import sys
import re
import json
import argparse
import logging
import getpass
from typing import Iterator, Tuple, Dict, Any, List
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
from tqdm import tqdm

# Constants
IDENTITY_URL = "https://identity.filevine.com/connect/token"
UTIL_URL = "https://api.filevineapp.com/fv-app/v2/utils/GetUserOrgsWithToken"
SCOPES = (
    "fv.api.gateway.access tenant "
    "filevine.v2.api.* openid email fv.auth.tenant.read"
)
USER_AGENT = "FilevineDocsDownloader/2.0"
DEFAULT_PAGE_SIZE = 50


def configure_session() -> requests.Session:
    """Create a requests.Session with retry logic."""
    session = requests.Session()
    retries = Retry(
        total=3,
        backoff_factor=0.3,
        status_forcelist=[429, 500, 502, 503, 504],
        allowed_methods=["GET", "POST"],
    )
    adapter = HTTPAdapter(max_retries=retries)
    session.mount("https://", adapter)
    session.mount("http://", adapter)
    session.headers.update({"User-Agent": USER_AGENT})
    return session


def prompt_secret(prompt_text: str) -> str:
    return getpass.getpass(prompt_text).strip()


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Download all documents from a Filevine project."
    )
    parser.add_argument(
        "--env", choices=["US", "CA"], default=os.getenv("FILEVINE_ENV", "US"),
        help="Filevine environment (US or CA)."
    )
    parser.add_argument(
        "--project-id", required=True,
        help="ID of the Filevine project to download docs from."
    )
    parser.add_argument(
        "--download-dir", default="downloads",
        help="Directory to store downloaded files."
    )
    parser.add_argument(
        "--pat", default=os.getenv("FILEVINE_PAT"),
        help="Personal Access Token (or set FILEVINE_PAT)."
    )
    parser.add_argument(
        "--client-id", default=os.getenv("FILEVINE_CLIENT_ID"),
        help="Client ID (or set FILEVINE_CLIENT_ID)."
    )
    parser.add_argument(
        "--client-secret", default=os.getenv("FILEVINE_CLIENT_SECRET"),
        help="Client Secret (or set FILEVINE_CLIENT_SECRET)."
    )
    parser.add_argument(
        "--verbose", action="store_true", help="Enable debug logging."
    )
    return parser.parse_args()


def get_bearer_token(
    session: requests.Session, pat: str, client_id: str, client_secret: str
) -> str:
    """Exchange a PAT for a short‑lived bearer token."""
    data = {
        "token": pat,
        "grant_type": "personal_access_token",
        "scope": SCOPES,
        "client_id": client_id,
        "client_secret": client_secret,
    }
    resp = session.post(IDENTITY_URL, data=data)
    resp.raise_for_status()
    return resp.json()["access_token"]


def get_user_org_ids(
    session: requests.Session, access_token: str
) -> Tuple[str, str]:
    """Fetch the User ID and Org ID via the gateway utility endpoint."""
    resp = session.post(
        UTIL_URL,
        headers={"Authorization": f"Bearer {access_token}"},
    )
    resp.raise_for_status()
    data = resp.json()
    return data["userId"], data["orgId"]


def list_documents(
    session: requests.Session,
    base_url: str,
    access_token: str,
    user_id: str,
    org_id: str,
    project_id: str,
) -> List[Dict[str, Any]]:
    """Return all document records for the project, handling pagination."""
    headers = {
        "Authorization": f"Bearer {access_token}",
        "x-fv-orgid": org_id,
        "x-fv-userid": user_id,
    }
    docs: List[Dict[str, Any]] = []
    page = 1
    next_token = None
    while True:
        # Request folder path information so downloaded files can be organized
        # into the same structure they have in Filevine. Different API versions
        # may expose this field under different names, so request both.
        params: Dict[str, Any] = {
            "fields": "id,title,fileName,folderPath,path"
        }
        if next_token:
            params["pageToken"] = next_token
        else:
            params["page"] = page

        url = f"{base_url}/core/projects/{project_id}/documents"
        resp = session.get(url, headers=headers, params=params)
        resp.raise_for_status()
        data = resp.json()

        # Extract list safely
        candidate = (
            data.get("projectDocuments")
            or data.get("items")
            or data.get("documents")
        )
        if isinstance(candidate, list):
            page_docs = candidate
        else:
            logging.debug("Unexpected response format, skipping page %s", page)
            break

        if not page_docs:
            break
        docs.extend(page_docs)

        next_token = data.get("nextPageToken") or data.get("pageToken")
        has_more = data.get("hasMore") or data.get("hasNextPage")
        if not next_token and not has_more:
            break
        page += 1

    return docs


def sanitize_filename(title: str, doc_id: str) -> str:
    safe = "".join(c for c in title if c not in '\\/:*?"<>|').strip()
    if not safe:
        safe = f"document_{doc_id}"
    return f"{safe}_{doc_id}"


def download_document(
    session: requests.Session,
    base_url: str,
    headers: Dict[str, str],
    doc: Dict[str, Any],
    dest_dir: str,
) -> None:
    """Download a single document file (latest version) by its ID."""
    doc_id = str(doc.get("id") or doc.get("documentId"))
    filename = doc.get("title") or doc.get("fileName") or ""

    # Determine the folder path from the document metadata if available. The
    # API may provide the folder hierarchy as a string ("folderPath" or "path")
    # or as a list of folder names. Normalize to a string separated by '/'.
    folder_path = doc.get("folderPath") or doc.get("path") or ""
    if isinstance(folder_path, list):
        folder_path = "/".join(str(p) for p in folder_path)
    folder_path = str(folder_path).strip("/")
    dest_subdir = os.path.join(dest_dir, folder_path) if folder_path else dest_dir
    os.makedirs(dest_subdir, exist_ok=True)

    safe_name = sanitize_filename(filename, doc_id)
    filepath = os.path.join(dest_subdir, safe_name)

    url = f"{base_url}/core/documents/{doc_id}/file"
    with session.get(url, headers=headers, stream=True) as resp:
        resp.raise_for_status()
        with open(filepath, "wb") as f:
            for chunk in resp.iter_content(chunk_size=8192):
                if chunk:
                    f.write(chunk)
    logging.info("Downloaded: %s", safe_name)


def main():
    args = parse_args()
    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s %(levelname)s: %(message)s",
    )

    # Validate project ID
    if not re.match(r"^\d+$|^[0-9a-fA-F-]{36}$", args.project_id):
        logging.error("Invalid project ID format: %s", args.project_id)
        sys.exit(1)

    # Resolve secrets
    pat = args.pat or prompt_secret("Personal Access Token (PAT): ")
    client_id = args.client_id or input("Client ID: ").strip()
    client_secret = args.client_secret or prompt_secret("Client Secret: ")
    if not (pat and client_id and client_secret):
        logging.error("PAT, Client ID, and Client Secret are required.")
        sys.exit(1)

    # Prepare environment
    env = args.env.upper()
    base_url = "https://api.filevine.io" if env == "US" else "https://api.filevine.ca"
    os.makedirs(args.download_dir, exist_ok=True)

    session = configure_session()
    logging.info("Authenticating to %s environment…", env)
    try:
        token = get_bearer_token(session, pat, client_id, client_secret)
    except requests.HTTPError as e:
        logging.error("Authentication failed: %s", e)
        sys.exit(1)

    try:
        user_id, org_id = get_user_org_ids(session, token)
    except requests.HTTPError as e:
        logging.error("Failed to retrieve user/org IDs: %s", e)
        sys.exit(1)

    logging.info("Org ID: %s, User ID: %s", org_id, user_id)
    logging.info("Fetching document list…")
    try:
        docs = list_documents(session, base_url, token, user_id, org_id, args.project_id)
    except requests.HTTPError as e:
        logging.error("Error listing documents: %s", e)
        sys.exit(1)

    logging.info("Found %d documents. Downloading to '%s'…", len(docs), args.download_dir)
    headers = {"Authorization": f"Bearer {token}", "x-fv-orgid": org_id, "x-fv-userid": user_id}
    for doc in tqdm(docs, desc="Downloading docs", unit="doc"):
        try:
            download_document(session, base_url, headers, doc, args.download_dir)
        except Exception as e:
            logging.error("Failed to download %s: %s", doc.get("id"), e)

    logging.info("Completed. %d documents saved.", len(docs))


if __name__ == "__main__":
    main()
