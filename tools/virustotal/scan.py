#!/usr/bin/env python3
"""Yeager VirusTotal Reference Scan Sidecar.

Submits release executables (.exe) to VirusTotal and polls results
bounded by an overall deadline.
"""

import datetime
import glob
import json
import os
import subprocess
import time
import urllib.error
import urllib.request
import uuid

KEY = os.environ.get("VT_API_KEY", "")
TAG = os.environ.get("RELEASE_TAG", "")
DEADLINE_SECONDS = 1200.0  # 20 minutes total deadline
start_time = time.time()
_last = 0.0


def throttle():
    global _last
    wait = 45.0 - (time.time() - _last)
    if wait > 0:
        time.sleep(wait)
    _last = time.time()


def iso_utc(ts):
    if not ts:
        return None
    try:
        return datetime.datetime.fromtimestamp(int(ts), datetime.timezone.utc).isoformat().replace("+00:00", "Z")
    except Exception:
        return None


def api_request(method, endpoint, headers=None, body=None):
    throttle()
    url = f"https://www.virustotal.com/api/v3{endpoint}"
    req_headers = {"x-apikey": KEY}
    if headers:
        req_headers.update(headers)
    req = urllib.request.Request(url, data=body, headers=req_headers, method=method)
    with urllib.request.urlopen(req) as resp:
        return json.load(resp)


def build_multipart(filename, file_bytes):
    boundary = f"----VTBoundary{uuid.uuid4().hex}"
    header = (
        f"--{boundary}\r\n"
        f'Content-Disposition: form-data; name="file"; filename="{filename}"\r\n'
        f"Content-Type: application/octet-stream\r\n\r\n"
    ).encode("utf-8")
    footer = f"\r\n--{boundary}--\r\n".encode("utf-8")
    body = header + file_bytes + footer
    content_type = f"multipart/form-data; boundary={boundary}"
    return body, content_type


def main():
    if not KEY:
        with open("vt.json", "w", encoding="utf-8") as fp:
            json.dump({"status": "skipped", "reason": "no VT_API_KEY"}, fp, indent=2)
        return

    out = {}
    pending_analyses = []

    # Scope: binary executables (.exe) only
    for f in sorted(glob.glob("dl/*.exe")):
        sha = subprocess.check_output(["sha256sum", f]).split()[0].decode()
        link = f"https://www.virustotal.com/gui/file/{sha}"
        fname = os.path.basename(f)

        if time.time() - start_time >= DEADLINE_SECONDS:
            out[fname] = {
                "sha256": sha,
                "link": link,
                "status": "not_submitted",
                "reason": "deadline_exceeded",
            }
            continue

        # Fast path: Check if file is already analyzed on VirusTotal
        try:
            finfo = api_request("GET", f"/files/{sha}")["data"]["attributes"]
            stats = finfo.get("last_analysis_stats")
            epoch = finfo.get("last_analysis_date")
            last_date = iso_utc(epoch) if epoch else None
            out[fname] = {
                "sha256": sha,
                "link": link,
                "status": "completed",
            }
            if last_date:
                out[fname]["last_analysis_date"] = last_date
            if stats:
                out[fname]["stats"] = stats
            print(f"File {fname} already analyzed on VirusTotal: {stats}")
            continue
        except urllib.error.HTTPError as e:
            if e.code != 404:
                # Other HTTP errors (e.g. 429 quota or 401 auth)
                out[fname] = {
                    "sha256": sha,
                    "link": link,
                    "status": "submit_failed",
                    "error": f"HTTP {e.code}: {e.reason}",
                }
                continue
        except Exception as e:
            out[fname] = {
                "sha256": sha,
                "link": link,
                "status": "submit_failed",
                "error": str(e),
            }
            continue

        # File not found on VT (404) -> Submit via multipart/form-data
        try:
            file_bytes = open(f, "rb").read()
            body, ctype = build_multipart(fname, file_bytes)
            res = api_request("POST", "/files", headers={"Content-Type": ctype}, body=body)
            aid = res["data"]["id"]
            out[fname] = {
                "sha256": sha,
                "link": link,
                "status": "pending",
            }
            pending_analyses.append((fname, sha, aid))
            print(f"Submitted {fname} to VirusTotal (analysis ID: {aid})")
        except Exception as e:
            out[fname] = {
                "sha256": sha,
                "link": link,
                "status": "submit_failed",
                "error": str(e),
            }

    # Polling loop bounded strictly by overall 20-minute job deadline
    while pending_analyses and (time.time() - start_time < DEADLINE_SECONDS):
        still_pending = []
        for fname, sha, aid in pending_analyses:
            if time.time() - start_time >= DEADLINE_SECONDS:
                still_pending.append((fname, sha, aid))
                continue

            try:
                d = api_request("GET", f"/analyses/{aid}")["data"]["attributes"]
                status = d.get("status")
            except Exception:
                still_pending.append((fname, sha, aid))
                continue

            if status == "completed":
                stats = None
                last_analysis_date = None
                try:
                    finfo = api_request("GET", f"/files/{sha}")["data"]["attributes"]
                    stats = finfo.get("last_analysis_stats")
                    epoch = finfo.get("last_analysis_date")
                    if epoch:
                        last_analysis_date = iso_utc(epoch)
                except Exception:
                    pass

                out[fname]["status"] = "completed"
                if last_analysis_date:
                    out[fname]["last_analysis_date"] = last_analysis_date
                if stats:
                    out[fname]["stats"] = stats
                print(f"Analysis completed for {fname}: {stats}")
            else:
                still_pending.append((fname, sha, aid))

        if len(still_pending) == len(pending_analyses):
            time.sleep(5)
        pending_analyses = still_pending

    payload = {
        "version": TAG,
        "scope": "executable_binaries",
        "scope_note": "Only executable binaries (.exe) are submitted for VirusTotal analysis; portable .zip is packaged from the release artifacts and integrity-verified via SHA256SUMS.txt.",
        "generated_at": datetime.datetime.now(datetime.timezone.utc).isoformat().replace("+00:00", "Z"),
        "results": out,
    }
    with open("vt.json", "w", encoding="utf-8") as fp:
        json.dump(payload, fp, indent=2)


if __name__ == "__main__":
    main()
