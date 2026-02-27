#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import base64
import hashlib
import logging
import secrets
import time
import datetime as dt
from typing import List, Optional, Dict, Any, Tuple, Union
import xml.etree.ElementTree as ET

import httpx
from fastapi import FastAPI, HTTPException, UploadFile, File, Form
from pydantic import BaseModel

from cryptography import x509
from cryptography.hazmat.primitives import hashes, padding as sym_padding
from cryptography.hazmat.primitives.asymmetric import padding as asy_padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

DEFAULT_API_BASE = "https://api-test.ksef.mf.gov.pl/v2"

AUTH_POLL_TIMEOUT_SEC = 40
AUTH_POLL_INTERVAL_SEC = 1.0

HTTP_TIMEOUT = httpx.Timeout(60.0, connect=30.0)

STATUS_POLL_INTERVAL_SEC = 2.0
MAX_WAIT_SECONDS = 600

UPO_POLL_TIMEOUT_SEC = 15
UPO_POLL_INTERVAL_SEC = 1.0

app = FastAPI(title="KSeF FastAPI Gateway", version="1.5.2")

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("ksef")

LAST_BY_NIP: Dict[str, Dict[str, str]] = {}
EE_INDEX: Dict[str, Dict[str, str]] = {}


# ============================================================
# UTILS
# ============================================================

def b64e(b: bytes) -> str:
    return base64.b64encode(b).decode("ascii")


def b64d(s: str) -> bytes:
    return base64.b64decode(s.encode("ascii"))


def sha256_b64(data: bytes) -> str:
    return b64e(hashlib.sha256(data).digest())


def to_unix_ms(ts: Any) -> int:
    if isinstance(ts, int):
        return ts
    if isinstance(ts, float):
        return int(ts)
    if isinstance(ts, str):
        s = ts.strip()
        if s.isdigit():
            return int(s)
        if s.endswith("Z"):
            s = s[:-1] + "+00:00"
        d = dt.datetime.fromisoformat(s)
        return int(d.timestamp() * 1000)
    raise ValueError("Bad timestamp")


def normalize_xml(text: str) -> bytes:
    text = text.lstrip("\ufeff")
    text = text.replace("\r\n", "\n").replace("\r", "\n")
    text = text.rstrip("\n")
    return text.encode("utf-8")


def make_client(api_base: str) -> httpx.Client:
    return httpx.Client(
        base_url=api_base,
        timeout=HTTP_TIMEOUT,
        headers={"User-Agent": f"ksef-fastapi-gateway/{app.version}"},
    )


def http_json_or_raise(r: httpx.Response, where: str) -> Union[Dict[str, Any], List[Any]]:
    if r.status_code >= 400:
        raise HTTPException(status_code=502, detail=f"{where} failed: {r.status_code} {r.text}")
    try:
        return r.json()
    except Exception:
        raise HTTPException(status_code=502, detail=f"{where} invalid JSON: {r.text}")


def pick_cert(certs: List[dict], usage: str) -> dict:
    for c in certs:
        u = c.get("usage") or []
        if isinstance(u, str):
            u = [u]
        if usage in u:
            return c
    raise RuntimeError(f"No cert usage={usage}")


def rsa_encrypt(cert_b64: str, plaintext: bytes) -> bytes:
    cert = x509.load_der_x509_certificate(b64d(cert_b64))
    return cert.public_key().encrypt(
        plaintext,
        asy_padding.OAEP(
            mgf=asy_padding.MGF1(hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )


def aes_encrypt(plain: bytes, key: bytes, iv: bytes) -> bytes:
    padder = sym_padding.PKCS7(128).padder()
    padded = padder.update(plain) + padder.finalize()
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    enc = cipher.encryptor()
    return enc.update(padded) + enc.finalize()


def extract_nip_from_ksef_token(ksef_token: str) -> str:
    parts = ksef_token.split("|")
    for p in parts:
        if p.startswith("nip-"):
            nip = p.replace("nip-", "").strip()
            if nip.isdigit():
                return nip
    raise HTTPException(400, "Invalid KSeF token format (expected ...|nip-XXXXXXXXXX|...)")


# ============================================================
# UPO PARSER -> JSON (minimal)
# ============================================================

def xml_find_text_any_ns(root: ET.Element, local_name: str) -> Optional[str]:
    for el in root.iter():
        tag = el.tag
        if isinstance(tag, str):
            if tag.endswith("}" + local_name) or tag == local_name:
                if el.text and el.text.strip():
                    return el.text.strip()
    return None


def parse_upo_xml_to_json(upo_xml: bytes) -> Dict[str, Any]:
    try:
        root = ET.fromstring(upo_xml)
        out = {
            "root_tag": root.tag,
            "parsed": True,
            "ksef_reference": (
                xml_find_text_any_ns(root, "NrKSeF")
                or xml_find_text_any_ns(root, "NrKSeFDokumentu")
            ),
            "invoice_number": (
                xml_find_text_any_ns(root, "P_2")
                or xml_find_text_any_ns(root, "NumerFaktury")
            ),
            "issue_date": (
                xml_find_text_any_ns(root, "P_1")
                or xml_find_text_any_ns(root, "DataWystawienia")
            ),
            "received_at": (
                xml_find_text_any_ns(root, "DataPrzyjecia")
                or xml_find_text_any_ns(root, "AcceptanceDate")
            ),
        }
        return {k: v for k, v in out.items() if v not in (None, "", [])}
    except Exception as e:
        return {"parsed": False, "error": str(e)}


# ============================================================
# MODELS
# ============================================================

class SubmitResponse(BaseModel):
    so_reference: str
    ee_reference: str
    upo_reference: Optional[str] = None
    upo_xml_base64: Optional[str] = None
    upo_json: Optional[Dict[str, Any]] = None
    failed_invoices: Optional[dict] = None
    failed_invoice_for_ee: Optional[Dict[str, Any]] = None
    session_json: Optional[Dict[str, Any]] = None
    ee_status: Optional[Dict[str, Any]] = None


class LastStatusResponse(BaseModel):
    nip: str
    so_reference: str
    ee_reference: str
    ee_status: Dict[str, Any]
    session_json: Optional[Dict[str, Any]] = None
    failed_invoice_for_ee: Optional[Dict[str, Any]] = None
    failed_invoices: Optional[dict] = None


class EeStatusResponse(BaseModel):
    ee_reference: str
    so_reference: str
    nip: str
    ee_status: Dict[str, Any]
    session_json: Optional[Dict[str, Any]] = None
    failed_invoice_for_ee: Optional[Dict[str, Any]] = None
    failed_invoices: Optional[dict] = None


class InvoicesListRequest(BaseModel):
    ksef_token: str
    api_base: str = DEFAULT_API_BASE
    query: Dict[str, Any]
    page_size: int = 50
    page_offset: int = 0
    include_xml: bool = False
    max_xml: int = 10


class InvoicesListResponse(BaseModel):
    api_base: str
    page_size: int
    page_offset: int
    items: List[Dict[str, Any]]
    has_more: Optional[bool] = None
    ksef_response: Dict[str, Any]
    xml_by_ksef_number: Optional[Dict[str, str]] = None


# ============================================================
# KSeF HELPERS
# ============================================================

def poll_auth_success(client: httpx.Client, auth_ref: str, auth_token: str) -> None:
    deadline = time.time() + AUTH_POLL_TIMEOUT_SEC
    last = None
    while time.time() < deadline:
        r = client.get(
            f"/auth/{auth_ref}",
            headers={"Authorization": f"Bearer {auth_token}", "Accept": "application/json"},
        )
        last = http_json_or_raise(r, f"GET /auth/{auth_ref}")
        if not isinstance(last, dict):
            raise HTTPException(status_code=502, detail={"message": "Bad auth status payload type", "payload": last})

        code = (last.get("status") or {}).get("code")
        if code == 200:
            return
        if isinstance(code, int) and code >= 400:
            raise HTTPException(status_code=401, detail={"message": "Auth failed", "auth_status": last})
        time.sleep(AUTH_POLL_INTERVAL_SEC)

    raise HTTPException(status_code=504, detail={"message": "Auth timeout", "last": last})


def get_failed_invoices(client: httpx.Client, access_token: str, so: str) -> dict:
    r = client.get(
        f"/sessions/{so}/invoices/failed?pageSize=1000",
        headers={"Authorization": f"Bearer {access_token}", "Accept": "application/json"},
    )
    j = http_json_or_raise(r, f"GET /sessions/{so}/invoices/failed")
    if not isinstance(j, dict):
        return {"raw": j}
    return j


def get_session_json(client: httpx.Client, access_token: str, so: str) -> Dict[str, Any]:
    r = client.get(
        f"/sessions/{so}",
        headers={"Authorization": f"Bearer {access_token}", "Accept": "application/json"},
    )
    j = http_json_or_raise(r, f"GET /sessions/{so}")
    if not isinstance(j, dict):
        raise HTTPException(status_code=502, detail={"message": "Bad session payload type", "payload": j})
    return j


def wait_for_upo_reference(
    client: httpx.Client,
    access_token: str,
    so: str,
    timeout_sec: int = UPO_POLL_TIMEOUT_SEC,
    interval_sec: float = UPO_POLL_INTERVAL_SEC,
) -> Tuple[str, Dict[str, Any]]:
    deadline = time.time() + timeout_sec
    last: Optional[Dict[str, Any]] = None

    while time.time() < deadline:
        last = get_session_json(client, access_token, so)

        pages = (last.get("upo") or {}).get("pages") or []
        if isinstance(pages, list) and pages and isinstance(pages[0], dict):
            upo_ref = pages[0].get("referenceNumber")
            if upo_ref:
                return str(upo_ref), last

        upo_ref2 = last.get("upoReference")
        if upo_ref2:
            return str(upo_ref2), last

        time.sleep(interval_sec)

    raise HTTPException(status_code=504, detail={"message": "UPO timeout", "session": so, "last": last})


def download_upo_xml(client: httpx.Client, access_token: str, so: str, upo_ref: str) -> bytes:
    r = client.get(
        f"/sessions/{so}/upo/{upo_ref}",
        headers={"Authorization": f"Bearer {access_token}", "Accept": "application/xml"},
    )
    if r.status_code >= 400:
        raise HTTPException(status_code=502, detail=f"GET /sessions/{so}/upo/{upo_ref} failed: {r.status_code} {r.text}")
    return r.content


def query_invoices_metadata(
    client: httpx.Client,
    access_token: str,
    query: Dict[str, Any],
    page_size: int,
    page_offset: int,
) -> Dict[str, Any]:
    payload = dict(query or {})
    payload.setdefault("pageSize", page_size)
    payload.setdefault("pageOffset", page_offset)

    r = client.post(
        "/invoices/query/metadata",
        headers={"Authorization": f"Bearer {access_token}", "Accept": "application/json"},
        json=payload,
    )
    j = http_json_or_raise(r, "POST /invoices/query/metadata")
    if not isinstance(j, dict):
        raise HTTPException(status_code=502, detail={"message": "Bad metadata payload type", "payload": j})
    return j


def download_invoice_by_ksef_number(
    client: httpx.Client,
    access_token: str,
    ksef_number: str,
) -> bytes:
    r = client.get(
        f"/invoices/ksef/{ksef_number}",
        headers={"Authorization": f"Bearer {access_token}", "Accept": "application/octet-stream"},
    )
    if r.status_code >= 400:
        raise HTTPException(status_code=502, detail=f"GET /invoices/ksef/{ksef_number} failed: {r.status_code} {r.text}")
    return r.content


def find_failed_invoice_by_ee(failed: Any, ee_reference: str) -> Optional[Dict[str, Any]]:
    invoices = None
    if isinstance(failed, dict):
        invoices = failed.get("invoices") or failed.get("items") or failed.get("entries") or failed.get("data")
    elif isinstance(failed, list):
        invoices = failed

    if not isinstance(invoices, list):
        return None

    for inv in invoices:
        if isinstance(inv, dict) and inv.get("referenceNumber") == ee_reference:
            return inv

    return None


def build_ee_status_from_session_and_failed(
    ee_reference: str,
    session_json: Optional[Dict[str, Any]],
    failed_invoice: Optional[Dict[str, Any]],
) -> Dict[str, Any]:
    if failed_invoice:
        st = failed_invoice.get("status") or {}
        code = st.get("code")
        return {"state": "FAILED", "ee_reference": ee_reference, "ksef_status": st, "ksef_code": code}

    if not isinstance(session_json, dict):
        return {"state": "PENDING", "ee_reference": ee_reference}

    st = session_json.get("status") or {}
    session_code = st.get("code")
    invoice_count = session_json.get("invoiceCount")
    ok_count = session_json.get("successfulInvoiceCount")

    if session_code == 200:
        if isinstance(invoice_count, int) and isinstance(ok_count, int):
            if invoice_count > 0 and ok_count >= invoice_count:
                return {
                    "state": "SUCCESS",
                    "ee_reference": ee_reference,
                    "session_status": st,
                    "invoiceCount": invoice_count,
                    "successfulInvoiceCount": ok_count,
                }
        pages = (session_json.get("upo") or {}).get("pages") or []
        if isinstance(pages, list) and len(pages) > 0:
            return {"state": "SUCCESS", "ee_reference": ee_reference, "session_status": st}

    if isinstance(session_code, int) and session_code >= 400:
        return {"state": "FAILED", "ee_reference": ee_reference, "session_status": st}

    return {"state": "PENDING", "ee_reference": ee_reference, "session_status": st}


def authenticate_get_access_token(client: httpx.Client, ksef_token: str, nip: str) -> str:
    # 1) challenge
    ch_any = http_json_or_raise(client.post("/auth/challenge", headers={"Accept": "application/json"}), "POST /auth/challenge")
    if not isinstance(ch_any, dict):
        raise HTTPException(status_code=502, detail={"message": "Bad /auth/challenge payload type", "payload": ch_any})

    challenge = ch_any.get("challenge")
    ts_ms = to_unix_ms(ch_any.get("timestamp"))
    if not challenge:
        raise HTTPException(status_code=502, detail={"message": "No challenge in /auth/challenge", "resp": ch_any})

    # 2) certs (moze byc listą)
    certs_any = http_json_or_raise(client.get("/security/public-key-certificates", headers={"Accept": "application/json"}), "GET /security/public-key-certificates")
    if isinstance(certs_any, list):
        cert_list = certs_any
    elif isinstance(certs_any, dict):
        cert_list = certs_any.get("certificates") or certs_any.get("items") or certs_any.get("data") or []
    else:
        cert_list = []

    if not isinstance(cert_list, list) or not cert_list:
        raise HTTPException(status_code=502, detail={"message": "No certificates returned", "resp": certs_any})

    try:
        cert = pick_cert([c for c in cert_list if isinstance(c, dict)], "encryption")
    except Exception:
        cert = cert_list[0] if isinstance(cert_list[0], dict) else None

    if not isinstance(cert, dict):
        raise HTTPException(status_code=502, detail={"message": "Bad certificate entry type", "entry": cert})

    cert_b64 = cert.get("certificate") or cert.get("certificateDer") or cert.get("cert")
    if not cert_b64:
        raise HTTPException(status_code=502, detail={"message": "No certificate DER in response", "resp": certs_any})

    # 3) RSA OAEP: token|timestamp
    plaintext = f"{ksef_token}|{ts_ms}".encode("utf-8")
    encrypted = rsa_encrypt(cert_b64, plaintext)

    # 4) POST /auth/ksef-token  <-- TU BYL BLAD: MUSI BYC contextIdentifier
    body = {
        "challenge": challenge,
        "contextIdentifier": {"type": "Nip", "value": nip},
        "encryptedToken": b64e(encrypted),
    }
    r = client.post("/auth/ksef-token", json=body, headers={"Accept": "application/json"})
    auth_resp_any = http_json_or_raise(r, "POST /auth/ksef-token")
    if not isinstance(auth_resp_any, dict):
        raise HTTPException(status_code=502, detail={"message": "Bad /auth/ksef-token payload type", "payload": auth_resp_any})

    auth_ref = auth_resp_any.get("referenceNumber") or (auth_resp_any.get("authenticationToken") or {}).get("referenceNumber")
    auth_token = (auth_resp_any.get("authenticationToken") or {}).get("token")

    if not auth_ref or not auth_token:
        raise HTTPException(status_code=502, detail={"message": "Bad /auth/ksef-token response", "resp": auth_resp_any})

    # 5) poll /auth/{ref}
    poll_auth_success(client, str(auth_ref), str(auth_token))

    # 6) redeem
    rr = client.post("/auth/token/redeem", headers={"Authorization": f"Bearer {auth_token}", "Accept": "application/json"})
    redeem_any = http_json_or_raise(rr, "POST /auth/token/redeem")
    if not isinstance(redeem_any, dict):
        raise HTTPException(status_code=502, detail={"message": "Bad redeem payload type", "payload": redeem_any})

    access_token = (redeem_any.get("accessToken") or {}).get("token") or redeem_any.get("token")
    if not access_token:
        raise HTTPException(status_code=502, detail={"message": "No accessToken in redeem", "resp": redeem_any})
    return str(access_token)


# ============================================================
# ENDPOINT: submit invoice
# ============================================================

@app.post("/invoice/submit", response_model=SubmitResponse)
def submit_invoice(
    ksef_token: str = Form(...),
    file: UploadFile = File(...),
    api_base: Optional[str] = Form(None),
):
    api_base = api_base or DEFAULT_API_BASE
    nip = extract_nip_from_ksef_token(ksef_token)

    xml_text = file.file.read().decode("utf-8", errors="strict")
    xml_bytes = normalize_xml(xml_text)

    with make_client(api_base) as client:
        access_token = authenticate_get_access_token(client, ksef_token, nip)

        r = client.post("/sessions/online", headers={"Authorization": f"Bearer {access_token}", "Accept": "application/json"}, json={})
        so_open_any = http_json_or_raise(r, "POST /sessions/online")
        if not isinstance(so_open_any, dict):
            raise HTTPException(status_code=502, detail={"message": "Bad /sessions/online payload type", "payload": so_open_any})
        so = so_open_any.get("referenceNumber")
        if not so:
            raise HTTPException(status_code=502, detail={"message": "No so_reference in /sessions/online", "resp": so_open_any})

        aes_key = secrets.token_bytes(32)
        aes_iv = secrets.token_bytes(16)
        encrypted_invoice = aes_encrypt(xml_bytes, aes_key, aes_iv)

        inv_body = {
            "invoiceHash": {"hashSHA": sha256_b64(xml_bytes)},
            "invoicePayload": {
                "type": "xml",
                "encryptedInvoice": b64e(encrypted_invoice),
                "encryption": {"type": "AES", "mode": "CBC", "key": b64e(aes_key), "iv": b64e(aes_iv)},
            },
        }
        r = client.post(f"/sessions/online/{so}/invoices", headers={"Authorization": f"Bearer {access_token}", "Accept": "application/json"}, json=inv_body)
        inv_send_any = http_json_or_raise(r, f"POST /sessions/online/{so}/invoices")
        if not isinstance(inv_send_any, dict):
            raise HTTPException(status_code=502, detail={"message": "Bad invoices payload type", "payload": inv_send_any})
        ee = inv_send_any.get("referenceNumber")
        if not ee:
            raise HTTPException(status_code=502, detail={"message": "No ee_reference in invoices response", "resp": inv_send_any})

        r = client.post(f"/sessions/online/{so}/close", headers={"Authorization": f"Bearer {access_token}", "Accept": "application/json"}, json={})
        _ = http_json_or_raise(r, f"POST /sessions/online/{so}/close")

        failed = get_failed_invoices(client, access_token, str(so))
        failed_invoice_for_ee = find_failed_invoice_by_ee(failed, str(ee))

        now_iso = dt.datetime.utcnow().replace(tzinfo=dt.timezone.utc).isoformat()
        LAST_BY_NIP[nip] = {"so": str(so), "ee": str(ee), "api_base": api_base, "updated_at": now_iso}
        EE_INDEX[str(ee)] = {"so": str(so), "nip": nip, "api_base": api_base, "updated_at": now_iso}

        if failed_invoice_for_ee:
            session_json = get_session_json(client, access_token, str(so))
            ee_status = build_ee_status_from_session_and_failed(str(ee), session_json, failed_invoice_for_ee)
            raise HTTPException(
                status_code=422,
                detail={
                    "message": "KSeF reported failed invoice(s) for this session - no UPO will be produced",
                    "so_reference": str(so),
                    "ee_reference": str(ee),
                    "failed_invoices": failed,
                    "failed_invoice_for_ee": failed_invoice_for_ee,
                    "session_json": session_json,
                    "ee_status": ee_status,
                },
            )

        try:
            upo_ref, session_json = wait_for_upo_reference(client, access_token, str(so), timeout_sec=UPO_POLL_TIMEOUT_SEC, interval_sec=UPO_POLL_INTERVAL_SEC)
        except HTTPException as e:
            if e.status_code == 504:
                session_json2 = None
                failed2 = None
                failed_invoice_for_ee2 = None
                try:
                    session_json2 = get_session_json(client, access_token, str(so))
                except Exception:
                    pass
                try:
                    failed2 = get_failed_invoices(client, access_token, str(so))
                    failed_invoice_for_ee2 = find_failed_invoice_by_ee(failed2, str(ee))
                except Exception:
                    pass

                ee_status2 = build_ee_status_from_session_and_failed(str(ee), session_json2, failed_invoice_for_ee2)
                raise HTTPException(
                    status_code=504,
                    detail={
                        "message": f"UPO not available within {UPO_POLL_TIMEOUT_SEC}s",
                        "so_reference": str(so),
                        "ee_reference": str(ee),
                        "session_json": session_json2,
                        "failed_invoices": failed2,
                        "failed_invoice_for_ee": failed_invoice_for_ee2,
                        "ee_status": ee_status2,
                    },
                )
            raise

        upo_xml = download_upo_xml(client, access_token, str(so), str(upo_ref))
        upo_json = parse_upo_xml_to_json(upo_xml)
        ee_status = build_ee_status_from_session_and_failed(str(ee), session_json, failed_invoice_for_ee)

        return SubmitResponse(
            so_reference=str(so),
            ee_reference=str(ee),
            upo_reference=str(upo_ref),
            upo_xml_base64=b64e(upo_xml),
            upo_json=upo_json,
            failed_invoices=failed,
            failed_invoice_for_ee=failed_invoice_for_ee,
            session_json=session_json,
            ee_status=ee_status,
        )


@app.post("/invoice/last/status", response_model=LastStatusResponse)
def last_status(ksef_token: str = Form(...), wait_seconds: int = Form(0), api_base: Optional[str] = Form(None)):
    api_base = api_base or DEFAULT_API_BASE
    nip = extract_nip_from_ksef_token(ksef_token)

    last = LAST_BY_NIP.get(nip)
    if not last:
        raise HTTPException(status_code=404, detail={"message": "No last invoice for this NIP (RAM is empty)", "nip": nip})

    so = last["so"]
    ee = last["ee"]
    api_base = last.get("api_base") or api_base

    wait_seconds = max(0, min(int(wait_seconds or 0), MAX_WAIT_SECONDS))

    with make_client(api_base) as client:
        access_token = authenticate_get_access_token(client, ksef_token, nip)

        deadline = time.time() + wait_seconds
        session_json = None
        failed = None
        failed_invoice_for_ee = None
        ee_status = {"state": "PENDING", "ee_reference": ee}

        while True:
            session_json = get_session_json(client, access_token, so)
            failed = get_failed_invoices(client, access_token, so)
            failed_invoice_for_ee = find_failed_invoice_by_ee(failed, ee)
            ee_status = build_ee_status_from_session_and_failed(ee, session_json, failed_invoice_for_ee)

            if ee_status.get("state") in ("SUCCESS", "FAILED"):
                break
            if time.time() >= deadline:
                break
            time.sleep(STATUS_POLL_INTERVAL_SEC)

        return LastStatusResponse(
            nip=nip,
            so_reference=so,
            ee_reference=ee,
            ee_status=ee_status,
            session_json=session_json,
            failed_invoice_for_ee=failed_invoice_for_ee,
            failed_invoices=failed,
        )


@app.get("/status/{ee_reference}", response_model=EeStatusResponse)
def status_by_ee_reference(ee_reference: str, ksef_token: str, wait_seconds: int = 0, api_base: Optional[str] = None):
    wait_seconds = max(0, min(int(wait_seconds or 0), MAX_WAIT_SECONDS))

    idx = EE_INDEX.get(ee_reference)
    if not idx:
        raise HTTPException(status_code=404, detail={"message": "Unknown ee_reference (not in gateway RAM index)", "ee_reference": ee_reference})

    nip = idx["nip"]
    so = idx["so"]
    api_base = api_base or idx.get("api_base") or DEFAULT_API_BASE

    with make_client(api_base) as client:
        access_token = authenticate_get_access_token(client, ksef_token, nip)

        deadline = time.time() + wait_seconds
        session_json = None
        failed = None
        failed_invoice_for_ee = None
        ee_status = {"state": "PENDING", "ee_reference": ee_reference}

        while True:
            session_json = get_session_json(client, access_token, so)
            failed = get_failed_invoices(client, access_token, so)
            failed_invoice_for_ee = find_failed_invoice_by_ee(failed, ee_reference)
            ee_status = build_ee_status_from_session_and_failed(ee_reference, session_json, failed_invoice_for_ee)

            if ee_status.get("state") in ("SUCCESS", "FAILED"):
                break
            if time.time() >= deadline:
                break
            time.sleep(STATUS_POLL_INTERVAL_SEC)

        return EeStatusResponse(
            ee_reference=ee_reference,
            so_reference=so,
            nip=nip,
            ee_status=ee_status,
            session_json=session_json,
            failed_invoice_for_ee=failed_invoice_for_ee,
            failed_invoices=failed,
        )


@app.post("/invoices/list", response_model=InvoicesListResponse)
def invoices_list(req: InvoicesListRequest):
    nip = extract_nip_from_ksef_token(req.ksef_token)
    api_base = req.api_base or DEFAULT_API_BASE

    page_size = max(1, min(int(req.page_size or 50), 1000))
    page_offset = max(0, int(req.page_offset or 0))

    include_xml = bool(req.include_xml)
    max_xml = max(0, min(int(req.max_xml or 0), 50))

    with make_client(api_base) as client:
        access_token = authenticate_get_access_token(client, req.ksef_token, nip)

        ksef_resp = query_invoices_metadata(client, access_token, req.query, page_size, page_offset)
        items = (ksef_resp.get("invoices") or ksef_resp.get("items") or ksef_resp.get("entries") or ksef_resp.get("data") or [])
        if not isinstance(items, list):
            items = []

        has_more = ksef_resp.get("hasMore")
        xml_by = None

        if include_xml and max_xml > 0:
            xml_by = {}
            for inv in items[:max_xml]:
                if not isinstance(inv, dict):
                    continue
                ksef_number = inv.get("ksefNumber") or inv.get("nrKSeF") or inv.get("NrKSeF") or inv.get("NrKSeFDokumentu")
                if not ksef_number:
                    continue
                xml_bytes = download_invoice_by_ksef_number(client, access_token, str(ksef_number))
                xml_by[str(ksef_number)] = b64e(xml_bytes)

        return InvoicesListResponse(
            api_base=api_base,
            page_size=page_size,
            page_offset=page_offset,
            items=items,
            has_more=has_more if isinstance(has_more, bool) else None,
            ksef_response=ksef_resp,
            xml_by_ksef_number=xml_by,
        )


@app.get("/health")
def health():
    return {"ok": True, "version": app.version}
