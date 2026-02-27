#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import base64
import hashlib
import logging
import secrets
import time
import datetime as dt
from typing import List, Optional, Dict, Any, Tuple
import xml.etree.ElementTree as ET

import httpx
from fastapi import FastAPI, HTTPException, UploadFile, File, Form
from pydantic import BaseModel

from cryptography import x509
from cryptography.hazmat.primitives import hashes, padding as sym_padding
from cryptography.hazmat.primitives.asymmetric import padding as asy_padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

DEFAULT_API_BASE = "https://api-test.ksef.mf.gov.pl/v2"

# --- timeouty logiczne (polling auth) ---
AUTH_POLL_TIMEOUT_SEC = 40
AUTH_POLL_INTERVAL_SEC = 1.0

# --- timeouty HTTP ---
HTTP_TIMEOUT = httpx.Timeout(60.0, connect=30.0)

# --- polling status endpoint ---
STATUS_POLL_INTERVAL_SEC = 2.0
MAX_WAIT_SECONDS = 600  # hard cap, zeby endpoint nie wisial wiecznie

app = FastAPI(title="KSeF Ultra Simple API", version="1.4.0")

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("ksef")

# ------------------------------------------------
# "ostatnia faktura" - stan w RAM (per NIP)
# LAST_BY_NIP[nip] = {"so": "...", "ee": "...", "api_base": "...", "updated_at": "...ISO..."}
# ------------------------------------------------
LAST_BY_NIP: Dict[str, Dict[str, str]] = {}


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
        headers={"User-Agent": "ksef-fastapi-gateway/1.4.0"},
    )


def http_json_or_raise(r: httpx.Response, where: str) -> Dict[str, Any]:
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
    """
    Minimalny parser UPO -> JSON.
    UPO ma namespace, więc szukamy po local-name.
    """
    try:
        root = ET.fromstring(upo_xml)

        out = {
            "root_tag": root.tag,
            "parsed": True,

            # część pól może nie istnieć w UPO zależnie od wersji
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
    return http_json_or_raise(r, f"GET /sessions/{so}/invoices/failed")


def get_session_json(client: httpx.Client, access_token: str, so: str) -> Dict[str, Any]:
    r = client.get(
        f"/sessions/{so}",
        headers={"Authorization": f"Bearer {access_token}", "Accept": "application/json"},
    )
    return http_json_or_raise(r, f"GET /sessions/{so}")


def wait_for_upo_reference(client: httpx.Client, access_token: str, so: str, timeout_sec: int = 180, interval_sec: float = 2.0) -> Tuple[str, Dict[str, Any]]:
    deadline = time.time() + timeout_sec
    last = None

    while time.time() < deadline:
        last = get_session_json(client, access_token, so)

        # wariant: upo.pages[0].referenceNumber (to masz w odpowiedzi)
        pages = (last.get("upo") or {}).get("pages") or []
        if isinstance(pages, list) and pages and isinstance(pages[0], dict):
            upo_ref = pages[0].get("referenceNumber")
            if upo_ref:
                return upo_ref, last

        # fallback: upoReference (gdyby API zwracało inaczej)
        upo_ref2 = last.get("upoReference")
        if upo_ref2:
            return upo_ref2, last

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


def find_failed_invoice_by_ee(failed: Any, ee_reference: str) -> Optional[Dict[str, Any]]:
    """
    Z /sessions/{so}/invoices/failed -> SessionInvoicesResponse.invoices[].
    Ten endpoint zwraca liste niepoprawnych faktur i ich statusy. :contentReference[oaicite:2]{index=2}
    """
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


def has_any_failed(failed: Any) -> bool:
    if not isinstance(failed, dict):
        return False
    for k in ("invoices", "entries", "failedInvoices", "items", "data"):
        v = failed.get(k)
        if isinstance(v, list) and len(v) > 0:
            return True
    return False


def build_ee_status_from_session_and_failed(
    ee_reference: str,
    session_json: Optional[Dict[str, Any]],
    failed_invoice: Optional[Dict[str, Any]],
) -> Dict[str, Any]:
    """
    SUCCESS:
      - sesja status.code == 200 ("Sesja interaktywna przetworzona pomyślnie") :contentReference[oaicite:3]{index=3}
      - i successfulInvoiceCount >= invoiceCount (lub >=1 przy braku invoiceCount)
    FAILED:
      - jeśli ee_reference jest na liście failed (zwraca statusy błędów) :contentReference[oaicite:4]{index=4}
    PENDING:
      - reszta
    """
    if failed_invoice:
        st = failed_invoice.get("status") or {}
        code = st.get("code")
        return {
            "state": "FAILED",
            "ee_reference": ee_reference,
            "ksef_status": st,
            "ksef_code": code,
        }

    if not isinstance(session_json, dict):
        return {"state": "PENDING", "ee_reference": ee_reference}

    st = session_json.get("status") or {}
    session_code = st.get("code")

    invoice_count = session_json.get("invoiceCount")
    ok_count = session_json.get("successfulInvoiceCount")

    # defensywnie: jeśli są liczniki i sesja 200
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
        # fallback: jeśli nie ma liczników, ale jest UPO
        pages = (session_json.get("upo") or {}).get("pages") or []
        if isinstance(pages, list) and len(pages) > 0:
            return {"state": "SUCCESS", "ee_reference": ee_reference, "session_status": st}

    if isinstance(session_code, int) and session_code >= 400:
        return {"state": "FAILED", "ee_reference": ee_reference, "session_status": st}

    return {"state": "PENDING", "ee_reference": ee_reference, "session_status": st}


def authenticate_get_access_token(client: httpx.Client, ksef_token: str, nip: str) -> str:
    # 1) challenge
    ch = http_json_or_raise(
        client.post("/auth/challenge", headers={"Accept": "application/json"}),
        "POST /auth/challenge",
    )
    challenge = ch.get("challenge")
    ts_ms = to_unix_ms(ch.get("timestamp"))
    if not challenge:
        raise HTTPException(502, "No challenge in /auth/challenge")

    # 2) certs
    certs = http_json_or_raise(
        client.get("/security/public-key-certificates", headers={"Accept": "application/json"}),
        "GET /security/public-key-certificates",
    )
    cert_token = pick_cert(certs, "KsefTokenEncryption")

    # 3) encrypt token|timestamp
    encrypted_token = b64e(
        rsa_encrypt(cert_token["certificate"], f"{ksef_token}|{ts_ms}".encode("utf-8"))
    )

    # 4) auth/ksef-token
    auth_resp = http_json_or_raise(
        client.post(
            "/auth/ksef-token",
            headers={"Accept": "application/json", "Content-Type": "application/json"},
            json={
                "challenge": challenge,
                "contextIdentifier": {"type": "Nip", "value": nip},
                "encryptedToken": encrypted_token,
            },
        ),
        "POST /auth/ksef-token",
    )

    auth_ref = auth_resp.get("referenceNumber")
    auth_token = ((auth_resp.get("authenticationToken") or {}).get("token"))
    if not auth_ref or not auth_token:
        raise HTTPException(502, detail={"message": "Bad /auth/ksef-token response", "raw": auth_resp})

    poll_auth_success(client, auth_ref, auth_token)

    redeem = http_json_or_raise(
        client.post(
            "/auth/token/redeem",
            headers={"Authorization": f"Bearer {auth_token}", "Accept": "application/json"},
            json={},
        ),
        "POST /auth/token/redeem",
    )

    access_token = ((redeem.get("accessToken") or {}).get("token"))
    if not access_token:
        raise HTTPException(502, detail={"message": "No accessToken in redeem", "raw": redeem})

    return access_token


# ============================================================
# ENDPOINT: submit
# ============================================================

@app.post("/invoice/submit", response_model=SubmitResponse)
async def submit_invoice(
    ksef_token: str = Form(..., description="Token EC z KSeF"),
    file: UploadFile = File(..., description="Plik XML faktury (UTF-8)"),
    api_base: str = Form(DEFAULT_API_BASE),
):
    raw = await file.read()
    if not raw:
        raise HTTPException(400, "Empty XML file")

    try:
        xml_text = raw.decode("utf-8")
    except UnicodeDecodeError:
        raise HTTPException(400, "XML must be UTF-8")

    invoice_bytes = normalize_xml(xml_text)
    nip = extract_nip_from_ksef_token(ksef_token)

    with make_client(api_base) as client:
        # auth -> access token
        access_token = authenticate_get_access_token(client, ksef_token, nip)

        # cert symmetric
        certs = http_json_or_raise(
            client.get("/security/public-key-certificates", headers={"Accept": "application/json"}),
            "GET /security/public-key-certificates",
        )
        cert_sym = pick_cert(certs, "SymmetricKeyEncryption")

        # open session
        aes_key = secrets.token_bytes(32)
        iv = secrets.token_bytes(16)
        encrypted_key = b64e(rsa_encrypt(cert_sym["certificate"], aes_key))

        open_resp = http_json_or_raise(
            client.post(
                "/sessions/online",
                headers={
                    "Authorization": f"Bearer {access_token}",
                    "Accept": "application/json",
                    "Content-Type": "application/json",
                },
                json={
                    "formCode": {"systemCode": "FA (3)", "schemaVersion": "1-0E", "value": "FA"},
                    "encryption": {
                        "encryptedSymmetricKey": encrypted_key,
                        "initializationVector": b64e(iv),
                    },
                },
            ),
            "POST /sessions/online",
        )
        so = open_resp.get("referenceNumber")
        if not so:
            raise HTTPException(502, detail={"message": "No SO reference", "raw": open_resp})

        # encrypt + send invoice
        enc_invoice = aes_encrypt(invoice_bytes, aes_key, iv)

        send_resp = http_json_or_raise(
            client.post(
                f"/sessions/online/{so}/invoices",
                headers={
                    "Authorization": f"Bearer {access_token}",
                    "Accept": "application/json",
                    "Content-Type": "application/json",
                },
                json={
                    "invoiceHash": sha256_b64(invoice_bytes),
                    "invoiceSize": len(invoice_bytes),
                    "encryptedInvoiceHash": sha256_b64(enc_invoice),
                    "encryptedInvoiceSize": len(enc_invoice),
                    "encryptedInvoiceContent": b64e(enc_invoice),
                    "offlineMode": False,
                },
            ),
            f"POST /sessions/online/{so}/invoices",
        )
        ee = send_resp.get("referenceNumber")
        if not ee:
            raise HTTPException(502, detail={"message": "No EE reference", "raw": send_resp})

        # close
        r_close = client.post(
            f"/sessions/online/{so}/close",
            headers={"Authorization": f"Bearer {access_token}", "Accept": "application/json"},
        )
        if r_close.status_code >= 400:
            raise HTTPException(status_code=502, detail=f"Close failed: {r_close.status_code} {r_close.text}")

        # failed early check
        failed = get_failed_invoices(client, access_token, so)
        failed_invoice_for_ee = find_failed_invoice_by_ee(failed, ee)

        if has_any_failed(failed):
            session_json = get_session_json(client, access_token, so)
            ee_status = build_ee_status_from_session_and_failed(ee, session_json, failed_invoice_for_ee)
            raise HTTPException(
                status_code=422,
                detail={
                    "message": "KSeF reported failed invoice(s) for this session - no UPO will be produced",
                    "so_reference": so,
                    "ee_reference": ee,
                    "failed_invoices": failed,
                    "failed_invoice_for_ee": failed_invoice_for_ee,
                    "session_json": session_json,
                    "ee_status": ee_status,
                },
            )

        # wait UPO (default)
        upo_ref, session_json = wait_for_upo_reference(client, access_token, so, timeout_sec=180, interval_sec=2.0)

        upo_xml = download_upo_xml(client, access_token, so, upo_ref)
        upo_json = parse_upo_xml_to_json(upo_xml)

        # ee_status based on session + failed
        ee_status = build_ee_status_from_session_and_failed(ee, session_json, failed_invoice_for_ee)

        # zapisz "ostatnia faktura" per NIP
        LAST_BY_NIP[nip] = {
            "so": so,
            "ee": ee,
            "api_base": api_base,
            "updated_at": dt.datetime.utcnow().replace(tzinfo=dt.timezone.utc).isoformat(),
        }

        return SubmitResponse(
            so_reference=so,
            ee_reference=ee,
            upo_reference=upo_ref,
            upo_xml_base64=b64e(upo_xml),
            upo_json=upo_json,
            failed_invoices=failed,
            failed_invoice_for_ee=failed_invoice_for_ee,
            session_json=session_json,
            ee_status=ee_status,
        )


# ============================================================
# ENDPOINT: last status (polling)
# ============================================================

@app.post("/invoice/last/status", response_model=LastStatusResponse)
def last_invoice_status(
    ksef_token: str = Form(..., description="Token EC z KSeF"),
    wait_seconds: int = Form(0, description="Ile sekund maksymalnie czekac na SUCCESS/FAILED (0 = bez czekania)"),
    api_base: str = Form(DEFAULT_API_BASE),
):
    nip = extract_nip_from_ksef_token(ksef_token)

    last = LAST_BY_NIP.get(nip)
    if not last:
        raise HTTPException(404, detail=f"No last invoice stored for NIP={nip}. Call /invoice/submit first.")

    so = last["so"]
    ee = last["ee"]

    # wait cap
    if wait_seconds is None:
        wait_seconds = 0
    try:
        wait_seconds = int(wait_seconds)
    except Exception:
        raise HTTPException(400, detail="wait_seconds must be int")

    if wait_seconds < 0:
        wait_seconds = 0
    if wait_seconds > MAX_WAIT_SECONDS:
        wait_seconds = MAX_WAIT_SECONDS

    with make_client(api_base) as client:
        access_token = authenticate_get_access_token(client, ksef_token, nip)

        deadline = time.time() + wait_seconds
        last_session_json: Optional[Dict[str, Any]] = None
        last_failed: Optional[dict] = None
        last_failed_for_ee: Optional[Dict[str, Any]] = None
        last_status: Dict[str, Any] = {"state": "PENDING", "ee_reference": ee}

        while True:
            # 1) sesja
            last_session_json = get_session_json(client, access_token, so)

            # 2) failed (jesli ee jest na liscie -> FAILED)
            last_failed = get_failed_invoices(client, access_token, so)
            last_failed_for_ee = find_failed_invoice_by_ee(last_failed, ee)

            # 3) ee_status
            last_status = build_ee_status_from_session_and_failed(ee, last_session_json, last_failed_for_ee)

            if last_status.get("state") in ("SUCCESS", "FAILED"):
                break

            if time.time() >= deadline:
                break

            time.sleep(STATUS_POLL_INTERVAL_SEC)

        return LastStatusResponse(
            nip=nip,
            so_reference=so,
            ee_reference=ee,
            ee_status=last_status,
            session_json=last_session_json,
            failed_invoice_for_ee=last_failed_for_ee,
            failed_invoices=last_failed,
        )


@app.get("/health")
def health():
    return {"ok": True}
