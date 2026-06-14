#!/usr/bin/env python3
"""
===================================================
  سنتر الدروس CRM — License Key Generator
  للاستخدام من داشبورد البائع فقط

  الاستخدام:
    python3 generate_license.py --hwid "ABCD-1234-EFGH-5678" --days 365
    python3 generate_license.py --hwid "ABCD-1234-EFGH-5678" --days 0  (مدى الحياة)

  المتطلبات:
    pip install cryptography
===================================================
"""
import argparse, base64, json, os, time
from datetime import datetime, timedelta, timezone
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
from cryptography.hazmat.primitives import hashes, serialization

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
DEFAULT_KEY_PATH = os.path.join(SCRIPT_DIR, "edu_private_key.pem")

def load_private_key(path=DEFAULT_KEY_PATH):
    with open(path, "rb") as f:
        return serialization.load_pem_private_key(f.read(), password=None)

def normalize_hwid(hwid: str) -> str:
    return hwid.strip().upper().replace(" ", "")

def build_payload(hwid: str, expiry_ts: int, edition: str) -> dict:
    return {"hwid": normalize_hwid(hwid), "exp": expiry_ts, "iat": int(time.time()), "ed": edition, "v": 1}

def sign_payload(payload: dict, private_key) -> str:
    payload_bytes = json.dumps(payload, separators=(',', ':')).encode('utf-8')
    payload_b64   = base64.urlsafe_b64encode(payload_bytes).rstrip(b'=').decode()
    signature_der = private_key.sign(payload_bytes, ec.ECDSA(hashes.SHA256()))
    r, s = decode_dss_signature(signature_der)
    sig_raw = r.to_bytes(32, 'big') + s.to_bytes(32, 'big')
    sig_b64  = base64.urlsafe_b64encode(sig_raw).rstrip(b'=').decode()
    return f"{payload_b64}.{sig_b64}"

def generate(hwid: str, days: int, edition: str, key_path: str):
    private_key = load_private_key(key_path)
    if days == 0:
        expiry_ts = 0
        expiry_str = "مدى الحياة"
    else:
        expiry_dt = datetime.now(timezone.utc) + timedelta(days=days)
        expiry_ts = int(expiry_dt.timestamp())
        expiry_str = expiry_dt.strftime("%Y-%m-%d")
    payload = build_payload(hwid, expiry_ts, edition)
    license_key = sign_payload(payload, private_key)
    print("\n" + "="*60)
    print("  سنتر الدروس CRM — License Key")
    print("="*60)
    print(f"  Hardware ID  : {normalize_hwid(hwid)}")
    print(f"  الإصدار      : {edition.upper()}")
    print(f"  تاريخ الإصدار: {datetime.now().strftime('%Y-%m-%d')}")
    print(f"  الصلاحية     : {expiry_str}")
    print("-"*60)
    print(f"\n  License Key:\n")
    print(f"  {license_key}")
    print(f"\n{'='*60}\n")
    return license_key

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Edu CRM License Generator")
    parser.add_argument("--hwid",    required=True,  help="Hardware ID بتاع العميل")
    parser.add_argument("--days",    type=int, default=365, help="عدد الأيام (0 = مدى الحياة)")
    parser.add_argument("--edition", default="pro",  help="pro | basic")
    parser.add_argument("--key",     default=DEFAULT_KEY_PATH, help="مسار المفتاح الخاص")
    args = parser.parse_args()
    generate(args.hwid, args.days, args.edition, args.key)
