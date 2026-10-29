#!/usr/bin/env python3
"""
Utool / AI Video Enhancer (Appbyte, InShot 家族) 协议客户端

传输加密：AES-128-ECB / PKCS7，key = MD5("haha")
  —— 静态还原自 libsafe_auth.so +0xcac8（见 docs/02-传输加密.md）

用法：
    from utool_client import call, signIn, enc, dec
    ident = signIn("https://android.inshot.cc", "videoeditor.videomaker.aieffect")
    code, r = call("/api/ai2/lowlight/task/query", {**ident, "resMd5": "..."},
                   base="https://iqe.inmelo.app")

注意：create 需要 credits，新账号额度为 0（见 docs/04-账号与额度.md）。
"""
from __future__ import annotations

import base64
import hashlib
import json
import secrets
import uuid as _uuid

import requests
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

# ---------------------------------------------------------------- 常量
KEY = hashlib.md5(b"haha").digest()
assert KEY.hex() == "4e4d6c332b6fe62a63afe56171fd3725", "key derivation mismatch"

PKG = "videoeditor.videomaker.aieffect"
BASE_IAP = "https://android.inshot.cc"      # 账号 / 额度
BASE_AI = "https://iqe.inmelo.app"          # AI 任务
BASE_UPLOAD = "https://fsbridge.appbyte.ltd"  # 文件上传（明文 JSON）

DEFAULT_TIMEOUT = 25


# ---------------------------------------------------------------- 信封
def enc(obj) -> str:
    """dict -> base64(AES-ECB(json))"""
    raw = json.dumps(obj, separators=(",", ":"), ensure_ascii=False).encode()
    return base64.b64encode(AES.new(KEY, AES.MODE_ECB).encrypt(pad(raw, 16))).decode()


def dec(body: str):
    """base64(AES-ECB(json)) 或明文 JSON -> dict"""
    body = (body or "").strip()
    if not body:
        return {}
    if body[:1] in "{[" and body[-1:] in "}]":
        return json.loads(body)          # 404 / 网关错误走明文
    pt = AES.new(KEY, AES.MODE_ECB).decrypt(base64.b64decode(body))
    try:
        pt = unpad(pt, 16)
    except ValueError:
        pass
    return json.loads(pt.decode("utf-8", "replace"))


# ---------------------------------------------------------------- HTTP
def call(path, payload=None, base=BASE_AI, method="POST", headers=None,
         raw_body=None, timeout=DEFAULT_TIMEOUT):
    """返回 (status_code, dict)"""
    h = {"Content-Type": "application/json", "Accept": "application/json"}
    if headers:
        h.update(headers)
    body = raw_body if raw_body is not None else enc(payload or {})
    resp = requests.request(method, base + path, data=body.encode(),
                            headers=h, timeout=timeout)
    try:
        return resp.status_code, dec(resp.text)
    except Exception:
        return resp.status_code, {"_raw": resp.text[:400]}


# ---------------------------------------------------------------- 账号
def signIn(base=BASE_IAP, package_name: str = PKG, account_id: str | None = None):
    """
    开放注册式登录：accountId 客户端自定义，accountToken/verifyCode 不校验。
    返回可直接用于后续请求的身份字典。
    """
    uid = str(_uuid.uuid4())
    acc = account_id or ("acc" + secrets.token_hex(6))
    code, r = call("/api/iap3/user/signIn", {
        "packageName": package_name,
        "uuid": uid,
        "accountId": acc,
        "signType": 1,
        "accountToken": "t",
        "accountName": acc,
        "verifyCode": "000000",
    }, base=base)
    if r.get("code") != 0:
        raise RuntimeError(f"signIn failed: {r}")
    d = r["data"]
    return {"packageName": package_name, "uuid": uid,
            "accountId": d["accountId"], "appUserId": d["appUserId"]}


def credits(ident, base=BASE_IAP):
    return call("/api/iap3/credits/android/creditsBalanceCount", ident, base=base)


def unused_count(ident, access_flags="0501.9991.00101", base=BASE_AI):
    return call("/api/ai2/accessflag/task/queryUnusedCount",
                {**ident, "accessFlags": access_flags, "vipType": 0}, base=base)


# ---------------------------------------------------------------- 任务
def task_url(model_type: str, action: str, test: bool = False) -> str:
    """/api/ai2/{modelType}{-test?}/task/{action}"""
    return f"/api/ai2/{model_type}{'-test' if test else ''}/task/{action}"


def task_query(ident, res_md5, model_type="lowlight", base=BASE_AI):
    return call(task_url(model_type, "query"), {**ident, "resMd5": res_md5}, base=base)


def task_cancel(ident, res_md5, model_type="lowlight", base=BASE_AI):
    return call(task_url(model_type, "cancel"), {**ident, "resMd5": res_md5}, base=base)


def task_create(ident, res_md5, res_url, res_size_bytes, bucket,
                resolution="1920*1080", model_type="lowlight",
                access_flags="0501.9991.00101", vip_type=0, base=BASE_AI):
    """
    需要 credits。无额度时上游返回 {"code":-2,"message":"Processing error"}。
    resSize 单位是 KB（上游用 字节/1024）。
    """
    payload = {
        **ident,
        "modelType": model_type,
        "resUrl": res_url,
        "resSize": int(res_size_bytes / 1024),
        "resMd5": res_md5,
        "resLength": 0.0,
        "bucket": bucket,
        "resolution": resolution,
        "vipType": vip_type,
        "accessFlags": access_flags,
    }
    return call(task_url(model_type, "create"), payload, base=base)


# ---------------------------------------------------------------- 自检
if __name__ == "__main__":
    print("AES key :", KEY.hex())
    ident = signIn()
    print("ident   :", json.dumps(ident, ensure_ascii=False))
    print("credits :", json.dumps(credits(ident)[1], ensure_ascii=False))
    print("unused  :", json.dumps(unused_count(ident)[1], ensure_ascii=False))
    print("query   :", json.dumps(task_query(ident, hashlib.md5(b"").hexdigest())[1],
                                 ensure_ascii=False))
