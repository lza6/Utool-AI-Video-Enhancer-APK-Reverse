# Utool / AI Video Enhancer v1.202.84 — 协议逆向与对接归档

> 目标样本：`AI Video Enhancer - Utool v1.202.84 b84 (Premium By ElaMods).apk`
> 包名：`videoeditor.videomaker.aieffect`（Appbyte Ltd. / InShot 家族白标）
> 结论：**协议层 100% 打通**，唯一缺口是 credits（额度）来源 —— 新账号无任何免费额度。

---

## 1. 一页结论

| 维度 | 状态 |
|---|---|
| 传输加密 | ✅ 已破：`AES-128-ECB/PKCS7`，key = `MD5("haha")` |
| 端点归属 | ✅ iap3 → `android.inshot.cc`；ai2 → `iqe.inmelo.app`；上传 → `fsbridge.appbyte.ltd` |
| API 面 | ✅ 账号/额度/任务/上传 全部端点已枚举并实测 |
| 账号体系 | ✅ `signIn` 实为开放注册：客户端自定义 `accountId` + 任意 token 即发 `appUserId` |
| 任务协议 | ✅ `query` / `cancel` 实测返回 `code:0` |
| 任务创建 | ❌ `create` 恒返回 `code:-2`（唯一扣额度动作被拦） |
| 免费额度 | ❌ 无。新账号 `credits=0`、`totalLimit=0`；仅 Play 购买 / 兑换码两条路 |
| 原生完整性校验 | ⚠️ 未在 ai2 链路上强制（注入 `appSign/apkSign/soMd5` 不改变结果） |

**一句话**：能免费读、能免费查、能免费取消，但**不能免费出片**。

---

## 2. 快速上手

```python
from src.utool_client import call, enc, dec

# 1) 注册/登录（开放注册，任意 accountId 均可）
code, r = call("/api/iap3/user/signIn", {
    "packageName": "videoeditor.videomaker.aieffect",
    "uuid": "<uuid4>", "accountId": "<任意字符串>",
    "signType": 1, "accountToken": "t",
    "accountName": "<任意>", "verifyCode": "000000"}, base="https://android.inshot.cc")
# -> {"code":0,"data":{"appUserId":"...","accountId":"...","isFirst":true}}

# 2) 查额度
call("/api/iap3/credits/android/creditsBalanceCount", ident, base="https://android.inshot.cc")

# 3) 查任务（返回 code:0）
call("/api/ai2/lowlight/task/query", {**ident, "resMd5": md5}, base="https://iqe.inmelo.app")
```

加密信封由 `utool_client.py` 自动处理。

---

## 3. 文档索引

| 文件 | 内容 |
|---|---|
| [docs/01-协议总览.md](docs/01-协议总览.md) | 架构、域名、DNS/集群关系、数据流 |
| [docs/02-传输加密.md](docs/02-传输加密.md) | 密钥派生反汇编、JNI 表重建、完整推导链 |
| [docs/03-接口清单.md](docs/03-接口清单.md) | 全端点表 + 参数 + 实测响应 |
| [docs/04-账号与额度.md](docs/04-账号与额度.md) | signIn 开放注册、credits 体系、无免费额度结论 |
| [docs/05-方法论与坑.md](docs/05-方法论与坑.md) | 无 jadx 的逆向路径、PLT/重定位坑、工具链 |
| [docs/NEW-API-对接指南.md](docs/NEW-API-对接指南.md) | 若要接 new-api 渠道的字段与预留设计 |
| [evidence/实测记录.md](evidence/实测记录.md) | 原始请求/响应粘贴 |

---

## 4. 工具链

| 文件 | 用途 |
|---|---|
| `src/utool_client.py` | AES 信封封装 + 端点调用（可直接 import） |
| `src/tools/andro.py` | androguard v4 封装：`ls <前缀>` / `src <类名>` / `grep <字符串>` / `xref <类> <方法>` |
| `src/tools/xrefs.py` | ARM64 ELF 的 `ADRP+ADD` 字符串交叉引用解析 |
| `src/tools/dexref.py` | 自研 DEX 扫描：定位引用指定字符串的 类→方法 |
| `src/tools/pkgstr.py` | 按包前缀导出全部 const-string |
| `src/tools/mstr.py` | 按方法导出 const-string（含指令偏移） |
| `src/tools/typeref.py` | 自研 DEX 扫描：定位引用指定 **类型** 的 类→方法 |

---

## 5. 免责声明

本项目为**安全研究与协议互操作性分析**存档，仅记录逆向分析结论与可复现方法。
所有接口、密钥、白名单均来自样本 APK 自带资产与公开网络请求，未包含任何他人账号、
支付凭证或隐私数据。请勿将其用于批量注册、盗刷额度或商业转售；由此产生的任何
后果与作者无关。若你是权利方并希望移除本仓库，请提 issue。
