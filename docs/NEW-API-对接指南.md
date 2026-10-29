# new-api 渠道对接指南（预留设计）

> 当前状态：**协议可用，但 `create` 被额度拦截 → 渠道默认关闭，仅保留代码插槽。**
> 待 `credits` 有合法来源后，按本文档接入即可，无需再改协议层。

---

## 1. 建议的渠道形态

参考本仓库已有的 `2API` 中转模式（duck-2api / AIVM type72），不建议做成 OpenAI 兼容的
`/v1/chat/completions`，因为语义不匹配。建议新增一类 **媒体任务渠道**：

```
POST /v1/media/enhance
{
  "model": "lowlight",             // 或 ai_video 的 templateModel
  "video_url": "https://.../in.mp4",
  "resolution": "1920*1080"        // 可选，默认原分辨率
}
-> {"task_id": "...", "status": "queued"}
```

```
GET /v1/media/task/{task_id}
-> {"status": "processing|succeeded|failed", "url": "https://aicdn.appbyte.ltd/..."}
```

内部流程：

```
取视频 → 算 MD5 → POST fsbridge:/api/upload/init → /chunk 分块 → /file 收尾
       → POST iqe:/api/ai2/lowlight/task/create  {resMd5,resUrl,resSize,bucket,resolution,...}
       → 轮询 iqe:/api/ai2/lowlight/task/query   {resMd5}
       → 成功后从 aicdn 取结果
```

## 2. 渠道配置字段

| 字段 | 说明 | 示例 |
|---|---|---|
| `base_iap` | 账号服务 | `https://android.inshot.cc` |
| `base_ai` | AI 任务服务 | `https://iqe.inmelo.app` |
| `base_upload` | 上传服务 | `https://fsbridge.appbyte.ltd` |
| `package_name` | 固定 | `videoeditor.videomaker.aieffect` |
| `AES_KEY` | 固定常量 | `md5("haha")` |
| `account_pool` | `{accountId, appUserId, uuid}` 三元组池 | 由 signIn 铸造 |
| `bucket` | `stn2_ai_gen` / `stn_inmelo_ai` | |
| `enable_create` | **默认 false**（无额度时禁止调用） | |

## 3. 账号池（可用，但无额度）

`signIn` 是开放注册，可以低成本铸造账号：

```python
def mint(base_iap, package_name):
    uid = str(uuid.uuid4())
    acc = "acc" + secrets.token_hex(6)
    _, r = call("/api/iap3/user/signIn", {
        "packageName": package_name, "uuid": uid, "accountId": acc,
        "signType": 1, "accountToken": "t", "accountName": acc,
        "verifyCode": "000000"}, base=base_iap)
    d = r["data"]
    return {"accountId": d["accountId"], "appUserId": d["appUserId"], "uuid": uid}
```

但 **每个新号 credits=0**，所以池化账号本身不产生能力。
若后续接入额度来源，应按 `accountId` 记账，并在 `creditsBalanceCount` 为 0 时把账号标记为 `exhausted`。

## 4. 计费建议

| 项 | 建议 |
|---|---|
| 上游成本 | 1 次 enhance 消耗未知（需有额度账号实测 `creditsBalanceDetail` 差额） |
| 对内计费 | 按 credits 等值折算，向上取整 |
| 并发 | 任务型，建议单账号并发 1，靠池子扩 |
| 超时 | create 后轮询上限建议 10 min |

## 5. 必须实现的防护

1. **`enable_create=false` 时直接返回 503**，禁止在无额度时把请求打到上游（会污染账号风控）。
2. 上传前校验文件大小/时长上限，避免把上游存储打满。
3. `resMd5` 必须由服务端从实际文件计算，禁止透传客户端值（防止越权查他人任务）。
4. 结果 URL 走 `aicdn.appbyte.ltd` 直链，需要做防盗链/过期处理。

## 6. 上线检查清单

- [ ] 拿到合法 credits 来源（Play 购买 / 兑换码）
- [ ] 用一个有额度账号跑通 create → query → 下载 全链路
- [ ] 测出单任务 credits 消耗
- [ ] 恢复 `enable_create=true`
- [ ] 压测：并发 8，观察 429 / `-2` 比例
