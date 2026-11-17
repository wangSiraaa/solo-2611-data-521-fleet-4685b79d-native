# 异步安全扫描约束的精确字节入仓

本地扫描适配 + 隔离入仓协调器。扫描器是题目提供的合成检查器
`materials/521/source_fixture.py`，不访问任何外部杀毒服务。持久化使用真实
SQLite，对象存储在文件系统中按内容摘要寻址。

## 快速开始

```bash
# 提交（读取并固定调用方路径的字节一次）
python3 -m quarantine.cli --root ./state submit u1 ./a.csv --display-name a.csv
# 显式扫描（每次生成新的 scan_id）
python3 -m quarantine.cli --root ./state scan u1            # 默认 normal
python3 -m quarantine.cli --root ./state scan u1 --mode block
# 状态 / 入仓 / 行检查
python3 -m quarantine.cli --root ./state status u1
python3 -m quarantine.cli --root ./state import u1
python3 -m quarantine.cli --root ./state inspect_rows u1
# 取消正在扫描的 upload
python3 -m quarantine.cli --root ./state cancel u1
# 清理服务自己创建且已无引用的对象
python3 -m quarantine.cli --root ./state cleanup
```

`--root` 保存 `objects/`、`tmp/` 与 `quarantine.sqlite3`。`--fixture` 可覆盖扫描器路径。

编程接口见 `quarantine/service.py:QuarantineService`：`submit`、`scan`、
`cancel`、`status`、`import_upload`、`inspect_rows`、`cleanup_objects`、
`recover_orphans`。

## 测试

```bash
python3 -m unittest tests.test_quarantine -v
```

测试会真实启动子进程、写入真实 SQLite，并直接读取受管对象摘要。覆盖：
normal/BLOCK/半输出/bad_exit/stderr 大量写入；替换原路径（接纳后、扫描与入仓
之间）；取消后注入旧回执；双终态、未知 scan_id、摘要/长度不符、超时、stdout 超限；
1000/1001 行边界；业务 id 冲突；重启恢复；最多 2 个扫描进程及卡住时的查询/取消。

## 文件身份固定

接纳时对调用方路径**只读一次**，边读边算 SHA-256 与长度，写入
`objects/<sha[:2]>/<sha[2:]>`，完成 `fsync` 后 `chmod 0444` 并以原子 `rename`
就位。`content_id` 就是 SHA-256，`display_name` 与原路径**不参与**身份判定。

- 相同 `upload_id` + 相同内容重试：返回原状态，不重复建行。
- 相同 `upload_id` + 不同内容：`UploadConflict`。
- 接纳后即使调用方替换原路径，后续扫描与导入只读受管对象；导入前再次核对摘要
  与长度，不符则 `INTEGRITY` 失败且不写行。
- 对象路径由校验过的 64 位十六进制摘要派生，用户路径不会被当作对象路径或删除
  目标。`cleanup` 只枚举受管对象目录、跳过非摘要名/符号链接/非普通文件，并且
  只删除数据库中已无引用的对象。

## 进程结果所有权（为何不会把扫描 A 的结论用在文件 B 上）

一次扫描尝试 = 一个 `scan_id` + 一条 `scan_attempts` 行，绑定
`(upload_id, content_id, generation)`。

- 适配器为每次尝试生成**新的** `scan_id`，随 `argv` 传给设施。
- 设施的最终记录必须同时满足：恰好一条完整 UTF-8 JSON；`scan_id` 等于本次；
  `content_sha256` 与 `size` 等于被绑定对象；`verdict ∈ {ALLOW,BLOCK}`；
  `reason` 为字符串；之后进程以 0 退出。任一不满足 → `ERROR`（永不 `ALLOW`）。
- 提交终态时在 `BEGIN IMMEDIATE` 事务中再次校验：该 attempt 仍为 `running`、
  upload 仍为 `scanning`、`generation` 与 `content_id` 与 job 一致。旧 `scan_id`、
  旧 generation 或已被取消/取代的尝试无法结算新尝试。
- 设施读取的是**受管对象路径**，且自身对读到的字节求摘要；若它被指向 A 的对象，
  记录里的摘要就是 A 的，与绑定到 B 的 `content_id` 不符 → `digest_mismatch` →
  `ERROR`。因此 A 的 ALLOW/BLOCK 结论无法记到 B 上。

## 状态机

`received → scanning → {blocked, error, ready} → imported`

- `scan` 从 `received/blocked/error/ready` 均可用新的 generation 重新发起；`imported`
  不可再扫描或取消。
- `blocked`、`error` 不新增任何行，`import` 被拒绝。
- `ready → imported` 在一个事务内完成整份 CSV 校验后的插入与状态更新：要么所有行
  与 `imported` 一起提交，要么回到 `error` 并保留原因，不留前缀行。
- 业务 `id` 已由**另一个** upload 导入 → `CONFLICT`（`error`），不覆盖旧行。
- 相同 upload 重复 `import` 是幂等的，不会二次写入。

## 扫描适配细节

- stdout/stderr 并发读取，`select`/线程泵，避免写满 stderr 的子进程永久挂起。
- 保留 stdout 至多 16 KiB，stderr 仅保留末尾 8 KiB；超限 → `stdout_overflow`
  `ERROR`。
- 超时或取消 → 杀掉整个子进程组（`start_new_session` + `killpg`）。
- 子进程在自身进程组中；服务关闭/取消时置取消标志，由适配器统一终止并回收。

## 取消、关闭与重启

- `cancel` 先提交 `error/cancelled` 与 attempt 的 `aborted`，再让适配器终止子进程。
  迟到的 ALLOW 因 attempt 不再 `running` 而无法结算。已 `imported` 的 upload
  拒绝 `cancel`，已提交行保留。
- 进程退出/服务关闭时，正在扫描的尝试记为 `aborted`，upload 回到 `received`
  （“仍待处理”，而非失败，也绝非通过）。重启后 `recover_orphans` 以同样方式
  恢复遗留 `running` 尝试，必须显式重新 `scan` 才可能得到终态。

## 并发

`ThreadPoolExecutor(max_workers=2)` 限制最多 2 个扫描子进程；查询与取消只读/写
SQLite，不等待扫描子进程，因此在两个扫描卡住时仍可 `status` 和 `cancel`。

## 明确的非目标

不包含 HTTP 上传页面、真实恶意文件识别、外部扫描平台、分布式队列、任意格式自动
检测。扫描器仅为本题目定义的合成检查器。
