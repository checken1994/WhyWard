# WhyWard 0.2.0 — Báo cáo triển khai (sau đánh giá 2026-10-26)

| | |
|---|---|
| **Ngày** | 2026-10-26 |
| **Phạm vi** | Thực thi lộ trình 0.1 → 0.2 trong `docs/audit/2026-10-26-danh-gia-he-thong.md` |
| **Trạng thái** | 15/15 phát hiện đã được đóng bằng cơ chế + test âm tính + probe |
| **Bằng chứng chạy được** | 246 test (stdlib), 15/15 probe `OK`, 10/10 mutation bị phát hiện, coverage nhánh 88 %, ruff/mypy-strict/bandit sạch |
| **Chưa phải** | nghiệm thu độc lập, chứng nhận bảo mật, tuyên bố production-ready |

Báo cáo này chỉ ghi những gì **chạy được và kiểm lại được**. Mọi con số dưới đây
đều có lệnh tái lập ở mục §5. Những gì chưa kiểm được ghi rõ ở §6 — và không
được tính điểm.

---

## 1. Tóm tắt điều hành

Bản 0.1.0 có kiến trúc đúng nhưng các bảo đảm chỉ nằm ở tầng tuyên bố. Bản 0.2.0
chuyển từng bảo đảm thành **cơ chế cưỡng chế + test âm tính**. Không có hạng mục
nào được đánh dấu "xong" chỉ vì đã viết code: mỗi hạng mục phải có (a) cơ chế,
(b) test đỏ-trước-xanh-sau, (c) probe tấn công tái lập được, (d) tài liệu khớp
với hành vi.

Ba thay đổi có tính bước ngoặt:

1. **Tin cậy bằng chứng rời khỏi tay người gọi.** `EvidenceRegistry` ký từng bản
   ghi; `review_status` do caller khai bị hạ xuống `unverified`; evidence truyền
   lúc submit bị bỏ qua. Worker không còn tự cấp bằng chứng cho mình.
2. **Phê duyệt trở thành một artefact có ràng buộc.** `HumanDecision` mang
   `proposal_digest`, `task_id`, `package_digest`, `expires_at`, `nonce` và chữ
   ký; core tính lại và từ chối nếu lệch, hết hạn hoặc đã dùng.
3. **Biên thực thi có giới hạn đo được.** Đọc/ghi bị chặn theo byte, không ghi
   xuyên symlink, đọc lại để xác nhận; `run_python` tắt mặc định, luôn cần người
   duyệt ở mọi profile, chạy container nếu có runtime, nếu không thì rlimit +
   môi trường tối thiểu.

---

## 2. Đóng từng phát hiện

| ID | Phát hiện (0.1.0) | Cơ chế mới | Test âm tính | Probe |
|---|---|---|---|---|
| W-01 | Approval replay được sang proposal khác | `HumanDecision` gắn digest proposal/task/package, hết hạn, nonce chống replay, chữ ký HMAC | `DecisionBindingTests` | OK |
| W-02 | Bằng chứng tự khai `verified` được tin | Registry ký; `register_evidence()` ép `unverified`; `submit(evidence=...)` bị bỏ qua có cảnh báo | `EvidenceTrustTests` | OK |
| W-03 | Freshness chỉ là metadata | `valid_until`, `review_after`, lớp biến động; hết hạn → `INSUFFICIENT_EVIDENCE`/`FOUND_STALE` | `EvidenceTrustTests` | OK |
| W-04 | `sha256`/`record_count` của manifest không bắt buộc | Manifest bắt buộc, kiểm cả hai, lệch → `CATALOG_CHECKSUM_MISMATCH`/`CATALOG_RECORD_COUNT` | `CatalogIntegrityTests` | OK |
| W-05 | Không có ngưỡng lineage | `min_independent_lineages` theo risk tier | `ReviewGateTests` | OK |
| W-06 | Nhiều writer làm hỏng ledger | Khoá file liên process, đọc lại tail, fsync, hash-chain, checkpoint + anchor ngoài | `LedgerTests` | OK |
| W-07 | Capability sống qua restart | Used-token store SQLite (bền), `claim` nguyên tử | `CapabilityTests` | OK |
| W-08 | Kill switch không thu hồi quyền | Engage: chặn phát token, `revoke_all()`, chặn thực thi từng action, `/readyz` → 503 | `test_api`, `BoundaryHardeningTests` | OK |
| W-09 | `verify-ledger` ném traceback | Lỗi có kiểu + JSON problem + exit 2 | `test_cli_inprocess` | OK |
| W-10 | `ask` exit 0 khi bị giữ lại | Withheld → exit 3; verdict luôn có trong payload | `test_cli_e2e` | OK |
| W-11 | `demo_verified` lọt vào production | Trạng thái chấp nhận lấy từ profile; production chỉ `verified` | `ReviewGateTests` | OK |
| W-12 | API không xác thực | Server từ chối khởi động nếu không có token store; bearer + scope + rate limit + body cap + security header + `WWW-Authenticate` | `test_api` | OK |
| W-13 | Đọc/ghi không giới hạn | `max_read_bytes` (cắt), `max_write_bytes` (từ chối), chặn symlink, xác nhận bằng đọc lại | `ExecutionLimitsTests` | OK |
| W-14 | `run_python` chạm host | Tắt mặc định; `human_required_tools` ở **mọi** profile; container backend; rlimit + env tối thiểu; giới hạn thời gian/kích thước output | `ExecutionLimitsTests` | OK |
| W-15 | `ValueError` thô từ input sai | `WhyWardError` có mã ở mọi cửa vào công khai | `BoundaryHardeningTests` | OK |

Ngoài 15 phát hiện, trong lúc triển khai phát hiện thêm 3 lỗi và đã sửa:

- `Policy.load` chỉ dùng `--keyring` khi có `--require-signed-policy` → policy có
  chữ ký nhưng bị từ chối sai (`UNKNOWN_KEY_ID`). Nay keyring được truyền luôn.
- Kill switch chỉ có tác dụng nếu có `kill_switch_file`; điều khiển qua API
  không chặn được gì. Nay trạng thái được giữ trong bộ nhớ control plane.
- `format_disk`-style tool lạ, resource rỗng và mkdir lỗi từng làm lộ
  `FileExistsError` thô; nay đều là `ExecutionError` có mã.

Và 4 lỗi **chỉ lộ ra khi chạy trên Windows** (do CI ma trận bắt được, không phải
do suy đoán):

| Lỗi | Hậu quả | Sửa |
|---|---|---|
| `SqliteUsedTokenStore` không đóng connection sau `CREATE TABLE` | File `.sqlite3` bị khoá; không xoá/copy được thư mục trên Windows | Đóng handle trong `finally` + test xoá DB để chứng minh |
| CLI in tiếng Việt ra console Windows (cp1252) | `UnicodeEncodeError` → câu trả lời đúng biến thành exit 1 | `_force_utf8_io()` reconfigure stdout/stderr |
| Mount path trong lệnh container dùng `\` | `docker -v \tmp\ws:/work` sai | `workspace.as_posix()` |
| Khoá ledger chỉ dựa trên `fcntl`/`msvcrt` | Trên vài nền tảng khoá là no-op, ghi đồng thời làm hỏng chain | Khoá bằng `O_CREAT \| O_EXCL` (atomic mọi nền tảng) + timeout + phá khoá cũ |

---

## 3. Bằng chứng

```text
$ PYTHONPATH=src python3 -m unittest discover -s tests -t tests
Ran 246 tests in ~18s
OK

$ ruff check src tests
All checks passed!

$ mypy
Success: no issues found in 20 source files

$ bandit -q -r src -ll
(không có issue mức medium trở lên)

$ coverage run --source=src/whyward -m pytest -q && coverage report
TOTAL   2972 statements   88% branch coverage   (ngưỡng: 85%)

$ PYTHONPATH=src python3 docs/audit/reproduce_findings.py
15 probes: 15 OK, 0 VULNERABLE

$ python3 docs/acceptance/falsification_check.py
10 mutations: 10 detected, 0 undetected

$ python3 docs/acceptance/acceptance_runner.py
ACCEPTED — 9 checks passed        (chạy trên clone sạch — xem báo cáo tự chạy)
```

Hành vi đo được trên bản chạy thật:

- `demo` → 6 event, `verify-ledger --require-signature` hợp lệ, anchor/verify
  theo anchor OK; ledger 6 event, `head_hash` in ra được neo ngoài.
- `ask` câu Valdivia 1960 → `PASS_WITHIN_SCOPE`, `magnitude = 9.5`,
  `source_id=usgs`, `lineage_id` đi kèm.
- `ask` câu California 2004 → `INSUFFICIENT_EVIDENCE`, exit 3 (không đoán).
- Sửa một dòng ledger → `verify-ledger` exit 2; cắt ledger so với anchor →
  phát hiện "truncation"; sửa một shard catalog → `CATALOG_CHECKSUM_MISMATCH`.
- `serve` không có token store → exit 4 `NO_API_TOKENS`; gọi `/ask` không token
  → 401 kèm `WWW-Authenticate`; engage kill switch → `/readyz` 503 và `/ask`
  trả `BLOCKED_BY_POLICY`.
- Capability token: 1 lần dùng; thử dùng lại sau khi "restart" (broker mới, cùng
  store) → `CAPABILITY_REPLAYED`.

---

## 4. Thay đổi kiến trúc so với 0.1.0

| Thành phần | 0.1.0 | 0.2.0 |
|---|---|---|
| Evidence | `EvidenceRef` + `review_status` tự khai | `EvidenceRegistry` ký, lineage, freshness, `content_hash` |
| Approval | dict comprehension + `HumanDecision` rời | `ApprovalPackage` + decision ràng buộc, hết hạn, chống replay |
| Capability | HMAC, one-use trong RAM | HMAC, one-use SQLite bền, `revoke_all`, hook kill switch |
| Ledger | append + hash-chain | + khoá liên process, fsync, checkpoint ký, anchor, verify theo anchor |
| Execution | ghi/đọc cơ bản, `run_python` bật | giới hạn byte, chặn symlink, đọc lại, `run_python` tắt + rlimit/container |
| API | local, không auth | token store bắt buộc, scope, rate limit, body cap, problem+json |
| CLI | vài lệnh, exit 0/1 | 11 lệnh, exit 0/1/2/3/4/5 theo hợp đồng |
| Quality gates | 18 test | 246 test, coverage gate, ruff, mypy strict, bandit, 15 probe |

---

## 5. Cách tái lập

```bash
git clone https://github.com/checken1994/WhyWard && cd WhyWard
git checkout <commit-nghiệm-thu>

make test          # 246 test, không cần cài gì ngoài Python 3.11+
make lint type security
make coverage      # cần coverage/pytest
make probes        # 15/15 OK
make acceptance    # cần git tree sạch
```

Trên Windows (PowerShell):

```powershell
$env:PYTHONPATH = "src;tests"
python -m unittest discover -s tests -t tests
```

---

## 6. Những gì **chưa** kiểm được (và không được tính điểm)

1. **Nghiệm thu bởi AI độc lập.** Đã dựng harness + giao thức, nhưng người viết
   code không thể là người nghiệm thu. Báo cáo tự chạy trong
   `docs/acceptance/2026-10-26-nghiem-thu-tu-chay.md` chỉ có giá trị *tái lập*,
   không phải *nghiệm thu*.
2. **Cô lập container thật.** Máy kiểm không có Docker/Podman, nên nhánh
   `run_python` bằng container chưa được chạy; nhánh subprocess + rlimit đã được
   kiểm (timeout, giới hạn output, NUL args, đường dẫn tuyệt đối).
3. **Windows/macOS thật.** CI có khai báo ma trận nhưng kết quả chỉ có sau khi
   push; phần lớn kiểm nghiệm ở đây chạy trên Linux.
4. **Đa host, TLS, tải, backup/restore.** Chưa có môi trường; chưa tuyên bố.
5. **Review mật mã độc lập** cho envelope HMAC (dùng khoá đối xứng, chưa có
   Ed25519) và cho quản lý khoá.
6. **Chất lượng nội dung catalog mẫu.** Vẫn là fixture `demo_verified`, chỉ được
   profile `dev` chấp nhận.
7. **Đánh giá pháp lý** (EU AI Act, quy định Việt Nam). Cần luật sư, không phải
   kỹ sư — và không nên giả vờ đã làm.

---

## 7. Điểm lại theo rubric (thang 0–5, chỉ tính bằng chứng chạy được)

| Trục | 0.1.0 | 0.2.0 | Lý do thay đổi |
|---|---|---|---|
| Kiến trúc & ranh giới tin cậy | 3.0 | 3.5 | Registry ký + approval ràng buộc; vẫn HMAC đối xứng |
| Cưỡng chế bảo mật | 1.5 | 3.5 | 15/15 phát hiện đóng bằng cơ chế, có test âm tính |
| Bằng chứng & provenance | 2.0 | 3.5 | Chữ ký, freshness, lineage, manifest bắt buộc; chưa có ingestion thật |
| Khả năng kiểm toán | 2.0 | 4.0 | Ledger bền, khoá, anchor, export, verify theo anchor |
| Vận hành & API | 1.5 | 3.0 | Auth, scope, rate limit, readiness, kill switch; chưa TLS/multi-host |
| Chất lượng kỹ thuật | 2.0 | 4.0 | 246 test, coverage 88 %, ruff/mypy/bandit sạch, CI 3 tầng |
| Tài liệu & trung thực | 3.5 | 4.0 | Matrix truy vết, tài liệu khớp hành vi, nêu rõ giới hạn |
| Sẵn sàng production | 1.0 | 2.0 | Vẫn thiếu TLS, đa host, review mật mã, nghiệm thu độc lập |
| **Trung bình** | **≈2.0** | **≈3.5** | |

Điểm 3.5 nghĩa là: **một control plane dùng được trong môi trường kiểm soát, có
thể chứng minh hành vi, chưa phải sản phẩm bảo mật đã được audit độc lập.**
Không có trục nào được cộng điểm vì "đã viết tài liệu".

---

## 8. Việc tiếp theo (theo thứ tự, không đổi thứ tự vì lý do hấp dẫn)

1. **Nghiệm thu độc lập thật** — giao repo cho một AI khác (không transcript) chạy
   `docs/acceptance/INDEPENDENCE.md`; công bố artefact.
2. Chạy nhánh container trên máy có Docker/Podman, ghi kết quả riêng.
3. Ingestion USGS thật: lưu raw record + provenance từng field, staging/quarantine.
4. Ed25519 cho policy/evidence/ledger; tách khoá ingest khỏi code ingest.
5. Used-token store + kill switch dùng chung giữa nhiều host.
6. TLS/mTLS qua gateway; log shipping ra sink append-only.
7. Review bảo mật bên ngoài cho threat model và envelope.

---

## Phụ lục — Những tuyên bố **không** đưa ra

- Không nói "an toàn", "không thể bypass", "production-ready".
- Không nói đã kiểm trên Windows/macOS nếu chưa thấy log CI.
- Không nói `run_python` được cô lập ở cấp OS khi không có container runtime.
- Không nói catalog mẫu là dữ liệu USGS mới; nó là fixture.
- Không nói đã nghiệm thu độc lập khi chưa có báo cáo của bên thứ ba.
