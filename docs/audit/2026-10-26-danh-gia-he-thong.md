# WhyWard 0.1.0 — Đánh giá hệ thống và lộ trình đạt chuẩn thế giới

| | |
|---|---|
| **Ngày đánh giá** | 2026-10-26 |
| **Commit** | `b0da4cb` — “Extract WhyWard standalone from Vietnam-Lab” |
| **Phạm vi** | toàn bộ repo: `src/whyward/*` (1 867 dòng), `tests/`, `examples/`, CI, docs, packaging |
| **Môi trường kiểm** | Linux, Python 3.11.2, chạy từ source (`PYTHONPATH=src`) và từ wheel cài trong venv |
| **Phương pháp** | đọc code theo luồng tin cậy → chạy test/CLI/API thật → 15 probe tấn công chủ động (tái lập được) → đối chiếu chuẩn quốc tế |
| **Bộ tái lập** | [`docs/audit/reproduce_findings.py`](reproduce_findings.py) — chạy: `PYTHONPATH=src python docs/audit/reproduce_findings.py` |
| **Kết quả probe** | **15/15 VULNERABLE** (mỗi probe mô tả một hành vi cần bị chặn ở chuẩn production) |
| **Kết quả test hiện có** | 18/18 pass (0.02 s) |
| **Điểm tổng (rubric §3)** | **≈ 2.0 / 5** — kiến trúc tốt, thực thi và bảo đảm chất lượng còn ở mức prototype |

> **Kết luận một câu.** WhyWard 0.1.0 là một *bản thiết kế đúng hướng và có kỷ luật ngôn ngữ* (nói rõ giới hạn, không thổi phồng), nhưng **các bảo đảm nó tuyên bố chưa được thực thi bằng cơ chế kỹ thuật**: phê duyệt của người không gắn với đề xuất, bằng chứng do worker tự khai vẫn được tin, capability dùng lại được sau restart, ledger hỏng âm thầm khi có hai writer, và toàn bộ dữ liệu freshness chỉ là metadata trang trí. Vì vậy hiện tại nó là **khung kiểm soát biên có thể demo**, chưa phải **control plane có thể đặt trước một tác nhân AI thật**.

---

## 1. Kết luận điều hành

### 1.1 Điều đáng giữ

1. **Luồng quyết định tách bạch và deterministic.** `submit_proposal` (`control.py:159`) không gọi LLM, không học, không tự sửa policy — đúng nguyên tắc “AI đề xuất, không tự phê duyệt”.
2. **Ngôn ngữ verdict trung thực.** `PASS_WITHIN_SCOPE`, `INSUFFICIENT_EVIDENCE`, `FOUND_SCOPED` — hiếm dự án dám đặt tên như vậy. Đây là tài sản thương hiệu, không phải chi tiết kỹ thuật.
3. **Capability có scope + fingerprint + TTL + one-use** (`capability.py:45-104`) — mô hình đúng, chỉ thiếu độ bền và thu hồi.
4. **Snapshot catalog bất biến, checksum, chống path escape** (`evidence.py:78-107`) — nền đúng cho provenance.
5. **Matcher thà thiếu còn hơn sai.** Ca “California 2004” trả `INSUFFICIENT_EVIDENCE` thay vì trả nhầm Sumatra; superlative trên catalog không khai complete chỉ trả `FOUND_SCOPED`.
6. **Tài liệu biết tự giới hạn.** `SECURITY.md`/`ROADMAP.md` không quảng bá quá phạm vi — đây là điều kiện cần để một hệ thống AI governance sống được với khách hàng doanh nghiệp.

### 1.2 Năm rủi ro chặn (phải đóng trước khi cho bất kỳ ai dùng thật)

| # | Rủi ro | Bằng chứng | Hậu quả thực tế |
|---|---|---|---|
| **P0-1** | Phê duyệt của người không bị ràng buộc vào đề xuất | probe **W-01**: một `HumanDecision` được chấp nhận cho hai proposal khác nhau; proposal thứ hai ghi được `prod/config/secret.txt` với verdict `PASS_WITHIN_SCOPE` | Toàn bộ “human gate” có thể bị vô hiệu bằng một approval cũ; audit sẽ ghi “đã được người duyệt” |
| **P0-2** | Bằng chứng tự khai được review tin | probe **W-02**: 2 `EvidenceRef` tự tạo (`review_status="verified"`, source/lineage tự chọn) đi qua review với **0 blocking finding** | Worker tự cấp bằng chứng cho chính mình → “evidence-gated” trở thành hình thức |
| **P0-3** | Chạy code tuỳ ý ở risk thấp, không cần người | probe **W-14**: proposal `LOW` + `run_python` → `PASS_WITHIN_SCOPE`, `human_required=False`, đọc được `/etc/passwd`, ghi file bằng UID host | Prompt injection → RCE trên host; đây là bề mặt tấn công lớn nhất của sản phẩm |
| **P0-4** | Ledger hỏng âm thầm khi >1 writer | probe **W-06**: 3 process, exit code đều `0`, 1200 event / 400 index duy nhất, `verify() → False: Unexpected index at event 3` | Audit trail mất giá trị đúng lúc cần nhất (sự cố, điều tra), mà không ai biết |
| **P0-5** | Kill switch không thu hồi được quyền đã cấp | probe **W-08**: cờ STOP bật → submit bị chặn, nhưng capability phát trước đó vẫn ghi `late.txt`; `control.py:279-292` không kiểm lại kill switch trước từng action | “Công tắc dừng” không dừng được việc đang chạy — vi phạm chính nguyên tắc 7 trong README |

Ngoài ra có 10 phát hiện P1/P2 (mục §5) và khoảng 25 khoảng trống “chuẩn thế giới” (§6, §9) chưa phải lỗi bảo mật nhưng là điều kiện để bán/triển khai cho tổ chức lớn.

---

## 2. Cách đánh giá và bằng chứng

### 2.1 Những gì đã chạy

```bash
# baseline chất lượng hiện có
PYTHONPATH=src python -m unittest discover -s tests -v      # 18 tests OK
PYTHONPATH=src python -m whyward.cli demo --catalog examples/catalog
python -m venv /tmp/venv && /tmp/venv/bin/pip install -e .   # cài đặt + entrypoint OK

# API thật (bind 127.0.0.1, gọi bằng curl)
GET /health → 200; GET /health?x=1 → 404
POST /ask (không credential) → 200 kèm dữ liệu catalog
POST /ask body 70 KB → 413; OPTIONS /ask → 501; HEAD /health → 501
Server: WhyWard/0.1.0 Python/3.11.2

# probe tấn công
PYTHONPATH=src python docs/audit/reproduce_findings.py
→ 15 probe | VULNERABLE: 15 | OK: 0
```

### 2.2 Những gì **chưa** kiểm (và phải nói rõ)

- Chưa có môi trường production để kiểm SLO, tải, multi-tenant, backup/restore.
- Chưa chạy penetration test độc lập, chưa review mật mã (HMAC usage, key management).
- Chưa kiểm trên Windows/macOS thật (CI có khai báo nhưng chưa xem kết quả run).
- Chưa đánh giá pháp lý (EU AI Act, Nghị định về AI của Việt Nam) — cần luật sư, không phải kỹ sư.
- Chất lượng *nội dung tri thức* của catalog mẫu không được đánh giá; nó là fixture.

### 2.3 Cách đọc điểm số

Thang 0–5, trong đó **5 = mức một control plane được audit độc lập, chạy production, có khách hàng doanh nghiệp**. Điểm đặt theo *bằng chứng chạy được*, không theo ý định trong tài liệu. Một tính năng được mô tả nhưng không có test âm tính chứng minh nó chặn được tấn công thì tính **một nửa** điểm.

---

## 3. Bảng điểm theo trục

| Trục | Trọng số | Điểm | Vì sao |
|---|---|---|---|
| Kiến trúc & mô hình mối đe doạ | 10% | **3.5** | Phân vùng tin cậy rõ, state machine rõ, ranh giới đúng; thiếu threat model dạng STRIDE/attack tree và thiếu sơ đồ luồng dữ liệu chi tiết |
| Ranh giới tin cậy & authorization | 20% | **2.0** | Capability đúng hình dạng nhưng phê duyệt không binding, bằng chứng tự khai, không có identity |
| Cách ly thực thi | 10% | **1.5** | Chỉ là thư mục + `subprocess`; không container/seccomp/netns/limit; `run_python` bật mặc định ở risk thấp |
| Bằng chứng & provenance | 15% | **2.0** | Có lineage/blind_spots/checksum nhưng freshness không thi hành, checksum tuỳ chọn, không ký record |
| Auditability & toàn vẹn log | 10% | **2.5** | Hash-chain đúng ý tưởng nhưng không có lock liên process, không fsync, không chữ ký từng event, payload thiếu nội dung quyết định |
| Kiểm thử & bảo đảm chất lượng | 10% | **1.5** | 18 test, không test cho `api.py`/`cli.py`, không coverage/lint/type-check/fuzz/property test, không test đồng thời |
| Vận hành production | 10% | **1.0** | Không auth, không rate limit, không metrics/tracing, không cấu hình qua env tách biệt, không graceful shutdown, không migration |
| API & identity | 5% | **1.0** | stdlib `http.server`, HTTP/1.0, không auth/TLS/versioning/problem+json/request-id |
| Tài liệu & minh bạch | 5% | **3.0** | Trung thực, có giới hạn rõ; nhưng chỉ tiếng Việt, lẫn tài liệu nội bộ (`WHYWARD_EXTRACTION_HANDOFF.md`, `PUBLISHING.md`), chưa có changelog/ADR |
| Kỹ thuật repo & chuỗi cung ứng | 5% | **1.5** | 1 commit, không tag/release, CI không pin SHA, không SBOM/lockfile, không CONTRIBUTING/CoC/kênh báo lỗ hổng thật |
| **Tổng có trọng số** | 100% | **≈ 2.0** | Prototype có kiến trúc tốt, chưa đủ để vận hành |

**Đọc điểm cho đúng:** 2.0/5 không phải “dở”. Với một MVP 1 837 dòng, đây là mức **trên trung bình về thiết kế, dưới chuẩn về bảo đảm**. Khoảng cách từ 2.0 lên 4.0 gần như không nằm ở việc viết thêm tính năng, mà ở **biến tuyên bố thành cơ chế có test âm tính**.

---

## 4. Những điểm làm tốt (cần giữ khi refactor)

| Điểm tốt | Vị trí | Vì sao quan trọng |
|---|---|---|
| Control core deterministic, không gọi LLM để ra quyết định gate | `control.py`, `review.py`, `policy.py` | Có thể audit, có thể test, không bị “model drift” |
| Verdict có scope, không có “đúng tuyệt đối” | `models.py:20-29` | Đúng triết lý “PASS ≠ đúng” |
| Capability gắn fingerprint toàn bộ action | `capability.py:26-27, 88-104` | Sửa một byte trong tham số là token vô hiệu |
| Sandbox chống path escape kể cả symlink | `execution.py:27-33` + probe | Đã kiểm: symlink ra ngoài bị chặn (`Resource escapes sandbox`) |
| Không dùng shell, argv trực tiếp, env tối thiểu | `execution.py:83-92` | Loại bỏ một lớp injection cổ điển |
| Read-back hash sau khi ghi | `execution.py:48-58` | Nguyên tắc “reality > model” có cơ chế |
| Catalog checksum + freeze đệ quy (`MappingProxyType`) | `evidence.py:23-28, 78-107` | Snapshot bất biến thật, có test |
| Matcher thận trọng, biết trả `AMBIGUOUS` | `evidence.py:241-281` | Hành vi đúng khi không chắc |
| Không có secret trong repo, `.gitignore` phủ runtime | `.gitignore` | Nền tảng để publish an toàn |
| Văn phong tài liệu không thổi phồng | `README`, `SECURITY`, `ROADMAP` | Điều kiện tin cậy với khách hàng kỹ thuật |

---

## 5. Phát hiện chi tiết

Mỗi phát hiện có: **bằng chứng** (probe hoặc `file:dòng`), **tác động**, **cách sửa**, **công sức** (S ≤ 1 ngày, M ≤ 1 tuần, L ≥ 2 tuần cho một người).

### 5.A Nhóm ranh giới tin cậy (P0)

#### W-01 · Phê duyệt của người không gắn với đề xuất — `P0` `M`

- **Bằng chứng:** `models.py:101-109` — `HumanDecision` không có `proposal_id`, `proposal_fingerprint`, `task_id`, `nonce`, không có chữ ký. `control.py:128-140` chỉ kiểm approver/restatement/comprehension. Probe W-01 tái sử dụng nguyên một decision cho proposal khác → `PASS_WITHIN_SCOPE`, ghi được file ngoài ý định của người duyệt.
- **Tác động:** human gate bị replay; audit trail ghi nhầm người chịu trách nhiệm; hai-người-duyệt (ROADMAP 0.6) sẽ vô nghĩa nếu không binding.
- **Cách sửa:**
  1. Thêm vào `HumanDecision`: `proposal_fingerprint`, `task_id`, `decided_at`, `expires_at`, `decision_nonce`, `approver_identity` (subject từ IdP, không phải chuỗi tự khai).
  2. `_validate_human_decision` từ chối nếu fingerprint lệch hoặc decision hết hạn/quá cũ.
  3. Ký decision bằng khóa của người duyệt (WebAuthn/passkey hoặc HMAC từ IdP) — xem Phụ lục B.1.
  4. Test âm tính: replay decision cho proposal khác phải trả `AWAITING_HUMAN` kèm lý do `DECISION_NOT_BOUND`.

#### W-02 · Bằng chứng tự khai được tin — `P0` `M`

- **Bằng chứng:** `control.py:76-77` (`register_evidence` công khai) và `control.py:167-168` (nhận `evidence=` từ caller); `review.py:37-72` chỉ đọc `ref.review_status` — một chuỗi do bên gọi tự đặt. Probe W-02: 0 blocking finding với bằng chứng bịa.
- **Tác động:** kẻ tấn công (hoặc chính model bị prompt injection) tự tạo “nguồn USGS đã verified” và đạt mọi ngưỡng lineage; toàn bộ giá trị “evidence-gated” biến mất.
- **Cách sửa:**
  1. Tách **Evidence Registry** khỏi worker API: chỉ ingestion pipeline / control core được ghi; registry ký từng `EvidenceRecord` (Ed25519, Sigstore) và lưu `content_hash` của payload nguồn.
  2. `review_proposal` chỉ nhận evidence **đã resolve từ registry**, từ chối `review_status` do caller cung cấp; bắt buộc `registry_signature` hợp lệ + `source_id` ∈ allowlist + `retrieved_at` trong cửa sổ freshness.
  3. `register_evidence` chuyển thành API nội bộ có capability riêng (không public).
  4. Test: evidence không ký → `UNSIGNED_EVIDENCE`; lineage tự khai nhưng trùng `content_hash` → tính là 1 lineage.

#### W-14 · `run_python` ở risk thấp = RCE có chủ đích — `P0` `L`

- **Bằng chứng:** `policy.py:23` bật `run_python` mặc định; `control.py:142-147` chỉ yêu cầu người khi risk ≥ HIGH hoặc action không reversible; probe W-14 đọc `/etc/passwd`, ghi file, UID host.
- **Tác động:** đây là bề mặt tấn công lớn nhất: prompt injection → thực thi mã trên host của control plane. `SECURITY.md` đã khai báo, nhưng **khai báo không phải kiểm soát**.
- **Cách sửa:**
  1. Đổi mặc định: `run_python` **tắt** trong `Policy.default()`; bật theo từng profile có tên (`dev-only`), và profile đó phải in cảnh báo khi khởi động.
  2. `run_python` luôn cần human approval bất kể risk (đưa vào `human_required_tools`).
  3. Chạy trong container tách biệt: `--network=none`, `--read-only`, `--cap-drop=ALL`, `--pids-limit`, `--memory`, `--cpus`, seccomp profile, chạy UID riêng không có quyền đọc secret.
  4. Chặn theo nội dung: chỉ cho chạy file đã qua review hash, không cho ghi file thực thi.

#### W-06 · Ledger hỏng âm thầm khi nhiều writer — `P0` `S`

- **Bằng chứng:** `ledger.py:24-36` nạp `_index`/`_head` một lần; `ledger.py:55-71` chỉ có `threading.Lock` (trong process), **không** `flock`/`msvcrt.locking`, không `fsync`, không kiểm tra `prev_hash` trên file trước khi ghi. Probe W-06: 3 process, exit 0 hết, ledger invalid.
- **Tác động:** mất tính toàn vẹn đúng lúc có sự cố (nhiều worker/service ghi song song); CLI sẽ crash (xem W-09) và không ai biết từ lúc nào.
- **Cách sửa:**
  1. Khóa file ghi (`fcntl.flock` exclusive, hoặc `msvcrt.locking` trên Windows) + `os.fsync` sau mỗi append + `O_APPEND`.
  2. Tốt hơn: **một writer duy nhất** (ledger service) nhận event qua queue; mọi thành phần khác gửi event.
  3. Khi mở ledger: nếu `index` cuối ≠ số event → fail fast với thông báo chứa `event_id` lỗi.
  4. Test: 8 process × 500 event → `verify() == True`.

#### W-08 · Kill switch không thu hồi capability — `P0` `S`

- **Bằng chứng:** `control.py:184-192` chỉ kiểm lúc submit; vòng lặp `control.py:279-292` không kiểm lại; `capability.py` không có `revoke()`; token sống 300 s.
- **Tác động:** “dừng khẩn cấp” không dừng được action đang chạy hoặc token đã phát.
- **Cách sửa:** kiểm kill switch **trước mỗi action**; thêm `CapabilityBroker.revoke(capability_id)` + danh sách thu hồi bền; kill switch bật → từ chối mọi `consume` ngay; test: bật cờ giữa 2 action → action 2 không chạy, task vào `FAILED_ROLLBACK_REQUIRED`.

#### W-07 · “One-use” chỉ đúng trong một process — `P1` `M`

- **Bằng chứng:** `capability.py:38-43, 99-104` — `_used` là `set` trong RAM. Probe W-07: token tiêu thụ lại được sau khi process restart với cùng secret.
- **Tác động:** replay sau restart/crash; scale ngang nhiều instance thì mỗi instance có registry riêng.
- **Cách sửa:** lưu used-token (hoặc nonce) vào store bền có TTL ≥ token TTL (SQLite/Redis/Postgres); token mang `issuer`, `audience`, `task_id`; thêm `nbf`; ký bằng khóa riêng của capability service, không dùng chung secret với policy.

#### W-15 · Exception thô ra khỏi control plane — `P1` `S`

- **Bằng chứng:** gọi `submit_proposal` trên task `COMPLETED` → `ValueError: Illegal task transition`. `api.py` không có endpoint submit nên chưa thành lỗi HTTP, nhưng SDK/HTTP layer tương lai sẽ biến thành 500.
- **Cách sửa:** định nghĩa error taxonomy (`WhyWardError` + `code`), trả `GateDecision` với `status=REJECTED_STATE` thay vì raise cho lỗi nghiệp vụ; chỉ raise cho lỗi lập trình.

### 5.B Nhóm toàn vẹn bằng chứng & policy

#### W-03 · `freshness` là metadata trang trí — `P1` `S`

- **Bằng chứng:** grep toàn bộ `src/`: không có chỗ nào đọc `freshness`, `valid_until`, `review_after`. Record có `valid_until: 1991-01-01` vẫn trả `PASS_WITHIN_SCOPE` (probe W-03).
- **Tác động:** fact stale được trình bày như fact đã kiểm; đây đúng là loại lỗi WhyWard sinh ra để chặn.
- **Cách sửa:** `KnowledgeStore.answer_query(..., now=...)`; record hết `valid_until` → `INSUFFICIENT_EVIDENCE` + lý do `STALE_AFTER`; quá `review_after` → hạ xuống `FOUND_SCOPED_STALE` (verdict mới) và bắt buộc hiển thị tuổi dữ liệu trong câu trả lời.

#### W-04 · Checksum tuỳ chọn, `record_count` bị bỏ qua — `P1` `S`

- **Bằng chứng:** `evidence.py:93-95` (`if expected and ...`), `record_count` không được đối chiếu. Probe W-04: `record_count=999` với 2 record → nạp bình thường; bỏ `sha256` → vẫn nạp.
- **Cách sửa:** bắt buộc `sha256`, bắt buộc khớp `record_count`; manifest tự ký (detached signature) và có `schema_version` được kiểm; từ chối shard lạ không khai trong manifest; thêm `dataset_digest` (Merkle root trên toàn bộ record) để so sánh giữa các môi trường.

#### W-05 · Policy thiếu key thì âm thầm nới lỏng — `P1` `S`

- **Bằng chứng:** `policy.py:65-78` dùng `.get(..., default)` cho mọi trường; `policy.py:119-120` `min_independent_lineages.get(risk, 1)`. Probe W-05: policy không khai `min_independent_lineages` → profile `critical` chỉ cần **1** lineage.
- **Tác động:** lỗi cấu hình (hoặc tấn công vào file policy) làm yếu kiểm soát mà không có cảnh báo; trái nguyên tắc fail-closed.
- **Cách sửa:** JSON Schema **required** đầy đủ + `additionalProperties: false`; thiếu key = lỗi khởi động; `required_lineages` raise nếu risk không được khai; log `policy_fingerprint` + `policy_version` khi start và ghi vào ledger.

#### W-11 · Profile mặc định vẫn nhận `demo_verified` — `P1` `S`

- **Bằng chứng:** `policy.py:32`; `evidence.py:151`; probe W-11. Trong khi `ROADMAP 0.2` yêu cầu bỏ khỏi production profile.
- **Cách sửa:** tách `Policy.dev()` / `Policy.production()`; profile production **không** chứa `demo_verified` và không chứa `demo-source`; ví dụ trong `examples/policy.json` đổi thành production-shaped; thêm test khẳng định default production từ chối fixture demo.

#### Thiếu: liên kết policy ↔ dữ liệu ↔ release — `P1` `M`

- Không có chữ ký bắt buộc cho policy/catalog/release (`policy.py:81-91`: nếu không truyền key thì bỏ qua chữ ký **hoàn toàn**).
- Không ghi vào ledger “phiên bản policy/dataset nào đã có hiệu lực cho quyết định này” (chỉ có `policy_fingerprint` trong event proposal — chưa đủ cho audit).
- **Cách sửa:** mọi artifact (policy, catalog snapshot, image) được ký; ledger event chứa `policy_digest`, `dataset_digest`, `image_digest`; deployment từ chối chạy nếu chữ ký không hợp lệ.

### 5.C Nhóm audit & ledger

| Phát hiện | Bằng chứng | Cách sửa |
|---|---|---|
| Event không có `schema_version`, không có `event_id`, `trace_id`, `actor_identity` (chỉ có chuỗi `actor`) | `ledger.py:55-71` | Event envelope có version + ULID + W3C trace-id + subject từ IdP |
| Payload không đủ để tái dựng quyết định (chỉ `goal_sha256`, `finding_codes`, không có nội dung proposal/approval) | `control.py:81-86, 171-181, 195-204` | Ghi `proposal_digest` + snapshot nội dung (hoặc reference tới object store bất biến) + `decision_digest` |
| Không ký từng event; checkpoint ký tuỳ chọn | `ledger.py:97-114` | Ký mỗi event bằng khóa ledger service; checkpoint đẩy ra WORM/Rekor theo chu kỳ; có witness độc lập |
| `verify()` đọc toàn file vào RAM, O(n) mỗi lần khởi động | `ledger.py:38-49, 73-95` | Streaming verify + incremental checkpoint; lưu `index/head` cache có chữ ký |
| Người duyệt tự khai chuỗi tên | `models.py:101-109` | Subject từ OIDC/SSO + chữ ký thiết bị; ledger ghi `idp_subject`, `auth_time`, `amr` |
| Không có cơ chế phát hiện **cắt đuôi** (truncation) nếu attacker có quyền file | `SECURITY.md` đã nêu | Checkpoint neo ngoài + đối chiếu `event_count` mỗi lần start; cảnh báo nếu ledger ngắn hơn checkpoint gần nhất |

### 5.D Nhóm API, CLI, vận hành

| # | Phát hiện | Bằng chứng | Mức | Cách sửa |
|---|---|---|---|---|
| A1 | Không có authentication/authorization; ai vào được cổng đều truy vấn được | probe W-12 | P0 (nếu bind ngoài localhost) | OIDC + mTLS/DPoP; scope theo tenant; authz theo từng endpoint |
| A2 | `http.server` + HTTP/1.0, không TLS, không giới hạn kích thước header, không timeout, không rate limit | `api.py:84`; curl cho thấy `HTTP/1.0` | P1 | Chuyển sang ASGI (FastAPI/Starlette + uvicorn) sau gateway; hoặc tối thiểu thêm `protocol_version="HTTP/1.1"`, `timeout`, body/header limit, token bucket |
| A3 | Routing so khớp chuỗi thô: `/health?x=1` → 404 | `api.py:36-60`; probe curl | P2 | Parse `urlsplit`, chuẩn hóa path |
| A4 | Không có `request-id`, structured log, metrics, tracing | `api.py:25-26` (log bị nuốt) | P1 | OTel SDK + `traceparent`; Prometheus `/metrics`; log JSON có `trace_id`, `verdict`, `policy_digest` |
| A5 | Trả `200` cho cả verdict bị withhold; client không phân biệt được “có câu trả lời” và “bị giữ lại” | `api.py:82` | P1 | Problem Details (RFC 9457) + mã lỗi ổn định; hoặc `200` kèm `verdict` nhưng thêm header `WhyWard-Verdict` và SDK bắt buộc kiểm |
| A6 | Thiếu security headers, lộ `Server: Python/3.11.2` | probe W-12 | P2 | Ẩn banner; `X-Content-Type-Options`, `Cache-Control: no-store`, CSP nếu có UI |
| A7 | CLI `verify-ledger` crash (traceback) khi ledger bị sửa; exit 1 thay vì JSON + exit code tài liệu hóa | `cli.py:148-152`; probe W-09 | P1 | Bắt `ValueError` → in JSON `{valid:false,...}` + `exit 2` |
| A8 | CLI `ask` luôn `exit 0`, kể cả khi `INSUFFICIENT_EVIDENCE` | `cli.py:63-71`; probe W-10 | P2 | Exit code theo verdict (0 = có câu trả lời, 3 = withhold, 4 = blocked) + tài liệu hóa |
| A9 | Secret ngẫu nhiên im lặng nếu thiếu env → token không dùng được qua restart, không ai biết | `cli.py:26-30` | P1 | Bắt buộc secret trong production profile; fail fast; cảnh báo rõ ở dev profile |
| A10 | `read_text` đọc cả file 64 MB rồi mới cắt; `write_text` không giới hạn, luôn ghi đè, không lưu pre-image | `execution.py:43-71`; probe W-13 | P1 | Giới hạn byte đọc/ghi; `O_EXCL` hoặc policy overwrite; lưu pre-image hash vào ledger để rollback |
| A11 | Không có `/readyz`, không có graceful shutdown, không có version/commit trong health | `api.py:36-49` | P2 | `/livez`, `/readyz`, `/version` kèm git SHA + dataset digest |
| A12 | Không có migration/versioning cho schema dữ liệu (ledger, catalog, API) | — | P1 | SemVer cho 3 schema riêng; migration test; `schema_version` bắt buộc |

### 5.E Nhóm kỹ thuật phần mềm, test, chuỗi cung ứng

| Phát hiện | Bằng chứng | Cách sửa |
|---|---|---|
| Test chỉ phủ đường đi chính; `api.py`, `cli.py` không có test nào; `review.py` chỉ được test gián tiếp | `grep` trong `tests/`: api 0, cli 0, review 0 | Thêm test cho từng finding W-01..W-15 (chúng đã sẵn ở dạng probe) |
| Không có coverage, lint, type-check trong CI | `.github/workflows/test.yml` chỉ chạy unittest | `ruff`, `mypy --strict` (hoặc pyright), `coverage --fail-under=85`, `bandit`, `pip-audit` |
| Không test đồng thời, không property-based, không fuzz | — | `hypothesis` cho invariant; fuzz parser capability/ledger/catalog; test 8 writer đồng thời |
| CI dùng action theo tag, không `permissions:` | `test.yml:16-17`, không có block `permissions` | Pin theo SHA, `permissions: contents: read`, `persist-credentials: false`, thêm job build wheel + `twine check` + SBOM |
| Không lockfile, không SBOM, không ký release | `pyproject.toml` | `uv.lock`/`pip-compile`; CycloneDX SBOM; Sigstore/cosign ký artifact + SLSA provenance |
| 1 commit duy nhất, không tag, không CHANGELOG, không ADR | `git log` | Lịch sử commit có nghĩa; tag `v0.1.0`; `CHANGELOG.md` (Keep a Changelog); `docs/adr/` cho các quyết định kiến trúc |
| Không có CONTRIBUTING, CODE_OF_CONDUCT, kênh báo lỗ hổng thật, template issue/PR | `SECURITY.md` còn placeholder “khi repo được công bố” | `SECURITY.md` có email/PGP + thời hạn phản hồi; `CONTRIBUTING.md`; `CODE_OF_CONDUCT.md`; template; `GOVERNANCE.md` |
| Tài liệu chỉ tiếng Việt, lẫn tài liệu nội bộ | `PUBLISHING.md`, `WHYWARD_EXTRACTION_HANDOFF.md` | Tiếng Anh là ngôn ngữ gốc của repo công khai; giữ bản tiếng Việt trong `docs/vi/`; chuyển tài liệu nội bộ ra ngoài repo |
| Không có benchmark cho matcher; ngưỡng 50/35/20/15 là magic number | `evidence.py:219-281` | Bộ eval có nhãn (precision/recall/F1, đặc biệt false-answer rate); biến ngưỡng thành cấu hình versioned; test hồi quy theo từng loại câu hỏi |
| `_detect_attribute` hard-code cụm từ Việt/Anh | `evidence.py:121-129` | Chuyển sang taxonomy thuộc tính theo domain + mapping đa ngữ có test; không suy luận ý định bằng substring |
| Không có `py.typed`, không có public API stability policy | `pyproject.toml` | Thêm `py.typed`, đánh dấu `_internal`, công bố chính sách SemVer cho API |
| `ActionRequest.parameters` là dict trong dataclass `frozen` | `models.py:74-81` | Dùng mapping bất biến hoặc tính fingerprint ngay khi tạo; test mutation sau khi issue token |

---

## 6. Đối chiếu chuẩn quốc tế

Bảng dưới đây trả lời câu hỏi “chuẩn thế giới” nghĩa là gì với **loại sản phẩm này**, và WhyWard đang ở đâu.

### 6.1 Quản trị & quản lý rủi ro AI

| Chuẩn | Yêu cầu cốt lõi | Hiện trạng WhyWard | Việc cần làm |
|---|---|---|---|
| **NIST AI RMF 1.0** (GOVERN/MAP/MEASURE/MANAGE) | Vai trò, trách nhiệm, ngưỡng rủi ro, đo lường, ứng phó | Có ngôn ngữ risk tier và human gate; thiếu GOVERN (owner, policy review cadence), thiếu MEASURE (metric, ngưỡng chấp nhận) | Viết `docs/governance/rmf-mapping.md`; gắn từng control với hàm RMF; định nghĩa risk appetite |
| **NIST AI 600-1** (Generative AI Profile) | Rủi ro đặc thù GenAI: hallucination, injection, lộ dữ liệu | Có `INSUFFICIENT_EVIDENCE`; chưa có chống prompt injection ở tầng worker | Red-team suite cho injection/indirect injection; sandbox context |
| **ISO/IEC 42001:2023** (AIMS) | Hệ thống quản lý, đánh giá rủi ro, cải tiến liên tục | Chưa có quy trình, chỉ có code | Bộ tài liệu AIMS tối thiểu: scope, risk register, internal audit, CAPA |
| **ISO/IEC 23894** | Risk management guidance cho AI | — | Risk register có owner + review date |
| **EU AI Act** | Art. 12 record-keeping, Art. 14 human oversight, Art. 15 robustness/cyber, Art. 9 risk mgmt (mức high-risk); nghĩa vụ GPAI nếu dùng model nền | Art. 12 gần đúng hướng nhưng ledger không đủ chi tiết; Art. 14 hình thức (W-01); Art. 15 chưa có | Ledger đủ tái dựng; decision binding; test robustness; tài liệu kỹ thuật theo Annex IV; kiểm tra mốc áp dụng với luật sư |

### 6.2 An ninh ứng dụng AI

| Chuẩn / bộ threat | Liên quan | Hiện trạng |
|---|---|---|
| **OWASP Top 10 for LLM Applications** (LLM01 prompt injection, LLM06 excessive agency, LLM10 unbounded consumption, LLM03 supply chain…) | WhyWard chính là control cho LLM06/LLM01 | Chưa chặn được LLM06 (W-14), chưa có test injection (LLM01), chưa giới hạn tài nguyên (LLM10 — W-13) |
| **OWASP GenAI — Agentic AI threats** (memory/context poisoning, tool misuse, privilege compromise, identity spoofing, repudiation, resource overload, rogue agents) | Bản đồ hoá trực tiếp sang control plane | Có mô hình “worker không đáng tin” nhưng thiếu identity, thiếu non-repudiation, thiếu rate limit |
| **MITRE ATLAS** | Kỹ thuật tấn công ML | Chưa map; nên map mỗi control ↔ technique |
| **SAIF (Google) / AI security posture** | Kiểm soát theo lớp | Dùng làm checklist bổ sung |

### 6.3 Toàn vẹn, bằng chứng, chuỗi cung ứng

| Chuẩn | Yêu cầu | Hiện trạng | Việc cần làm |
|---|---|---|---|
| **W3C PROV-O** | Mô hình provenance: entity/activity/agent | Có lineage_id, source_id, retrieved_at — dạng tự chế | Xuất provenance dưới dạng PROV-JSON; dùng `prov:wasDerivedFrom`, `prov:wasGeneratedBy` |
| **in-toto / SLSA v1.0** | Build provenance, chống tráo artifact | Không có | Ký wheel + SBOM; attestation SLSA L2→L3; verify khi deploy |
| **Sigstore (cosign, Rekor)** | Ký + transparency log | Không có | Ký policy/catalog/decision; đẩy checkpoint lên Rekor |
| **RFC 9162 (Certificate Transparency) / Merkle log** | Log chỉ-append có bằng chứng bao hàm | Hash-chain tuyến tính, không có inclusion proof | Merkle tree + proof API để bên thứ ba kiểm một event cụ thể |
| **The Update Framework (TUF)** | Cập nhật an toàn trước rollback/freeze | Không có | Áp dụng cho phân phối policy/catalog |
| **CycloneDX / SPDX** | SBOM | Không có | Sinh trong CI, ký, lưu cùng release |

### 6.4 Vận hành, API, dữ liệu

| Chuẩn | Yêu cầu | Hiện trạng |
|---|---|---|
| **OpenTelemetry (GenAI semconv) + W3C Trace Context** | Trace xuyên worker → gate → executor | Không có |
| **Prometheus/OpenMetrics + SLO** | Metric, alert, error budget | Không có |
| **RFC 9457 Problem Details** | Lỗi máy đọc được, mã ổn định | Không có |
| **OpenAPI 3.1** | Hợp đồng API có schema, sinh client | Không có |
| **OAuth 2.1 / OIDC + DPoP (RFC 9449) / mTLS (RFC 8705)** | Identity cho người và workload | Không có |
| **SPIFFE/SPIRE** | Workload identity giữa các service | Không có |
| **ISO/IEC 27001:2022 (A.5.15, A.8.15, A.8.16, A.8.8)** | Access control, logging, monitoring, vuln mgmt | Một phần logging |
| **SOC 2 Type II** | Bằng chứng kiểm soát vận hành liên tục | Chưa có quy trình |
| **ISO/IEC 29147 & 30111** | Tiếp nhận & xử lý lỗ hổng | `SECURITY.md` còn placeholder |
| **OpenSSF Scorecard** | 18 check về sức khoẻ repo | Điểm sẽ rất thấp (không pin, không review, không branch protection…) |

---

## 7. Kiến trúc đích (v1.0)

Nguyên tắc: **giữ control core nhỏ và deterministic**, đẩy mọi thứ “có thể bị compromise” ra ngoài và biến mọi tuyên bố thành một kiểm tra chạy được.

```text
                       ┌──────────────────────────────┐
   Người duyệt ───────►│ Decision Service             │  (OIDC + passkey/WebAuthn)
   (IdP subject)       │ - binding: proposal_digest   │
                       │ - dual control cho critical  │
                       │ - decision có chữ ký, hạn    │
                       └──────────────┬───────────────┘
                                      │ signed decision
 ┌─────────────┐   proposal   ┌───────▼──────────────────────────┐
 │ AI worker   │─────────────►│ Control Core (deterministic)      │
 │ (untrusted) │◄─────────────│ policy │ review │ state machine   │
 └─────────────┘   verdict    │ evidence gate │ ledger writer    │
        │                     └───┬───────────────┬──────────────┘
        │ claim/evidence ref       │ capability    │ event
        ▼                          ▼               ▼
 ┌────────────────────┐   ┌──────────────────┐  ┌──────────────────────┐
 │ Evidence Registry  │   │ Capability Svc   │  │ Ledger + Anchor      │
 │ - ingestion có ký  │   │ - durable nonce  │  │ - 1 writer, flock    │
 │ - record ký        │   │ - revoke         │  │ - event ký, Merkle   │
 │ - freshness policy │   │ - audience/TTL   │  │ - WORM/Rekor witness │
 │ - staging→promote  │   └────────┬─────────┘  └──────────────────────┘
 └────────────────────┘            │
                          ┌────────▼─────────────────────────┐
                          │ Execution Broker (isolated)      │
                          │ container/gVisor, no egress,     │
                          │ seccomp, cgroup limits, no secret│
                          │ read-back + pre-image journal    │
                          └──────────────────────────────────┘
```

### 7.1 Thay đổi mô hình dữ liệu bắt buộc

```text
EvidenceRecord (mới)
  evidence_id, source_id, source_record_id, retrieved_at, content_hash
  observed_fields[], blind_spots[], freshness{valid_from,valid_until,review_after}
  registry_signature, registry_key_id, pipeline_version, dataset_digest

HumanDecision (sửa)
  + proposal_digest, task_id, approver_subject, idp_issuer, auth_time, amr[]
  + decision_signature, expires_at, nonce

LedgerEvent (sửa)
  + schema_version, event_id (ULID), trace_id, actor{subject, kind}
  + decision_digest, policy_digest, dataset_digest, image_digest
  + signature{key_id, alg, value}

Capability (sửa)
  + capability_id, issuer, audience, task_id, nbf, revocable, revocation_ref
  + not_after; used-registry bền theo nonce
```

### 7.2 Ba thay đổi kiến trúc có đòn bẩy lớn nhất

1. **Một writer duy nhất cho ledger** (service nhỏ, nhận event qua queue nội bộ). Giải quyết W-06, W-09, chuẩn bị cho Merkle/anchor, và cho phép ký từng event.
2. **Evidence Registry là biên giới tin cậy duy nhất** giữa dữ liệu thật và review. Giải quyết W-02, W-03, W-04 và là điều kiện để bán “provenance” như một tính năng.
3. **Execution Broker tách process/UID/network**, `run_python` mặc định tắt. Giải quyết W-14, W-13, W-08.

---

## 8. Lộ trình hoàn thiện

Bốn giai đoạn, mỗi giai đoạn có **Definition of Done đo được**. Thời lượng giả định 2–3 kỹ sư; một người làm thì nhân ~2.5.

### Giai đoạn 0 — “Stop the bleed” (2 tuần, ~4 person-week)

Mục tiêu: biến 5 rủi ro P0 thành test âm tính đang chạy xanh trong CI.

| Việc | DoD |
|---|---|
| Binding approval (W-01) | Probe W-01 → `OK`; test: replay decision cho proposal khác bị từ chối với mã `DECISION_NOT_BOUND` |
| Evidence Registry tối thiểu có ký HMAC/Ed25519 (W-02) | Probe W-02 → `OK`; evidence không ký bị loại; API `register_evidence` không còn public |
| Tắt `run_python` trong default policy + bắt buộc human (W-14) | Probe W-14 → `OK` hoặc bị chặn bởi policy; `Policy.default()` không chứa `run_python` |
| Ledger lock + fsync + fail-fast (W-06) | Probe W-06 → `OK` (8 process × 500 event, `verify()=True`) |
| Kill switch theo từng action + revoke capability (W-08) | Probe W-08 → `OK` |
| CLI/API fail-safe (W-09, W-10, A5, A7) | `verify-ledger` trả JSON + exit 2; exit code theo verdict; problem+json |
| CI: ruff + mypy + coverage ≥ 80% + action pin + `permissions:` | CI đỏ nếu vi phạm; `reproduce_findings.py` chạy như job “adversarial (expected OK)” |

**Exit gate:** 15/15 probe `OK`; coverage ≥ 80%; không còn `except Exception` nuốt lỗi ở control/execution.

### Giai đoạn 1 — v0.2: Bằng chứng thật & provenance (6 tuần, ~14 person-week)

| Việc | DoD |
|---|---|
| Ingestion pipeline USGS (hoặc nguồn domain chọn) có staging → quarantine → promote | Fact production có `retrieved_at`, `content_hash`, chữ ký; chạy lại được, idempotent |
| Freshness & completeness policy theo domain (W-03, W-04) | Record stale trả `INSUFFICIENT_EVIDENCE`; manifest thiếu checksum bị từ chối |
| Profile `dev` vs `production` tách biệt (W-11) | Test khẳng định production từ chối `demo_verified`/`demo-source` |
| Policy strict load + JSON Schema + chữ ký bắt buộc (W-05) | Thiếu key = fail fast; policy digest vào ledger |
| Provenance export (PROV-JSON) + `dataset_digest` | Cùng một câu hỏi trả cùng một digest trên 2 môi trường |
| Benchmark matcher có nhãn | Báo cáo precision/recall/false-answer; ngưỡng cấu hình hóa, có hồi quy |

**Exit gate:** 0 fact production không có nguồn; độ chính xác matcher được đo trên ≥ 200 câu hỏi, false-answer = 0; `demo_verified` không thể xuất hiện trong production.

### Giai đoạn 2 — v0.3–0.5: Cách ly, identity, root of trust (10 tuần, ~24 person-week)

| Việc | DoD |
|---|---|
| Execution broker chạy container/gVisor: no egress, read-only, seccomp, cgroup, UID riêng | Test escape: `/etc/passwd`, network, fork bomb, ghi ngoài workspace đều thất bại; hết CPU/mem bị kill có kiểm soát |
| Capability service bền + thu hồi + audience + nonce store | Replay sau restart bị chặn; revoke có hiệu lực < 1 s; test đa instance |
| API gateway: OIDC, mTLS/DPoP, rate limit, quota, problem+json, OpenAPI | Pentest nội bộ không tìm thấy đường ẩn danh; contract test sinh client |
| Signing & anchoring: policy/catalog/release ký; checkpoint → WORM/Rekor | Kiểm tra chữ ký trong pipeline deploy; mất file ledger bị phát hiện nhờ anchor |
| Observability: OTel + Prometheus + dashboard + alert | Có SLO 99.9%, alert khi `verify()` fail, khi kill switch bật, khi rate limit vượt ngưỡng |
| Incident response & drills | Diễn tập mất khóa, lộ khóa, ledger truncation, rollback; có runbook |

**Exit gate:** red-team nội bộ 2 tuần không vượt được biên; mọi control P0/P1 có test tự động; tài liệu vận hành đủ để người khác on-call.

### Giai đoạn 3 — v0.6–0.7: Con người & tự thay đổi có kiểm soát (12 tuần, ~20 person-week)

| Việc | DoD |
|---|---|
| Decision console: approval package dễ hiểu, hiển thị disagreement/unknowns/vùng chưa kiểm | Đo được thời gian ra quyết định và tỉ lệ approve-mù (khảo sát) |
| Dual control cho thay đổi biên (policy, protected path) | Không thể approve một mình; test 4-eyes |
| Governed self-change: worktree cô lập, protected paths, delta review, canary, rollback | Đo false-fix rate & regression-introduced; rollback tự động khi canary đỏ |
| Audit report export | Báo cáo kiểm toán 1 câu hỏi = 1 file có thể đưa cho auditor |

**Exit gate (điều kiện gọi 1.0):** xem §10.

---

## 9. Bộ bảo đảm chất lượng “chuẩn thế giới”

### 9.1 Test pyramid mục tiêu

| Lớp | Hiện có | Cần |
|---|---|---|
| Unit (deterministic, < 1 s) | 18 | ≥ 150, phủ policy/capability/ledger/evidence/execution/review |
| Contract | 0 | OpenAPI + schema JSON cho ledger/catalog/decision; test tương thích ngược |
| Integration | ~5 | API, CLI, ledger đa process, signing, anchor |
| **Adversarial (âm tính)** | 0 | Chính là 15 probe W-01..W-15 + injection corpus + replay/TOCTOU/symlink/unicode |
| Property-based | 0 | Invariant: “không action nào chạy mà không có capability hợp lệ”, “không verdict PASS nếu thiếu evidence đã ký”, “ledger luôn verify sau N writer” |
| Fuzz | 0 | Parser token capability, loader catalog, hash-chain verifier, API body |
| Mutation testing | 0 | Mục tiêu mutation score ≥ 75% trên `policy.py`, `capability.py`, `review.py` |
| Performance/SLO | 0 | p95 `/ask` < 100 ms với 100k record; ledger ≥ 5k event/s; RAM ổn định |
| Chaos/drill | 0 | Kill switch giữa chừng, mất anchor, crash giữa write, đầy đĩa, xoay khóa |

### 9.2 Bộ test tấn công tối thiểu (theo threat model của chính repo)

1. **Forged evidence / lineage** — evidence không ký, lineage trùng `content_hash`, source ngoài allowlist.
2. **Replay** — decision, capability, ledger segment, question (idempotency key).
3. **Confused deputy** — worker A dùng capability của task B; tool/resource chéo.
4. **Injection** — prompt injection trong nội dung file/document được đưa vào context worker.
5. **TOCTOU** — symlink đổi giữa `_resolve` và `write`; file đổi giữa read-back và verify.
6. **Resource exhaustion** — 1 GB file, 10⁵ action trong proposal, nested JSON sâu, subprocess fork bomb.
7. **Poisoning** — record độc hại trong staging cố tự promote; manifest sửa `record_count`.
8. **Repudiation** — người duyệt phủ nhận; yêu cầu chữ ký + log có `auth_time`.
9. **Withhold correctness** — hệ thống không được trả lời khi thiếu evidence (đo false-answer = 0).

### 9.3 Metric cần công bố công khai (tạo niềm tin)

- **False-answer rate** trên benchmark: mục tiêu 0 (bỏ trống thay vì đoán).
- **Withhold rate** (tỉ lệ câu bị giữ lại) — trung thực về giới hạn.
- **Time-to-detect** ledger corruption; **time-to-revoke** capability.
- **Coverage của control ↔ threat**: bao nhiêu % threat trong threat model có test tấn công tương ứng.
- **Mutation score** của control core.
- **Số fact production thiếu nguồn** — phải luôn bằng 0.

---

## 10. Checklist “world-class” (dùng làm cổng cho v1.0)

Mỗi dòng phải trả lời được bằng **một lệnh hoặc một liên kết**, không bằng lời khẳng định.

**An ninh & biên**
- [ ] 0 probe trong `reproduce_findings.py` trả `VULNERABLE`
- [ ] Không action nào chạy mà không có capability có audience + nonce bền
- [ ] Kill switch có hiệu lực < 1 s trên cả action đang chạy và token đã phát
- [ ] Execution trong sandbox OS-level; test escape (file, net, proc, resource) đỏ
- [ ] Mọi evidence dùng trong review đều có chữ ký registry + kiểm freshness
- [ ] Approval binding + dual control cho thay đổi biên; repudiation test pass
- [ ] Bí mật trong KMS/HSM; không có secret trong env của worker; rotation drill

**Toàn vẹn & audit**
- [ ] Ledger: 1 writer, fsync, event ký, Merkle proof, anchor ngoài (WORM/Rekor)
- [ ] Tái dựng được một quyết định 6 tháng trước chỉ từ ledger (có test)
- [ ] `verify` phát hiện cả truncation, không chỉ sửa giữa dòng
- [ ] Mọi artifact (policy/catalog/image/wheel) ký + SBOM + provenance SLSA

**Chất lượng kỹ thuật**
- [ ] Coverage ≥ 85% dòng, ≥ 75% mutation score trên control core
- [ ] mypy strict + ruff sạch; 0 warning; CI < 10 phút
- [ ] API có OpenAPI 3.1, problem+json, request-id, auth, rate limit, SLO
- [ ] Test đa nền tảng (Linux/Windows/macOS × 3.11–3.13) xanh
- [ ] Không endpoint/CLI nào trả 200 khi bị withhold mà không có mã phân biệt

**Vận hành & tổ chức**
- [ ] Runbook + incident drills + RTO/RPO công bố
- [ ] `SECURITY.md` có kênh thật, SLA phản hồi, PGP; đã diễn tập nhận báo cáo
- [ ] Changelog, SemVer, deprecation policy, ADR cho quyết định lớn
- [ ] Tài liệu tiếng Anh là gốc; tiếng Việt là bản dịch; không có tài liệu nội bộ
- [ ] Benchmark công khai + báo cáo giới hạn; tuyên bố marketing khớp phạm vi kiểm chứng
- [ ] Audit độc lập bên thứ ba (pentest + review kiến trúc) đã chạy và công bố tóm tắt

**Sản phẩm**
- [ ] Adapter thật cho ≥ 1 model API và ≥ 1 coding agent, chạy proposal-only
- [ ] Benchmark worker trên held-out tasks; worker không tự chấm mình
- [ ] Console phê duyệt dùng được bởi người không kỹ thuật (đo bằng usability test)
- [ ] Rollback/canary cho thay đổi có kiểm soát; đo false-fix rate

---

## 11. Kế hoạch 90 ngày (bản rút gọn để bắt đầu ngay)

| Tuần | Việc | Người | Sản phẩm kiểm chứng |
|---|---|---|---|
| 1 | Binding approval + evidence registry tối thiểu | backend | 2 probe xanh, 2 test âm tính |
| 2 | Tắt `run_python` mặc định; container executor bản spike; ledger lock+fsync+fail-fast | backend/infra | 3 probe xanh; CI job adversarial |
| 3 | CLI/API fail-safe, error taxonomy, problem+json, exit code | backend | test CLI/API; coverage ≥ 80% |
| 4 | ruff + mypy strict + coverage gate + pin action + `permissions:` + SBOM | devops | CI đỏ khi vi phạm |
| 5–6 | Ingestion USGS + freshness/completeness + profile dev/production | data | 0 fact thiếu nguồn; stale bị chặn |
| 7–8 | Policy schema + ký artifact + digest vào ledger | backend/security | verify chữ ký trong pipeline |
| 9 | OTel + Prometheus + SLO + dashboard + alert | devops | 4 alert chạy thật; SLO 99.9% |
| 10 | API gateway: OIDC/mTLS/rate limit/OpenAPI | backend | pentest nội bộ không có đường ẩn danh |
| 11 | Đa writer/đa instance test; capability service bền + revoke | backend | replay/revoke test xanh |
| 12 | Red-team nội bộ 3 ngày + sửa + báo cáo; cập nhật docs tiếng Anh | cả nhóm | báo cáo red-team + 0 P0 mở |

---

## 12. Những quyết định cần chủ dự án chốt trước khi đi tiếp

1. **Mô hình triển khai:** thư viện nhúng trong tiến trình khách (hardening khác hoàn toàn) hay **service biên độc lập** (cần identity, HA, multi-tenant)? Roadmap hiện tại giả định service nhưng code là library.
2. **Một domain hay đa domain:** giữ “earthquake” làm domain tham chiếu rồi mở rộng, hay xây pipeline tổng quát ngay? Khuyến nghị: **một domain sâu** để chứng minh provenance, rồi mới tổng quát hoá.
3. **Ai là “external root of trust”** trong thực tế: KMS nào, IdP nào, ai giữ khóa ký policy, ai có quyền bật kill switch. Không có câu trả lời này thì mọi mục 0.5 của ROADMAP chỉ là giấy.
4. **Ngưỡng “đủ để công bố”**: có cần audit độc lập trước khi public repo không? Nếu có, dừng public cho tới Giai đoạn 2.
5. **Giấy phép & quản trị:** MIT + “WhyWard Project” hiện tại không nói ai sở hữu, ai merge, ai ký release. Cần `GOVERNANCE.md` nếu muốn cộng đồng.
6. **Ngôn ngữ gốc của repo:** tiếng Anh (khuyến nghị) hay tiếng Việt; quyết định này ảnh hưởng tới mọi tài liệu sau này.

---

## Phụ lục A — Chạy lại toàn bộ đánh giá

```bash
# 1) baseline
PYTHONPATH=src python -m unittest discover -s tests -v
PYTHONPATH=src python -m whyward.cli demo --catalog examples/catalog

# 2) 15 probe tấn công (kỳ vọng hiện tại: 15 VULNERABLE)
PYTHONPATH=src python docs/audit/reproduce_findings.py
PYTHONPATH=src python docs/audit/reproduce_findings.py --only W-01,W-06 --json /tmp/audit.json

# 3) mục tiêu sau Giai đoạn 0
#    → 15/15 OK, và script được nâng thành test trong CI
```

---

## Phụ lục B — Sửa nhanh (mức patch, có thể làm trong 1–2 ngày)

### B.1 Ràng buộc phê duyệt vào đề xuất

```python
# models.py
@dataclass(frozen=True)
class HumanDecision:
    decision_id: str
    approver: str
    approved: bool
    proposal_digest: str          # sha256(canonical_json(proposal))
    task_id: str
    restatement: str = ""
    reason: str = ""
    comprehension: dict[str, bool] = field(default_factory=dict)
    decided_at: str = field(default_factory=now_iso)
    expires_at: str = ""
    signature: str = ""           # ký bằng khóa của người duyệt / IdP

# control.py — trước khi chấp nhận
def _validate_human_decision(decision, proposal, task):
    problems = list(_existing_checks(decision, proposal))
    if decision.proposal_digest != proposal_digest(proposal):
        problems.append("DECISION_NOT_BOUND: approval không khớp proposal digest.")
    if decision.task_id != task.task_id:
        problems.append("DECISION_WRONG_TASK: approval thuộc task khác.")
    if decision.expires_at and decision.expires_at < now_iso():
        problems.append("DECISION_EXPIRED: approval đã hết hạn.")
    if not verify_decision_signature(decision):
        problems.append("DECISION_UNSIGNED: approval không có chữ ký hợp lệ.")
    return tuple(problems)
```

### B.2 Evidence registry ký + chỉ control core ghi

```python
class EvidenceRegistry:
    """Chỉ ingestion pipeline/control core được ghi. Worker chỉ được tham chiếu ID."""

    def __init__(self, signing_key: bytes, store: Path):
        self._key = signing_key
        self._store = store

    def register(self, record: dict) -> str:
        payload = canonical_json({k: record[k] for k in REQUIRED_FIELDS})
        eid = record["evidence_id"]
        signature = hmac.new(self._key, payload.encode(), hashlib.sha256).hexdigest()
        self._store.write_text(json.dumps({**record, "registry_signature": signature}))
        return eid

    def resolve(self, eid: str) -> dict:
        record = json.loads(self._store.read_text())
        payload = canonical_json({k: record[k] for k in REQUIRED_FIELDS})
        expected = hmac.new(self._key, payload.encode(), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(expected, record["registry_signature"]):
            raise PermissionError(f"UNSIGNED_EVIDENCE: {eid}")
        return record
```

`review_proposal` nhận `Mapping[str, EvidenceRecord]` **đã resolve**, không nhận `review_status` từ caller.

### B.3 Ledger: khóa liên process + fsync + event envelope

```python
import fcntl, os, uuid

def append(self, event_type, actor, payload):
    with self.path.open("a", encoding="utf-8") as handle:
        fcntl.flock(handle.fileno(), fcntl.LOCK_EX)      # Windows: msvcrt.locking
        try:
            self._reload_tail(handle)                    # đồng bộ index/head dưới lock
            core = {
                "schema_version": 1,
                "event_id": str(uuid.uuid4()),
                "index": self._index + 1,
                "timestamp": now_iso(),
                "event_type": event_type,
                "actor": actor,
                "payload": payload,
                "prev_hash": self._head,
            }
            event = {**core, "event_hash": self._hash_event(core)}
            handle.write(canonical_json(event) + "\n")
            handle.flush()
            os.fsync(handle.fileno())                    # chống mất event khi crash
            self._index += 1
            self._head = event["event_hash"]
            return event
        finally:
            fcntl.flock(handle.fileno(), fcntl.LOCK_UN)
```

### B.4 Freshness gate

```python
def _freshness_state(record, now: datetime) -> str:
    fresh = record.get("freshness", {})
    valid_until = fresh.get("valid_until")
    review_after = fresh.get("review_after")
    if valid_until and now > parse_date(valid_until):
        return "expired"
    if review_after and now > parse_date(review_after):
        return "review_overdue"
    return "current"
```

`answer_query` bỏ record `expired`; record `review_overdue` chỉ được trả với verdict mới `FOUND_STALE` và câu trả lời bắt buộc kèm “dữ liệu từ <ngày>, đã quá hạn review”.

### B.5 CLI fail-safe

```python
def _cmd_verify_ledger(args):
    try:
        ledger = Ledger(args.path)
    except ValueError as exc:
        _print_json({"valid": False, "message": str(exc)})
        return 2
    valid, message = ledger.verify()
    _print_json({"valid": valid, "message": message,
                 "checkpoint": ledger.checkpoint() if valid else None})
    return 0 if valid else 2
```

---

## Phụ lục C — Bảng ánh xạ phát hiện → chương chuẩn

| Phát hiện | NIST AI RMF | ISO/IEC 42001 (gợi ý) | OWASP LLM/Agentic | EU AI Act (nếu high-risk) |
|---|---|---|---|---|
| W-01 approval replay | GOVERN 1.4, MANAGE 2.2 | A.8.3 phân quyền | Excessive agency, trust exploitation | Art. 14 human oversight |
| W-02 evidence tự khai | MEASURE 2.5 | A.8.2 nguồn dữ liệu | Data/model poisoning, privilege compromise | Art. 10 data governance |
| W-03 freshness | MEASURE 2.4 | A.8.2 | Misinformation | Art. 15 accuracy |
| W-04 manifest | MEASURE 2.6 | A.8.1 | Supply chain | Art. 15 robustness |
| W-06 ledger race | MANAGE 4.1 | A.8.15 logging | Repudiation & untraceability | Art. 12 record-keeping |
| W-07 capability replay | MANAGE 2.4 | A.5.15 access control | Identity spoofing | Art. 15 cybersecurity |
| W-08 kill switch | MANAGE 2.3, 4.2 | A.5.24 sự cố | Rogue agent | Art. 14(4) stop |
| W-14 run_python | MEASURE 2.7 | A.8.19 cài đặt phần mềm | Unexpected RCE, tool misuse | Art. 15 cybersecurity |
| A1 API không auth | GOVERN 1.1 | A.5.15 | Identity spoofing | Art. 15 |

> Bảng này để đội kỹ thuật nói cùng ngôn ngữ với đội compliance; mỗi dòng nên trở thành một mục trong risk register có owner và ngày review.

---

## Phụ lục D — Ghi chú về tính trung thực của báo cáo này

- Mọi kết luận “VULNERABLE” đều kèm script tái lập; không có kết luận nào chỉ dựa trên đọc code mà không kiểm.
- Điểm số là **đánh giá của một người/agent**, không phải chứng nhận. Muốn dùng cho khách hàng, cần audit độc lập.
- Những mục “chưa kiểm” ở §2.2 không được tính là đã đạt.
- Khi sửa xong một mục, **đừng xoá probe** — hãy để nó chuyển từ `VULNERABLE` sang `OK` và đưa vào CI như một test hồi quy. Đó chính là cách một dự án trở nên đáng tin: mỗi tuyên bố có một bài test từng thất bại.
