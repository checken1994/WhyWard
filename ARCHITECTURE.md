# Kiến trúc WhyWard

## 1. Mục tiêu

WhyWard kiểm soát **biên tác động của AI**, không cố kiểm soát nội tâm của model và không cố kiểm soát toàn bộ thế giới bên ngoài.

Nó kiểm soát năm đường biên:

1. **Biên danh tính/phạm vi:** ai yêu cầu, nhiệm vụ gì, dữ liệu nào được dùng.
2. **Biên nhận thức:** AI nhận context nào; claim nào có bằng chứng.
3. **Biên hành động:** tool nào được chạy, trên tài nguyên nào, với capability nào.
4. **Biên kết luận:** kết quả nào được trả ra, ở verdict và scope nào.
5. **Biên thay đổi:** patch/policy/dataset nào được promote và rollback ra sao.

## 2. Các vùng tin cậy

### External Root of Trust

Nằm ngoài WhyWard và ngoài worker:

- hệ điều hành/cloud identity;
- khóa ký;
- người/tổ chức có thẩm quyền phê duyệt;
- backup và external anchor cho ledger checkpoint;
- cơ chế dừng dịch vụ ở tầng nền tảng.

WhyWard phải khai báo đây là giả định tin cậy. Nếu tầng này bị chiếm hoàn toàn, WhyWard ở tầng ứng dụng không tự cứu được.

### Control Core

Module chính: `control.py`, `policy.py`, `capability.py`, `ledger.py`, phần deterministic của `review.py`.

Đặc tính:

- không gọi LLM để ra quyết định gate;
- không tự học;
- không tự sửa policy;
- chỉ nhận proposal/claim/action có schema;
- phát hành capability hẹp;
- ghi ledger;
- có thể withhold/block.

### Cognitive Workers

Module mẫu: `workers.py`.

Worker có thể là model ngoài, coding agent, expert hoặc script. Output của worker là `Proposal`/`Claim` chưa đáng tin. Worker không nhận ledger writer, policy signing key hoặc credentialproduction toàn cục.

### Execution Domain

Module hiện tại: `execution.py`.

Executor chỉ chạy tool allowlist trong workspace. Mỗi action phải khớp capability đã ký theo action ID, tool, resource và fingerprint. Sau khi ghi, executor đọc lại bytes và hash.

Giới hạn MVP: `run_python` vẫn dùng interpreter của host trong thư mục sandbox, vì vậy chưa phải OS sandbox hoàn chỉnh. Production phải dùng container/user tách biệt và policy hạ tầng.

### Evidence & Knowledge Plane

Module hiện tại: `evidence.py`.

- Catalog canonical cho MVP là JSONL shard + `manifest.json`.
- Manifest chứa dataset version, checksum và completeness.
- Snapshot được đóng băng đệ quy.
- Fact phải có source, lineage, observed fields, blind spots và review status.
- Superlative được tính từ dữ liệu, nhưng nếu catalog không khai báo đầy đủ, kết quả chỉ là `FOUND_SCOPED`.

Một FTS/search warehouse trong tương lai chỉ hỗ trợ tìm ứng viên bằng chứng; nó không được tự promote kết quả thành fact verified.

## 3. Luồng nhiệm vụ

```text
RECEIVED
  -> PROPOSED
  -> UNDER_REVIEW
  -> AWAITING_HUMAN (nếu risk/autonomy yêu cầu)
  -> AUTHORIZED
  -> EXECUTING
  -> VERIFYING
  -> COMPLETED / FAILED / FAILED_ROLLBACK_REQUIRED / WITHHELD / BLOCKED
```

`PASS_WITHIN_SCOPE` chỉ được dùng khi proposal qua review, execution và read-back trong phạm vi đã cấu hình.

## 4. Hợp đồng qua biên

- `Claim`: phát biểu + evidence IDs + assumptions.
- `Proposal`: hành động, alternatives, hậu quả làm/không làm, unknowns, rollback, autonomy và risk.
- `ActionRequest`: tool, resource, parameters, khả năng đảo ngược, kết quả kỳ vọng.
- `HumanDecision`: người duyệt, restatement, comprehension về action/consequence/rollback.
- `GateDecision`: verdict có scope, findings, trạng thái và execution results.

## 5. Các vai trò phản biện

Review deterministic hiện kiểm tra:

- **Missing piece:** claim thiếu evidence hoặc unknowns chưa khai báo.
- **Meta:** proposal rủi ro vừa trở lên thiếu alternatives/no-build.
- **Consequence:** thiếu hậu quả hoặc rollback.
- **Security:** tool/resource vi phạm policy.
- **Observability:** nguồn không được allowlist, evidence chưa reviewed hoặc thiếu blind spots.
- **Independence:** nhiều evidence cùng lineage không được tính là nhiều nguồn độc lập.

Các vai trò AI trong tương lai chỉ tạo thêm objection/claim. Chúng không bỏ phiếu thành chân lý.

## 6. Ranh giới chưa hoàn thiện

Bản 0.1.0 chưa có:

- process/container isolation thật;
- identity và authentication production cho API;
- secret manager/HSM;
- external anchoring tự động;
- policy signing bắt buộc trong deployment;
- ingestion pipeline đầy đủ;
- adapter cho các coding agent/model provider cụ thể;
- giao diện phê duyệt hoàn chỉnh;
- cơ chế rollback tự động tổng quát.

Các hạng mục này nằm trong `ROADMAP.md`, không được mô tả như đã hoàn thành.
