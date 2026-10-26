# Roadmap WhyWard

Nguyên tắc roadmap: không tăng capability chỉ vì lập luận nghe thuyết phục. Mỗi mức phải có bằng chứng chạy thật, test âm tính và đường rollback.

## 0.1 — Boundary MVP (hiện tại)

- [x] ControlPlane và state machine.
- [x] Policy/capability/read-back tối thiểu.
- [x] Hash-chain ledger + checkpoint.
- [x] Human comprehension gate dạng dữ liệu.
- [x] KnowledgeStore JSONL + manifest checksum.
- [x] Regression F1 cho Valdivia/Sumatra.
- [x] CLI và local API tối thiểu.

## 0.2 — Real source ingestion

- [ ] Source registry theo domain.
- [ ] USGS ingestion lấy field thật, lưu source record và retrieved_at.
- [ ] Staging/quarantine và promotion workflow.
- [ ] Freshness/completeness policy theo domain.
- [ ] Bỏ trạng thái `demo_verified` khỏi production profile.

## 0.3 — Worker adapters

- [ ] Adapter cho ít nhất một model API ngoài.
- [ ] Adapter cho một coding agent ngoài ở chế độ proposal-only.
- [ ] Ghi provider/model/version và lineage của context.
- [ ] Benchmark so sánh worker bằng held-out tasks; không để worker tự chấm mình.

## 0.4 — Execution isolation

- [ ] Chạy executor bằng user/container tách biệt.
- [ ] Resource limits và network egress ở tầng hạ tầng.
- [ ] Credential broker theo adapter, không truyền toàn bộ env.
- [ ] Git worktree sandbox cho patch proposal.
- [ ] Read-back bằng test/diff/API độc lập.

## 0.5 — External root of trust

- [ ] Bắt buộc ký policy/dataset/release trong profile production.
- [ ] Tách khóa ký khỏi worker và Control Core runtime nếu khả thi.
- [ ] Neo ledger checkpoint ra storage độc lập.
- [ ] Quy trình khôi phục và diễn tập mất/lộ khóa.
- [ ] Đường dừng độc lập ở tầng dịch vụ/OS.

## 0.6 — Human decision console

- [ ] Giao diện approval package bằng ngôn ngữ dễ hiểu.
- [ ] Hiển thị disagreement, unknowns và vùng chưa kiểm chứng.
- [ ] Hai người duyệt cho thay đổi protected boundary.
- [ ] Decision record có thể xuất báo cáo kiểm toán.

## 0.7 — Governed self-change

- [ ] Patch proposal trong branch/worktree cô lập.
- [ ] Protected paths không cho autofix tự sửa.
- [ ] Independent delta review và regression window.
- [ ] Canary, rollback và đo false-fix/regression-introduced.

## 1.0 — Limited operation

Chỉ tuyên bố 1.0 sau khi:

- audit độc lập chạy lại các kịch bản trọng yếu;
- không còn fact production không nguồn trong domain đã bật;
- worker không vượt được protected boundary trong adversarial tests thuộc scope;
- rollback và kill-switch đã drill trên môi trường đích;
- tài liệu không tuyên bố vượt phạm vi đã kiểm chứng.
