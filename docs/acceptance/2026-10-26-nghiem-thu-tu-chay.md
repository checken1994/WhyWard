# Nghiệm thu WhyWard 0.2.0 — báo cáo **tự chạy** (chưa phải nghiệm thu độc lập)

| | |
|---|---|
| **Ngày** | 2026-10-26 |
| **Commit được kiểm** | `f17129cefbb010a3406c985bac73b252eedd1127` (nhánh `arena/6afa33c6-whyward`) |
| **Hình thức** | clone sạch từ `https://github.com/checken1994/WhyWard` vào thư mục tạm, không dùng bất kỳ artefact nào của máy phát triển |
| **Môi trường** | Linux 6.1.158, Python 3.11.2, không cài thêm package nào |
| **Lệnh** | `python3 docs/acceptance/acceptance_runner.py --report … --json …` |
| **Kết quả** | **ACCEPTED — 9/9 check PASS**, `dirty=False`, exit 0, 20.9 s |
| **Ai chạy** | **Chính agent đã viết code** |
| **Giá trị** | Chứng minh *tái lập được từ repo công khai*; **không** phải nghiệm thu độc lập |

> **Đọc kỹ dòng cuối.** Theo `docs/acceptance/INDEPENDENCE.md`, người viết code
> không thể là người nghiệm thu. Báo cáo này chỉ có giá trị chứng minh rằng
> **một máy khác, clone sạch, không cài gì, chạy đúng một lệnh, ra đúng kết quả**.
> Nó không thay thế được phán quyết của một AI/bên thứ ba không đọc transcript
> của người viết. Hạng mục nghiệm thu độc lập vì vậy vẫn **mở**.

---

## 1. Kết quả từng check

| ID | Nội dung | Kết quả | Bằng chứng đo được |
|---|---|---|---|
| A-01 | Xuất xứ repo rõ ràng, cây làm việc sạch | PASS | `commit=f17129c…` `dirty=False` |
| A-02 | Chỉ dùng thư viện chuẩn | PASS | 0 import ngoài stdlib |
| A-03 | Bộ test của repo | PASS | 243 test, `OK`, 17.9 s |
| A-04 | 15 probe tấn công | PASS | `15 probes: 15 OK, 0 VULNERABLE` |
| A-05 | Hành trình vận hành | PASS | demo 0 · verify 0 · anchor 0 · ask trả lời 0 · ask bị giữ lại **3** · report 0 · doctor 0 |
| A-06 | Phát hiện sửa đổi | PASS | sửa ledger = True · cắt ledger so với anchor = True · sửa catalog = True |
| A-07 | Bề mặt API | PASS | không token store → từ chối; ẩn danh → 401; có token → 200 + `WhyWard-Verdict: PASS_WITHIN_SCOPE`; kill switch → `/readyz` 503 và `/ask` `BLOCKED_BY_POLICY` |
| A-08 | Tài liệu không nói quá | PASS | mọi mã kiểm soát nêu trong `SECURITY.md` đều tồn tại trong `src/` |
| A-09 | Bỏ một kiểm soát bất kỳ thì bằng chứng phải phát hiện | PASS | `10 mutations: 10 detected, 0 undetected` |

Chi tiết thô (nguyên văn từ harness):

```text
[PASS] A-01 ... commit=f17129cefbb0 branch=arena/6afa33c6-whyward dirty=False
[PASS] A-02 ... 0 non-stdlib imports
[PASS] A-03 ... Ran 243 tests in 17.928s | OK
[PASS] A-04 ... 15 probes: 15 OK, 0 VULNERABLE
[PASS] A-05 ... demo rc=0 verify rc=0 (valid: true, events: 6) checkpoint rc=0
                anchored verify rc=0 ask(answered) rc=0 ask(withheld) rc=3
                report rc=0 doctor rc=0
[PASS] A-06 ... ledger_edit=True truncation=True catalog=True
[PASS] A-07 ... no_token_store_refused=True anonymous=401 health=200 authed=200
                verdict=PASS_WITHIN_SCOPE engage=200 ready=503 blocked=200
[PASS] A-09 ... 10 mutations: 10 detected, 0 undetected
[PASS] A-08 ... all referenced control codes are implemented
ACCEPTED — 9 checks passed
```

## 2. Bốn kiểm tra “tự suy luận lại” (không tin harness)

Người kiểm phải tự chạy lại, không chỉ đọc bảng trên. Kết quả tự chạy lần này:

```console
$ whyward ask "Động đất năm 2004 tại California có độ lớn bao nhiêu?" ...
exit code: 3            # bị giữ lại, không đoán

$ (sửa 1 dòng ledger) ; whyward verify-ledger ledger.jsonl --keyring demo.keyring.json
exit code: 2            # "valid": false

$ whyward serve --catalog examples/catalog --port 8765
exit code: 4            # NO_API_TOKENS — từ chối khởi động

$ PYTHONPATH=src python3 docs/audit/reproduce_findings.py
15 probes: 15 OK, 0 VULNERABLE

$ python3 docs/acceptance/falsification_check.py
10 mutations: 10 detected, 0 undetected
```

## 3. Những gì báo cáo này **không** chứng minh

1. **Không phải nghiệm thu độc lập** — người chạy là người viết.
2. **Không kiểm cô lập container** — máy kiểm không có Docker/Podman; nhánh
   container của `run_python` chưa được chạy ở đâu cả.
3. **Không kiểm Windows/macOS** — chỉ Linux + Python 3.11.2.
4. **Không kiểm tải, đa host, TLS, backup/restore.**
5. **Không kiểm mật mã** — envelope HMAC đối xứng chưa qua review độc lập.
6. **Không kiểm chất lượng nội dung catalog mẫu** — vẫn là fixture.

## 4. Điều kiện để chuyển báo cáo này thành nghiệm thu thật

Giao cho một AI khác (không có transcript của phiên này) hoặc một người không
viết code, và yêu cầu chạy đúng giao thức:

```bash
git clone https://github.com/checken1994/WhyWard && cd WhyWard
git checkout f17129cefbb010a3406c985bac73b252eedd1127   # hoặc commit mới hơn
git status --porcelain          # phải rỗng
python3 docs/acceptance/acceptance_runner.py \
        --report acceptance-report.md --json acceptance-report.json
```

Brief đầy đủ ở `docs/acceptance/INDEPENDENCE.md` §7. Bên nghiệm thu phải công bố:

- báo cáo markdown + JSON do harness sinh ra (không chỉnh sửa);
- commit, phiên bản Python, OS, thời điểm;
- tên model/người chạy và xác nhận **không** đọc transcript của người viết;
- mọi điểm tài liệu nói quá so với hành vi, kể cả khi harness PASS.

Chỉ khi đó mới được ghi "đã nghiệm thu độc lập". Cho đến lúc đó, trạng thái đúng
là: **đã có harness, đã tái lập được từ repo công khai, chưa nghiệm thu độc lập.**
