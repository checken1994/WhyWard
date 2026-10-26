# WhyWard

**WhyWard** là một *boundary control plane* cho AI: một cổng kiểm soát đứng giữa AI lao động và thế giới thật.

Tên gọi gồm hai phần:

- **Why** — câu hỏi “Tại sao?”: vì sao cần làm, bằng chứng đâu, còn thiếu gì, nếu sai thì sao?
- **Ward** — lớp canh giữ ở biên: AI không tự cấp quyền, tự thực thi việc nguy hiểm hoặc tự tuyên bố mình đúng.

WhyWard thay thế hướng đi “xây một bộ não AI tổng quát khác” bằng một lõi kiểm soát nhỏ hơn:

> AI đề xuất → WhyWard kiểm tra bằng chứng và quyền → sandbox thực thi trong biên → đọc lại kết quả từ thực tế → con người quyết định việc quan trọng → ghi dấu vết có thể kiểm toán.

## Nguyên tắc

1. **Reality > model.** Báo cáo của AI không thắng được kết quả chạy thật.
2. **PASS ≠ đúng.** PASS chỉ có nghĩa là chưa phát hiện lỗi trong phạm vi và cửa sổ quan sát đã khai báo.
3. **AI là bên đề xuất, không phải bên tự phê duyệt.**
4. **Quyền cấp capability nằm ngoài workspace của worker.**
5. **Mọi fact production phải truy được nguồn và lineage.**
6. **Chưa đủ bằng chứng thì withhold, không bịa và không fallback bừa.**
7. **Hành động phải nhỏ, quan sát được, có giới hạn và có đường rollback.**
8. **WhyWard không phải nguồn chân lý.** Nó là cơ chế ép hệ thống đối diện với bằng chứng và giới hạn của chính nó.

## Có gì trong bản 0.1.0?

- `ControlPlane` deterministic với state machine cho nhiệm vụ.
- Policy gate cho tool/resource được phép và protected paths.
- Capability token có chữ ký HMAC, giới hạn đúng action/resource, hết hạn và dùng một lần cho mỗi action.
- Sandbox executor tối thiểu cho `write_text`, `read_text`, `run_python` trong một thư mục chỉ định, kèm read-back hash.
- Ledger JSONL dạng hash-chain và checkpoint để neo ra ngoài.
- Human approval gate yêu cầu ghi nhận khả năng hiểu về hành động, hậu quả và rollback.
- Review roles dạng deterministic: missing piece, meta/alternatives, consequence, security, observability và independence.
- `KnowledgeStore` nạp catalog JSONL có manifest/checksum thành snapshot bất biến.
- Matcher sửa lỗi F1 kiểu cũ: hỏi Valdivia 1960 không cần biết trước đáp án 9.5; hỏi năm 2004 ở California không bị trả nhầm Sumatra.
- CLI và local development API bằng Python standard library.

Đây là **MVP kiến trúc chạy được**, không phải tuyên bố đã đạt chuẩn production security. Các giới hạn còn lại được ghi rõ trong [`SECURITY.md`](SECURITY.md) và [`ROADMAP.md`](ROADMAP.md).

## Cài đặt

Yêu cầu Python 3.11 trở lên.

```bash
python -m pip install -e .
```

Hoặc chạy trực tiếp từ source:

```bash
PYTHONPATH=src python -m whyward.cli --help
```

Trên Windows PowerShell:

```powershell
$env:PYTHONPATH = "src"
python -m whyward.cli --help
```

## Chạy demo

Demo tạo một file trong sandbox qua đầy đủ đường proposal → review → capability → execution → read-back, sau đó hỏi catalog mẫu về Valdivia:

```bash
PYTHONPATH=src python -m whyward.cli demo --catalog examples/catalog
```

Hỏi trực tiếp:

```bash
PYTHONPATH=src python -m whyward.cli ask \
  --catalog examples/catalog \
  "Trận động đất Valdivia năm 1960 có độ lớn bao nhiêu?"
```

Câu không được trả nhầm Sumatra:

```bash
PYTHONPATH=src python -m whyward.cli ask \
  --catalog examples/catalog \
  "Động đất năm 2004 tại California có độ lớn bao nhiêu?"
```

Kiểm tra ledger:

```bash
PYTHONPATH=src python -m whyward.cli verify-ledger .whyward-demo/ledger.jsonl
```

Chạy local API cho phát triển:

```bash
PYTHONPATH=src python -m whyward.cli serve --catalog examples/catalog --port 8765
```

API mẫu chỉ nên chạy local; chưa có authentication/TLS production.

## Chạy test

```bash
PYTHONPATH=src python -m unittest discover -s tests -v
```

## Đánh giá độc lập và probe tấn công

Bản đánh giá 2026-10-26 (điểm, phát hiện, ánh xạ chuẩn quốc tế, lộ trình) nằm ở
[`docs/audit/2026-10-26-danh-gia-he-thong.md`](docs/audit/2026-10-26-danh-gia-he-thong.md).
Đi kèm là bộ probe tấn công tái lập được, mỗi probe ứng với một bài test âm tính
cần chuyển từ đỏ sang xanh trước khi dùng thật:

```bash
PYTHONPATH=src python docs/audit/reproduce_findings.py
```

Tại commit hiện tại, bộ probe báo 15/15 hành vi cần bị chặn. Đây là *bản đồ
việc cần làm*, không phải danh sách tính năng đã có.

## Kiến trúc ngắn

```text
External Root of Trust
  OS identity | signing keys | external log anchor | human authority
                         │
                    Control Core
          policy | capability | evidence gate | ledger
                    ▲                  │
          proposal/claim               │ scoped capability
                    │                  ▼
              AI Workers          Execution Sandbox
                    │                  │
                    └──── evidence ────┘
                              │
                    Evidence & Knowledge
              sources | lineage | reviewed catalog
```

Chi tiết: [`ARCHITECTURE.md`](ARCHITECTURE.md).

## Trạng thái dữ liệu mẫu

Catalog trong `examples/catalog` là **demo fixture** để kiểm tra cơ chế matching và provenance. Hai record được đánh dấu `demo_verified`, không phải tuyên bố đã thực hiện một production ingestion mới từ USGS trong repo này. Trước khi dùng thật, phải thay bằng pipeline lấy và kiểm tra field từ nguồn chủ quản như mô tả trong roadmap.

## Vì sao không giữ tên SCP?

Tên SCP gắn với một monolith vừa làm bộ não, vừa làm expert, vừa học, vừa kiểm soát. WhyWard chọn phạm vi hẹp và rõ hơn:

- Không cạnh tranh làm model thông minh nhất.
- Dùng được với AI/agent của nhiều hãng.
- Sở hữu lớp biên, bằng chứng, quyền và dấu vết.
- Cho phép thay worker khi có hệ thống tốt hơn.

Triết lý gốc không bị bỏ đi; nó được rút thành một sản phẩm kỹ thuật có ranh giới.
