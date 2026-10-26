# BÀN GIAO TÁCH WHYWARD THÀNH GITHUB REPOSITORY MỚI

## Nguồn cần tách

Trong repo SCP hiện tại, toàn bộ hệ thống mới nằm tại:

```text
whyward-standalone/
```

Thư mục này đã được tổ chức như root của một repository độc lập, gồm:

- `pyproject.toml`
- `README.md`
- `ARCHITECTURE.md`
- `SECURITY.md`
- `ROADMAP.md`
- `PUBLISHING.md`
- `src/whyward/`
- `tests/`
- `examples/`
- `scripts/publish-github.ps1`
- `scripts/publish-github.sh`
- `.github/workflows/test.yml`

## Nguyên tắc khi tách

1. **Copy trước, không move ngay.** Chỉ được đề xuất xóa bản trong repo SCP sau khi repo WhyWard mới đã push và kiểm chứng thành công.
2. Không copy `.git`, `.env` hoặc bất kỳ file nào ngoài `whyward-standalone/` của repo SCP.
3. Không copy các thư mục runtime/cache sau nếu xuất hiện:
   - `.whyward-demo/`
   - `.whyward-runtime/`
   - `__pycache__/`
   - `*.pyc`
   - `build/`
   - `dist/`
   - `*.egg-info/`
4. Repo GitHub mới mặc định là **private**. Chỉ dùng public khi chủ dự án xác nhận riêng.
5. Tên repo mặc định: `whyward`.
6. Không tự thay đổi kiến trúc hoặc thêm tính năng trong lúc tách. Việc tách repo là một thay đổi đóng gói, không phải dịp refactor.

## Quy trình bắt buộc cho AI trên PC

### Bước 1 — Ghi baseline

- Ghi đường dẫn repo SCP hiện tại.
- Ghi branch/commit bắt đầu.
- Ghi `git status --short` và giữ nguyên thay đổi không liên quan.
- Xác nhận thư mục nguồn `whyward-standalone/` tồn tại.

### Bước 2 — Copy sang thư mục đích độc lập

Đặt thư mục đích **ngoài** repo SCP, ví dụ cùng cấp với repo SCP và tên là `whyward`.

Sau khi copy, kiểm tra thư mục đích có các file gốc:

```text
pyproject.toml
README.md
src/whyward/__init__.py
src/whyward/cli.py
tests/test_whyward.py
examples/catalog/manifest.json
```

### Bước 3 — Kiểm thử trước khi khởi tạo repo

Trên Windows PowerShell:

```powershell
$env:PYTHONPATH = "src"
python -m unittest discover -s tests -v
python -m whyward.cli demo --catalog examples/catalog
python -m whyward.cli ask --catalog examples/catalog "Động đất năm 2004 tại California có độ lớn bao nhiêu?"
```

Kết quả kỳ vọng tại thời điểm bàn giao:

- Unit test: **18 test đạt**.
- Demo ghi file: `PASS_WITHIN_SCOPE`.
- Câu California 2004: `INSUFFICIENT_EVIDENCE`, không trả nhầm Sumatra.

Nếu thực tế khác, dừng lại và báo cáo. Không tự sửa trong cùng nhiệm vụ tách repo trừ khi chủ dự án duyệt riêng.

### Bước 4 — Dọn runtime khỏi bản copy

Xóa khỏi thư mục đích nếu tồn tại:

```text
.whyward-demo/
.whyward-runtime/
__pycache__/
*.pyc
build/
dist/
*.egg-info/
```

Chạy quét bí mật ở mức tối thiểu: bảo đảm không có `.env`, khóa riêng, token hoặc ledger vận hành thật trong danh sách file sẽ commit.

### Bước 5 — Khởi tạo Git repo mới

Từ root thư mục WhyWard đã tách:

```powershell
git init -b main
git add .
git status --short
git commit -m "Initial WhyWard boundary control plane"
```

Phải kiểm tra danh sách file staged chỉ thuộc WhyWard. Nếu xuất hiện file của SCP cũ, dừng lại.

### Bước 6 — Tạo GitHub repo và push

Ưu tiên dùng script đã có:

```powershell
.\scripts\publish-github.ps1 -RepoName "whyward" -Visibility private
```

Hoặc thủ công:

```powershell
gh repo create whyward --private --source=. --remote=origin --push --description "WhyWard — an evidence-gated boundary control plane for AI workers"
```

Nếu repo `whyward` đã tồn tại, dừng và báo cáo; không tự chọn tên khác hoặc force-push.

### Bước 7 — Kiểm chứng sau push

AI thực thi phải báo cáo:

- URL GitHub repo mới.
- Commit hash đã push.
- `git remote -v`.
- Kết quả test đã chạy từ thư mục đã tách.
- Demo đạt hay không.
- Danh sách file ngoài dự kiến nếu có.
- Phần chưa kiểm chứng, ví dụ GitHub Actions chưa chạy hoặc bị billing chặn.

Chỉ sau bước này mới hỏi chủ dự án có muốn xóa `whyward-standalone/` khỏi repo SCP cũ hay giữ như bản lưu chuyển tiếp.

## Lệnh copy/paste cho AI trên PC

```text
Hãy tách WhyWard thành GitHub repository mới theo file WHYWARD_EXTRACTION_HANDOFF.md ở root repo SCP hiện tại.

Nguồn duy nhất được tách là thư mục whyward-standalone/. Chỉ copy thư mục này ra ngoài repo SCP thành thư mục whyward. Không copy .git, .env, file SCP khác, cache hoặc runtime. Không sửa kiến trúc/tính năng trong nhiệm vụ này.

Trước khi git init, chạy unit test và demo từ bản đã copy. Kỳ vọng tại baseline là 18 test đạt, demo PASS_WITHIN_SCOPE và câu California 2004 trả INSUFFICIENT_EVIDENCE. Nếu khác, dừng và báo cáo.

Sau khi dọn runtime/cache và kiểm tra không có bí mật, khởi tạo git branch main, commit "Initial WhyWard boundary control plane", rồi tạo GitHub repo private tên whyward và push. Nếu repo đã tồn tại hoặc gh chưa đăng nhập, dừng và báo cáo, không force-push và không tự đổi tên.

Cuối cùng báo cáo URL repo, commit hash, remote, test/demo đã chạy và phần chưa kiểm chứng. Không xóa whyward-standalone khỏi repo SCP cũ khi tôi chưa duyệt.
```
