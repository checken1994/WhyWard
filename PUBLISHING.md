# Tách WhyWard thành GitHub repository độc lập

Thư mục `whyward-standalone` được tổ chức như root của một repo mới. Không copy theo `.git`, `.venv`, `.whyward-demo`, `.whyward-runtime` hoặc cache Python.

## Cách thủ công bằng GitHub CLI

Từ thư mục cha của `whyward-standalone`:

```bash
cp -R whyward-standalone whyward
cd whyward
find . -type d -name __pycache__ -prune -exec rm -rf {} +
git init -b main
git add .
git commit -m "Initial WhyWard boundary control plane"
gh repo create whyward --private --source=. --remote=origin --push \
  --description "WhyWard — an evidence-gated boundary control plane for AI workers"
```

Trên Windows PowerShell:

```powershell
Copy-Item -Recurse whyward-standalone whyward
Set-Location whyward
Get-ChildItem -Recurse -Directory -Filter __pycache__ | Remove-Item -Recurse -Force
git init -b main
git add .
git commit -m "Initial WhyWard boundary control plane"
gh repo create whyward --private --source=. --remote=origin --push --description "WhyWard — an evidence-gated boundary control plane for AI workers"
```

Đổi `--private` thành `--public` chỉ sau khi đã rà soát license, dữ liệu mẫu, bảo mật và không còn thông tin nội bộ.

## Kiểm tra trước khi push

```bash
PYTHONPATH=src python -m unittest discover -s tests -v
PYTHONPATH=src python -m whyward.cli demo --catalog examples/catalog
```

Trên Windows PowerShell:

```powershell
$env:PYTHONPATH = "src"
python -m unittest discover -s tests -v
python -m whyward.cli demo --catalog examples/catalog
```

Không commit `.whyward-demo`, `.whyward-runtime`, `.env`, khóa, ledger vận hành thật hoặc dữ liệu người dùng.
