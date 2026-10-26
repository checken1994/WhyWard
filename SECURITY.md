# Security Policy & Threat Model — WhyWard 0.1.0

## Trạng thái

WhyWard 0.1.0 là MVP kiến trúc để chứng minh ranh giới kiểm soát. Nó chưa phải một sản phẩm bảo mật production hoàn chỉnh và không nên được quảng bá như vậy.

## Tài sản cần bảo vệ

- Policy và khóa ký.
- Capability signing secret.
- Ledger và checkpoint.
- Catalog đã xác thực.
- Credential của tool/API.
- Workspace và hệ thống đích mà action có thể chạm tới.
- Danh tính và quyết định của người phê duyệt.

## Tác nhân đe dọa trong phạm vi thiết kế

1. AI worker hallucinate hoặc tự tin sai.
2. AI worker bị prompt injection và cố xin hành động vượt phạm vi.
3. Nguồn dữ liệu sai, stale hoặc bị đầu độc.
4. Tool báo success nhưng trạng thái thật không đổi.
5. Worker cố sửa protected path hoặc dùng token sai scope.
6. Người vận hành phê duyệt hình thức mà không hiểu hậu quả.

## Ngoài khả năng tự bảo vệ của WhyWard

- Host/root/cloud account bị chiếm hoàn toàn.
- Khóa ký và danh tính phê duyệt cùng bị chiếm.
- Phần cứng/hệ điều hành bị can thiệp ở tầng dưới.
- Nguồn chủ quản duy nhất bị sai mà không có lineage độc lập để đối chiếu.
- Người có thẩm quyền cố ý phê duyệt hành vi phá hoại bằng danh tính hợp lệ.

Các trường hợp này cần IAM, MFA, phân tách quản trị, HSM/secret manager, backup bất biến, giám sát độc lập và quy trình tổ chức.

## Kiểm soát đã có trong MVP

- Tool/resource allowlist và protected path.
- Capability có chữ ký, expiry, fingerprint và one-use theo action.
- Workspace path containment.
- Không dùng shell cho `run_python`; truyền argv trực tiếp.
- Môi trường subprocess tối thiểu, không kế thừa toàn bộ biến môi trường.
- Read-back hash sau khi ghi.
- Ledger hash-chain phát hiện sửa event.
- Kill switch bằng env/file.
- Catalog checksum và snapshot bất biến.
- Không cho năm đơn lẻ làm điều kiện đủ để xác định thực thể trong matcher mẫu.
- Human decision phải ghi comprehension đối với action/consequence/rollback.

## Giới hạn quan trọng

- `run_python` chưa phải sandbox cấp hệ điều hành. Mã Python độc hại vẫn có thể dùng quyền của tiến trình host nếu được cấp action này.
- Capability used-token registry đang ở bộ nhớ tiến trình.
- Local API chưa có authentication/TLS và chỉ nên bind local trong phát triển.
- Ledger hash-chain phát hiện sửa đổi nhưng không ngăn attacker có quyền file thay toàn bộ ledger; checkpoint phải neo ra ngoài.
- Policy JSON hỗ trợ kiểm tra HMAC khi người triển khai cung cấp khóa, nhưng deployment mẫu chưa bắt buộc chữ ký.
- Catalog mẫu là demo, chưa phải production ingestion đã kiểm tra trực tiếp với nguồn.

## Báo cáo lỗ hổng

Khi repo được công bố, hãy thay mục này bằng kênh báo cáo riêng của chủ dự án. Không đăng exploit hoặc bí mật trong issue công khai.
