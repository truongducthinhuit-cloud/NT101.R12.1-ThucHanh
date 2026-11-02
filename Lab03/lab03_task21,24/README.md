# Lab03 - Nhiệm vụ 2.1 và 2.4

Mục tiêu: minh họa RSA giáo khoa và xác minh chữ ký RSA/SHA-256 trên chứng chỉ X.509 lấy từ webserver thật.

Yêu cầu: Python 3.8 trở lên, OpenSSL và Internet cho bước lấy chứng chỉ. Không cần thư viện Python bổ sung. Hướng dẫn chi tiết bằng tiếng Việt: `HUONG_DAN_CHI_TIET.md`. Nội dung báo cáo tham khảo: `BAO_CAO_MAU.md`.

Chạy với Python/OpenSSL có sẵn trong PATH:

```text
python task21.py keys
python task21.py number
python task21.py text
python task21.py decrypt
python task21.py random --bits 2048
python task24.py fetch --host www.amazon.com
python task24.py inspect
python task24.py verify
```

Máy Windows đang dùng có Python tại `C:\Users\Win\AppData\Local\Python\pythoncore-3.14-64\python.exe`; dùng hướng dẫn chi tiết nếu lệnh `python` không hoạt động. `task24.py` tự tìm OpenSSL native đi kèm Git rồi mới tìm trong PATH.

`Lab03_Colab.ipynb` là notebook độc lập để chạy trên Google Colab. Kết quả trong `ket_qua_tham_khao/` là kết quả trợ lý chạy kiểm tra, cần tự chạy lại để lấy hình minh chứng và số liệu của nhóm. Mã nguồn là tài liệu hỗ trợ học; đọc, hiểu, điều chỉnh và ghi nguồn phù hợp quy định môn học trước khi dùng trong bài nộp.

Task 2.1 dùng little-endian để tương thích bản mã đề. Task 2.4 dùng big-endian theo RSA/X.509 và chỉ hỗ trợ `sha256WithRSAEncryption` (PKCS#1 v1.5). Kiểm tra chữ ký không thay thế xác minh đầy đủ chuỗi tin cậy TLS. RSA không padding ở task 2.1 chỉ dùng cho minh họa.

Website có thể thay chứng chỉ. Nếu không còn trả chứng chỉ theo thuật toán cần thiết, chọn website khác với `--host`, chạy lại fetch, inspect và verify. Không trộn tệp từ các lần tải khác nhau.
