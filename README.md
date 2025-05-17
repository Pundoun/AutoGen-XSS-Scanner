# AutoGen-XSS-Scanner - XSS Detection and Exploitation Framework using AutoGen Multi-Agent AI

Đồ án môn học Lập trình Mạng - Phát triển bởi Lê Trường Khoa & Nguyễn Đinh Như Quỳnh.
Giảng viên hướng dẫn: Nguyễn Đăng Quang

## Giới thiệu

Ứng dụng này sử dụng kiến trúc AI đa tác nhân (Multi-Agent) với thư viện AutoGen để tự động hóa quy trình phát hiện lỗ hổng Cross-Site Scripting (XSS) trên các ứng dụng web. Hệ thống có khả năng crawling website, phân tích HTML, xác định các điểm chèn tiềm năng, sinh và thử nghiệm các payload XSS (bao gồm cả payload dựa trên sự kiện và submit form), sau đó báo cáo kết quả và lưu trữ tóm tắt vào cơ sở dữ liệu SQLite.

## Yêu cầu Hệ thống

1.  **Miniconda hoặc Anaconda:** Đã được cài đặt trên máy.
    *   Nếu chưa có, tải Miniconda từ [docs.conda.io/en/latest/miniconda.html](https://docs.conda.io/en/latest/miniconda.html) hoặc Anaconda từ [www.anaconda.com/products/distribution](https://www.anaconda.com/products/distribution).
2.  **Git (Tùy chọn):** Nếu clone dự án từ repository Git.

## Hướng dẫn Cài đặt và Khởi chạy (Sử dụng Conda)

Vui lòng thực hiện các bước sau trong **Anaconda Prompt** (trên Windows):

1.  **Lấy Mã nguồn:**
    *   Nếu clone từ Git:
        ```
        git clone https://github.com/Pundoun/AutoGen-XSS-Scanner.git
        cd <TEN_THU_MUC_DU_AN>
        ```
    *   Nếu nhận dưới dạng thư mục/ZIP: Giải nén và di chuyển vào thư mục gốc của dự án.

2.  **Tạo và Kích hoạt Môi trường Conda:**
    Tạo một môi trường Conda mới cho dự án (ví dụ: tên `xss_autogen_env`) với phiên bản Python mong muốn (ví dụ: 3.9).
    ```
    conda create --name xss_autogen_env python=3.9
    ```
    Kích hoạt môi trường vừa tạo:
    ```
    conda activate xss_autogen_env
    ```
    Bạn sẽ thấy `(xss_autogen_env)` ở đầu dòng lệnh sau khi kích hoạt thành công.

4.  **Cài đặt các Thư viện Python:**
    Trong thư mục gốc của dự án (với môi trường Conda đã kích hoạt), chạy:
    ```
    pip install -r requirements.txt
    ```
    *Lưu ý: Mặc dù Conda có trình quản lý gói riêng, `pip` vẫn có thể được sử dụng bên trong môi trường Conda để cài đặt các gói từ PyPI không có sẵn trên các channel Conda chính hoặc khi file `requirements.txt` được cung cấp.*

5.  **Cài đặt Trình duyệt cho Playwright:**
    Sau khi `pip install` hoàn tất, chạy lệnh sau để tải và cài đặt trình duyệt Chromium mà Playwright sẽ sử dụng:
    ```
    python -m playwright install
    ```
    *(Lưu ý: Lệnh này chỉ cần chạy một lần trong môi trường Conda này sau khi cài đặt Playwright).*

6.  **Cấu hình Biến Môi trường (API Key):**
    *   Trong thư mục gốc của dự án, tạo một file mới tên là `.env`.
    *   Mở file `.env` và cập nhật các giá trị sau:

        ```env
        # Deepseek API key - QUAN TRỌNG
        DEEPSEEK_API_KEY="YOUR_DEEPSEEK_API_KEY_HERE"

        AUTOGEN_MODEL_NAME="deepseek-coder"
        USER_LOGIN_NAME="YOUR_NAME" # Có thể thay đổi tên người dùng hiển thị
        ```
    *   **QUAN TRỌNG:** Thay thế `"YOUR_DEEPSEEK_API_KEY_HERE"` bằng API Key hợp lệ của DeepSeek. Nếu không có API Key, ứng dụng sẽ không thể tương tác với LLM.

7.  **Kiểm tra File Cấu hình Agent:**
    Đảm bảo file `agents_config.json` tồn tại trong thư mục gốc với nội dung tương tự như sau (trường `"api_key": "env"` sẽ lấy key từ file `.env`):
    ```json
    [
      {
        "model": "deepseek-coder",
        "api_key": "env",
        "base_url": "https://api.deepseek.com/v1",
        "price": [0.00014, 0.00028]
      }
    ]
    ```

8.  **Khởi chạy Ứng dụng:**
    Sau khi hoàn tất các bước trên (và đảm bảo môi trường `xss_autogen_env` vẫn đang được kích hoạt), chạy ứng dụng Streamlit từ thư mục gốc của dự án:
    ```
    streamlit run app.py
    ```
    Ứng dụng sẽ tự động mở trong trình duyệt web của bạn, thường tại địa chỉ `http://localhost:8501`.
    *Lưu ý: Lần chạy đầu tiên, cơ sở dữ liệu SQLite (`xss_scan_reports.db`) sẽ được tự động tạo trong thư mục dự án.*

## Sử dụng Ứng dụng

1.  **Nhập URL:** Tại giao diện chính, nhập URL của trang web bạn muốn phân tích vào ô "Nhập URL chính...".
2.  **Điểm chèn đã biết (Tùy chọn):** Nếu bạn biết một điểm chèn cụ thể trên URL gốc (ví dụ: "ô tìm kiếm", "tham số name"), hãy nhập mô tả vào ô tương ứng.
3.  **Cấu hình Crawling (Sidebar):**
    *   **Số URL tối đa để crawl:** Giới hạn số lượng trang web con sẽ được thu thập và phân tích.
    *   **Độ sâu crawling tối đa:** 0 nghĩa là chỉ phân tích URL gốc. 1 nghĩa là URL gốc và các trang liên kết trực tiếp từ nó, v.v.
    *   **Giới hạn tổng số Tool Call:** Để kiểm soát thời gian chạy và chi phí API (nếu có).
4.  **Bắt đầu Phân tích:** Nhấn nút "🚀 Bắt đầu Phân Tích & Crawling".
5.  **Theo dõi Tiến trình:** Theo dõi nhật ký tương tác của các AI Agent trong các expander bên dưới. Quá trình này có thể mất một vài phút hoặc lâu hơn tùy thuộc vào độ phức tạp của website và cấu hình.
6.  **Xem và Tải Báo cáo:** Sau khi hoàn tất, báo cáo tổng hợp sẽ được hiển thị và có thể tải về dưới dạng file `.txt`.
7.  **Dọn dẹp Playwright (Sidebar):** Nếu cần giải phóng tài nguyên hoặc Playwright có vẻ bị "kẹt", nhấn nút "🧹 Dọn dẹp Playwright".
