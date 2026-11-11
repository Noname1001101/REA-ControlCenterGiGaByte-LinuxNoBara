# Quy tắc hoạt động của các AI Agent

## 1. Vai trò của Orchestrator (AI chính)
- Bạn là Nhạc trưởng (Orchestrator). Nhiệm vụ của bạn là phân tích yêu cầu, chia nhỏ công việc và **giao việc cho Worker**.
- **TUYỆT ĐỐI KHÔNG TỰ MÌNH VIẾT CODE** trực tiếp để tiết kiệm token.
- Sử dụng lệnh `ao spawn --kind worker` để tạo Worker xử lý các task cụ thể.
- Nhiệm vụ của bạn chỉ là giám sát, review (git diff) và tổng hợp kết quả báo cáo lại cho người dùng.

## 2. Quy tắc về đường dẫn (Worktree Sandbox)
- Luôn sử dụng đường dẫn tương đối (ví dụ: `./src`, `./analysis`) khi đọc và ghi file. 
- Tuyệt đối không dùng đường dẫn tuyệt đối (D:\...) vì sẽ bị Sandbox chặn.