# DNS riêng — bản sao quy tắc DNS quan sát được

Bộ này được tạo từ hồ sơ công khai ở `https://lab.jayteam.click/dns` và các truy vấn DNS ngày 25/11/2026. Đây là mã DNS viết mới, **không phải source bị lấy từ máy chủ của họ**.

Đã kiểm tra A record của đủ **68 tên miền**: **28 chuyển hướng**, **23 chặn**, **17 phân giải bình thường**. Danh sách chi tiết nằm trong `config.json` và `reference/snapshot.json`. Các câu trả lời thông thường được lấy mới từ DNS công cộng, không đóng băng IP CDN. Chỉ áp dụng quy tắc cho tên miền đã đo, không tự suy diễn wildcard.

**Giới hạn quan trọng:** mặc định 28 tên miền chuyển hướng vẫn trỏ tới **103.252.93.74, máy chủ bên gốc**. Bạn sở hữu mã DNS này, nhưng chưa sở hữu backend Locket/Spotify/YouTube của họ. Mã xử lý API/VIP và khóa riêng CA của họ không có trong bộ này. Không đảm bảo mở Gold/Premium hay tương thích mọi phiên bản ứng dụng.

## Chạy trên Railway

Railway cấp tên miền `*.up.railway.app` và xử lý HTTPS cho dịch vụ. Không cần chạy Caddy hoặc Docker Compose trên Railway. Repository triển khai đặt các file `Dockerfile`, `dns_server.py`, `config.json`, `railway.json` ngay ở thư mục gốc.

1. Trong Railway chọn **New Project → Deploy from GitHub repo**, chọn repository chứa bộ mã này. Để **Root Directory** mặc định `/` nếu các file DNS nằm ngay ở gốc repo.
2. Trong **Variables**, đặt `DOH_TOKEN` bằng đúng nội dung file `.doh-token` đang dùng trên máy Windows. Xem giá trị bằng `Get-Content -LiteralPath .\.doh-token` tại thư mục DNS. Không đưa file này lên GitHub. Có thể đặt `PORT=8053`; nếu không, dịch vụ nhận cổng Railway cấp qua biến `PORT`.
3. Deploy hoặc redeploy sau khi lưu Variables. `railway.json` đã cấu hình build Dockerfile và healthcheck `/health`.
4. Vào **Settings → Networking → Public Networking → Generate Domain**. Nếu đã đặt `PORT=8053`, chọn target port **8053**. Nếu để Railway cấp `PORT`, dùng cổng dịch vụ đang nghe trong log.
5. Kiểm tra `https://TEN-APP.up.railway.app/health`; kết quả phải là `{"status":"ok"}`.
6. Tại thư mục DNS trên Windows, tạo hồ sơ bằng tên miền thật vừa được cấp:

```powershell
python configure.py --domain TEN-APP.up.railway.app
```

Giữ `.doh-token` trên máy Windows trùng với biến `DOH_TOKEN` trên Railway. URL riêng sẽ là `https://TEN-APP.up.railway.app/dns-query/TOKEN_CUA_BAN`. Muốn dùng CA/backend bên gốc, xem tùy chọn `--with-original-ca` bên dưới. Railway chỉ chạy dịch vụ DoH của bạn, không chứa mã backend VIP bên gốc.

Tài liệu Railway: <https://docs.railway.com/networking/domains/working-with-domains> và <https://docs.railway.com/builds/dockerfiles>.

## Tải hồ sơ trực tiếp bằng Safari trên iPhone

Dịch vụ hỗ trợ link riêng dạng `https://TEN-MIEN/dns/MA-RIENG.mobileconfig`. Khi mở bằng Safari, máy chủ trả MIME `application/x-apple-aspen-config` và tên file `.mobileconfig`, để iOS nhận đây là hồ sơ cấu hình và hiển thị yêu cầu cho phép tải.

Đường dẫn tải được suy ra từ token DNS; không tải `.mobileconfig` chứa token lên GitHub công khai. Hồ sơ được tạo trong bộ nhớ từ `profile-template.plist`, gắn token lúc chạy, giữ tên **DNS by tnguyeendepzaii**, dòng **TikTok: tnguyen2601_**, CA bên gốc và UUID của hồ sơ hiện có. File template trong repo không chứa token DNS thật.

Máy chủ lấy tên miền từ `PROFILE_HOST`, rồi `RAILWAY_PUBLIC_DOMAIN`, hoặc `profile_host` trong `config.json`. Không lấy tên miền từ header Host do người truy cập gửi. Docker Compose đặt `PROFILE_HOST` theo `DNS_HOST` để chạy với VPS riêng.

Sau khi tải, người dùng mở **Cài đặt → Hồ sơ đã tải về → Cài đặt**. Việc cho phép tải không tự cài hồ sơ hoặc bật tin cậy CA. Hồ sơ chưa ký vẫn hiển thị trạng thái chưa xác minh như bản file tải thủ công.

## Chạy thử ngay trên Windows

Yêu cầu Python 3.11 trở lên. Không cần cài thư viện Python, Docker hoặc chứng chỉ vào hệ điều hành để thử tại máy.

Mở PowerShell tại thư mục này:

```powershell
python -m unittest -v test_dns
python dns_server.py serve
```

Mở PowerShell thứ hai, cũng tại thư mục này:

```powershell
$taskDnsToken = (Get-Content -LiteralPath .\.doh-token -Raw).Trim()
python dns_server.py query --url "http://127.0.0.1:8053/dns-query/$taskDnsToken" --name api.revenuecat.com
python dns_server.py query --url "http://127.0.0.1:8053/dns-query/$taskDnsToken" --name googleads.g.doubleclick.net
python dns_server.py query --url "http://127.0.0.1:8053/dns-query/$taskDnsToken" --name example.com
```

Kết quả hai truy vấn đầu lần lượt là `103.252.93.74` và `0.0.0.0`. Truy vấn `example.com` lấy kết quả trực tiếp từ Cloudflare hoặc Google. Nhấn Ctrl+C ở cửa sổ máy chủ để dừng. URL HTTP này chỉ để thử tại máy, chưa dùng làm DoH trên iPhone.

## Đưa lên VPS và tạo hồ sơ iPhone

Bạn cần VPS với IPv4 công khai, tên miền riêng và Docker Compose. Hướng dẫn cài Docker: <https://docs.docker.com/engine/install/ubuntu/>.

1. Trỏ bản ghi A của tên miền, ví dụ `dns.tenmiencuaban.com`, tới IPv4 VPS. Không dùng tên miền ví dụ khi chạy thực tế.
2. Sao chép thư mục này lên VPS và mở terminal trong thư mục.
3. Tạo cấu hình với tên miền thật:

```bash
python3 configure.py --domain dns.tenmiencuaban.com
docker compose up -d --build
docker compose ps
```

Caddy tự xin và gia hạn chứng chỉ HTTPS. Cổng TCP 80 và 443 phải truy cập được từ Internet; UDP 443 là tùy chọn cho HTTP/3. Dịch vụ Python nằm trong mạng Docker, không công khai cổng 8053. Không cần mở cổng DNS UDP 53 cho bản DoH này.

Lệnh cấu hình tạo `.env`, `.doh-token` và `personal-dns.mobileconfig`. URL riêng có dạng:

```text
https://dns.tenmiencuaban.com/dns-query/<token-trong-file-.doh-token>
```

Hồ sơ iPhone giữ nguyên 68 mục `SupplementalMatchDomains`, đổi DoH sang máy chủ của bạn, dùng UUID mới và mặc định chỉ chứa DNS. Không dùng IP `1.1.1.1`/`8.8.8.8` làm địa chỉ thay thế cho máy chủ HTTPS mang tên miền của bạn.

Hồ sơ mặc định **không chứa root CA của bên gốc**, nên kết nối HTTPS bị chuyển hướng tới backend của họ có thể bị ứng dụng từ chối. Nếu chủ đích là dùng lại chính backend và CA công khai của bên gốc, tạo hồ sơ bằng tùy chọn rõ ràng sau:

```bash
python3 configure.py --domain dns.tenmiencuaban.com --with-original-ca
```

Tùy chọn này thêm **CA của bên gốc**, không tạo CA riêng và không cấp quyền sở hữu máy chủ đó. Việc cài hồ sơ hay bật tin cậy TLS trên iPhone do bạn thực hiện; bộ mã không tự cài hoặc bật tin cậy trên thiết bị. CA được tin cậy cho phép backend bên gốc kết thúc HTTPS đối với các ứng dụng chấp nhận chứng chỉ của CA đó. Không phát tán hồ sơ có token cho người ngoài.

Nếu đã có một backend HTTPS/API riêng hoạt động tương thích, có thể đổi đích:

```bash
python3 configure.py --domain dns.tenmiencuaban.com --redirect-ip IP_BACKEND_CUA_BAN
docker compose up -d --force-recreate
```

**Chỉ thay IP sang VPS DNS trống sẽ làm ứng dụng lỗi kết nối.** VPS đó phải có backend API/TLS tương ứng; bộ mã này không chứa backend đó. Nếu backend dùng CA riêng, cần cấu hình chứng chỉ riêng cho thiết bị, không dùng `--with-original-ca`.

## Kiểm chứng và dữ liệu tham chiếu

- `reference/original.mobileconfig`: hồ sơ gốc tải công khai, lưu để đối chiếu; không phải hồ sơ DNS của bạn.
- `reference/original-profile.xml`: nội dung XML trích xuất từ hồ sơ gốc; chứa chứng chỉ công khai, không có khóa riêng.
- `reference/snapshot.json`: thời điểm đo, checksum, danh sách và kết quả A của đủ 68 tên miền.
- `test_dns.py`: kiểm tra toàn bộ 51 quy tắc chặn/chuyển hướng; GET/POST DoH, token, gói lỗi, upstream lỗi, cấu hình hồ sơ và CA tùy chọn.

AAAA và HTTPS/SVCB của các mục chuyển hướng/chặn trả câu trả lời rỗng, tránh dùng IP khác qua IPv6 hoặc gợi ý HTTPS. Đã đối chiếu AAAA/HTTPS ở máy chủ gốc cho mẫu RevenueCat, YouTube và quảng cáo; chưa xác minh mọi loại bản ghi của mọi tên miền. Không thể cam kết toàn bộ hành vi giống backend gốc.

Máy chủ mặc định chỉ nghe `127.0.0.1`, giới hạn 24 kết nối xử lý đồng thời, yêu cầu token trong URL và không ghi đường dẫn chứa token vào access log. Tạo lại hồ sơ sau khi đổi tên miền hoặc token. Không có UDP DNS, giao diện quản trị, tự cập nhật quy tắc hoặc can thiệp HTTPS trong phiên bản này.

Tài liệu giao thức: <https://www.rfc-editor.org/rfc/rfc8484>. Định dạng hồ sơ Apple: <https://github.com/apple/device-management/blob/release/mdm/profiles/com.apple.dnsSettings.managed.yaml>.
