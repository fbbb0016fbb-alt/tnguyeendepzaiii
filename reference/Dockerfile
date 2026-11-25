FROM python:3.12-slim
WORKDIR /app
COPY dns_server.py /app/dns_server.py
COPY config.json /app/config.json
COPY profile-template.plist /app/profile-template.plist
USER 65534:65534
EXPOSE 8053
CMD ["python", "-u", "dns_server.py", "serve", "--listen", "0.0.0.0"]
