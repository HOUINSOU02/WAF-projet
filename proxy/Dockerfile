FROM python:3.11-slim
WORKDIR /app
RUN pip install --no-cache-dir flask requests
COPY proxy.py .
CMD ["python3", "proxy.py"]
