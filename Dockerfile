FROM python:3.11-slim

ENV PYTHONUNBUFFERED=1
WORKDIR /app

COPY my-ai-soc-agent/requirements.txt /tmp/requirements.txt
RUN pip install --no-cache-dir -r /tmp/requirements.txt

COPY . /app

CMD ["python", "consumer.py"]
