FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
	PYTHONUNBUFFERED=1 \
	VIRTUAL_ENV=/opt/venv \
	PATH="/opt/venv/bin:$PATH" \
	PIP_NO_CACHE_DIR=1

WORKDIR /app

RUN apt-get update \
	&& apt-get install -y --no-install-recommends nmap \
	&& rm -rf /var/lib/apt/lists/* \
	&& python -m venv "$VIRTUAL_ENV" \
	&& "$VIRTUAL_ENV/bin/pip" install --upgrade pip

COPY my-ai-soc-agent/requirements.txt /tmp/requirements.txt
RUN pip install -r /tmp/requirements.txt

COPY . /app

RUN mkdir -p /app/logs /app/my-ai-soc-agent/incidents

EXPOSE 8501

CMD ["python", "-m", "streamlit", "run", "app.py", "--server.address=0.0.0.0", "--server.port=8501"]
