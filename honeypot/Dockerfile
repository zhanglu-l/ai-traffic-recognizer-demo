FROM python:3.12-slim

ENV PYTHONUNBUFFERED=1
WORKDIR /app

RUN pip install --no-cache-dir paramiko==3.5.1

COPY honeypot/honeypot_server.py /app/honeypot_server.py
COPY honeypot/countermeasure_policy.py /app/countermeasure_policy.py
COPY honeypot/countermeasure_mimic.py /app/countermeasure_mimic.py
COPY honeypot/countermeasure_engine.py /app/countermeasure_engine.py
COPY honeypot/decoys.json /app/decoys.json
COPY honeypot/data/ /app/data/

EXPOSE 22
CMD ["python3", "/app/honeypot_server.py"]
