FROM python:3.12-slim

ENV PYTHONUNBUFFERED=1
WORKDIR /app

RUN pip install --no-cache-dir paramiko==3.5.1

COPY tools/attacker_common.py /app/attacker_common.py
COPY tools/ai_attacker.py /app/ai_attacker.py
COPY tools/human_attacker.py /app/human_attacker.py
COPY tools/countermeasure_attacker.py /app/countermeasure_attacker.py
COPY tools/realistic_ai_attacker.py /app/realistic_ai_attacker.py
COPY tools/profiles/ /app/profiles/

ENTRYPOINT ["python3", "/app/ai_attacker.py"]
