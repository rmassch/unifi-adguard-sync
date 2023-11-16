FROM python:3.11.2-alpine3.17

COPY sync.py sync.py
COPY requirements.txt requirements.txt
COPY crontab crontab

RUN pip install -r requirements.txt
RUN crontab crontab

CMD ["crond", "-f"]