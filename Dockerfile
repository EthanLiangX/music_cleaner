FROM python:3.9-slim
RUN apt-get update && apt-get install -y ffmpeg
COPY requirements.txt .
RUN pip install --upgrade pip
RUN pip install  -r requirements.txt
WORKDIR /app
COPY music_cleaner.py /app