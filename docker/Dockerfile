FROM python:3.9.10-slim-buster

ENV PYTHONUNBUFFERED=1

WORKDIR /app


RUN apt-get update

RUN apt-get install -y libmariadb-dev-compat libmariadb-dev
RUN apt install -y gcc
RUN apt-get install libssl-dev
RUN python3 -m pip install --upgrade pip
COPY requirements.txt requirements.txt

RUN pip3 install -r requirements.txt

COPY . .


