FROM python:3.6.8-slim-stretch

ADD . /app
WORKDIR /app
RUN cd /app && python setup.py install
