# Docker build for IoT testbed describe
# january 28 2020

FROM python:3

RUN mkdir -p /python-service
WORKDIR /python-service


COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

COPY app.py /python-service
RUN chmod ugo+x app.py

# Create and define the container's working directory.
ENV FLASK_APP=app.py
EXPOSE 3000
CMD [ "/usr/local/bin/flask", "run", "--host=0.0.0.0", "--port=3000" ]

