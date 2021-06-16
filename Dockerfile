FROM python:3.9-slim-buster
WORKDIR /tmp
COPY requirements.txt tests_linshare.py linshare.admin.test.ini  linshare.user.test.ini  file10M LinShare.jpg /tmp/
ENV CONFIG_FILE_ADMIN=linshare.admin.test.ini
ENV CONFIG_FILE_USER=linshare.user.test.ini
RUN pip install -r requirements.txt
CMD /tmp/tests_linshare.py
