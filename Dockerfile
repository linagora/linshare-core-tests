FROM docker-registry.linagora.com:5000/linshare-snapshots/python:3.9-slim-buster
WORKDIR /tmp
COPY requirements.txt README.md patch_gitlab.py tests_linshare.py linshare.admin.test.ini  linshare.user.test.ini  file10M LinShare.jpg /tmp/
ENV CONFIG_FILE_ADMIN=linshare.admin.test.ini
ENV CONFIG_FILE_USER=linshare.user.test.ini
RUN pip install -r requirements.txt
CMD /tmp/tests_linshare.py
