# file: Dockerfile
# description: Crate graven container for running in docker
#
# @author: Derek Garcia

# install grype
FROM alpine/curl:8.12.0 AS grype_download
# latest as of writing
ARG GRYPE_VERSION=v0.87.0
RUN curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh | sh -s -- -b /usr/local/bin $GRYPE_VERSION

FROM python:3.12.9-alpine3.21 AS graven
LABEL maintainer="Derek Garcia <dgarcia2@hawaii.edu"
LABEL version=1.0.0
LABEL name=graven
# create user
RUN adduser -D graven
WORKDIR /home/graven
RUN mkdir -p .cache/grype/db && chown -R graven:graven /home/graven
# install graven
COPY graven graven/
COPY requirements.txt requirements.txt
COPY --from=grype_download /usr/local/bin/grype /usr/local/bin/grype
USER graven
RUN pip install -r requirements.txt

# lauch graven
ENTRYPOINT ["python3", "graven"]
CMD ["-h"]