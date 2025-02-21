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
LABEL version=1.1.0
LABEL name=graven
ENV PATH=$PATH:/home/graven/.local/bin

# prevent update mid scan
ENV GRYPE_DB_AUTO_UPDATE=false
ENV GRYPE_CHECK_FOR_APP_UPDATE=false

# create user
RUN adduser -D graven
WORKDIR /home/graven
RUN mkdir -p .cache/grype/db && chown -R graven:graven /home/graven
COPY --from=grype_download /usr/local/bin/grype /usr/local/bin/grype

# install graven
COPY --chown=graven:graven common/common/ common/common/
COPY --chown=graven:graven common/pyproject.toml common/
COPY --chown=graven:graven graven/graven/ graven/graven/
COPY --chown=graven:graven graven/requirements.txt graven/

USER graven
RUN pip install --user --no-cache-dir ./common
RUN pip install --user --no-cache-dir -r graven/requirements.txt

# lauch graven
ENTRYPOINT ["python3", "graven/graven"]
CMD ["-h"]