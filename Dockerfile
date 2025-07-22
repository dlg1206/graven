# file: Dockerfile
# description: Crate graven container for running in docker
#
# @author: Derek Garcia


# install syft
FROM alpine/curl:8.12.0 AS syft_download
# latest as of writing
ENV SYFT_VERSION=v1.23.1
RUN curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh | sh -s -- -b /usr/local/bin $SYFT_VERSION


# install grype
FROM alpine/curl:8.12.0 AS grype_download
# latest as of writing
ENV GRYPE_VERSION=v0.91.2
RUN curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh | sh -s -- -b /usr/local/bin $GRYPE_VERSION


FROM python:3.12-alpine3.22 AS graven
LABEL maintainer="Derek Garcia <dgarcia2@hawaii.edu>"
LABEL version=2.2.1
LABEL name=graven
# prevent update mid scan
ENV SYFT_CHECK_FOR_APP_UPDATE=false
ENV GRYPE_DB_AUTO_UPDATE=false
ENV GRYPE_CHECK_FOR_APP_UPDATE=false
# ensure only java catalogers are used
ENV SYFT_DEFAULT_CATALOGERS=java-archive-cataloger
# copy anchore tools
COPY --from=syft_download /usr/local/bin/syft /usr/local/bin/syft
COPY --from=grype_download /usr/local/bin/grype /usr/local/bin/grype
# setup graven
WORKDIR /app
RUN mkdir -p .cache/grype
# install graven dependencies
COPY --chown=graven:graven requirements.txt requirements.txt
RUN pip install --no-cache-dir -r requirements.txt
# copy code
COPY --chown=graven:graven graven graven
# create user
RUN adduser -H -D graven
USER graven
# launch graven
ENTRYPOINT ["python3", "graven"]
CMD ["-h"]