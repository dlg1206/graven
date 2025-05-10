# file: Dockerfile
# description: Crate graven container for running in docker
#
# @author: Derek Garcia

# install syft
FROM alpine/curl:8.12.0 AS syft_download
# latest as of writing
ENV SYFT_VERSION=v1.22.0
RUN curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh | sh -s -- -b /usr/local/bin $SYFT_VERSION

# install grype
FROM alpine/curl:8.12.0 AS grype_download
# latest as of writing
ENV GRYPE_VERSION=v0.91.0
RUN curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh | sh -s -- -b /usr/local/bin $GRYPE_VERSION

FROM python:3.12.9-alpine3.21 AS graven
LABEL maintainer="Derek Garcia <dgarcia2@hawaii.edu>"
LABEL version=2.2.0
LABEL name=graven
ENV HOME="/home/graven"
ENV PATH=$PATH:/home/graven/.local/bin

# prevent update mid scan
ENV SYFT_CHECK_FOR_APP_UPDATE=false
ENV GRYPE_DB_AUTO_UPDATE=false
ENV GRYPE_CHECK_FOR_APP_UPDATE=false

# ensure only java catalogers are used
ENV SYFT_DEFAULT_CATALOGERS=java-archive-cataloger

# create user
RUN adduser -D graven
WORKDIR $HOME
RUN mkdir -p .cache/grype && chown -R graven:graven /home/graven
COPY --from=syft_download /usr/local/bin/syft /usr/local/bin/syft
COPY --from=grype_download /usr/local/bin/grype /usr/local/bin/grype

# install graven
COPY --chown=graven:graven requirements.txt requirements.txt
COPY --chown=graven:graven graven/ graven/

USER graven
RUN pip install --user --no-cache-dir -r requirements.txt

# lauch graven
ENTRYPOINT ["python3", "graven"]
CMD ["-h"]