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

FROM python:3.12.9-alpine3.21 AS graven
LABEL maintainer="Derek Garcia <dgarcia2@hawaii.edu>"
LABEL version=2.2.1
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

# install graven dependencies
USER graven
COPY --chown=graven:graven graven/requirements.txt requirements.txt
RUN pip install --user --no-cache-dir -r requirements.txt
# remove pip
USER root
RUN rm requirements.txt && pip uninstall pip -y
USER graven
# copy code
COPY --chown=graven:graven graven/graven/ graven/

# copy anchore tools
COPY --from=syft_download /usr/local/bin/syft /usr/local/bin/syft
COPY --from=grype_download /usr/local/bin/grype /usr/local/bin/grype

# lauch graven
ENTRYPOINT ["python3", "graven"]
CMD ["-h"]