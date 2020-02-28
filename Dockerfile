FROM alpine:3.7 as seed-build

RUN apk update
RUN apk --no-cache add autoconf
RUN apk --no-cache add automake
RUN apk --no-cache add boost-dev
RUN apk --no-cache add build-base
RUN apk --no-cache add openssl
RUN apk --no-cache add openssl-dev
ADD . /src

WORKDIR /src

# Needed to avoid an error compiling on alpine
RUN sed -i -e 's/^inline//g' strlcpy.h
RUN make

FROM alpine:3.7

COPY --from=seed-build /src/tapyrusseed /usr/local/bin/tapyrusseed

RUN apk --no-cache add \
    libcrypto1.0 \
    libstdc++

ENV APP_DIRECTORY=/data

WORKDIR ${APP_DIRECTORY}

VOLUME ${APP_DIRECTORY}

EXPOSE 53

ENTRYPOINT ["tapyrusseed", "-i", "1939510133", "-s", "1939510133:seed.tapyrus.dev.chaintope.com", "-m", "nakajo@chaintope.com"]
