FROM golang:1.14.4-alpine3.12 as build
WORKDIR /build
COPY ./ ./
RUN go build -o auth

FROM alpine:3.12
WORKDIR /app
COPY --from=build /build/auth .
EXPOSE 80
CMD "/app/auth"
