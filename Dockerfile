FROM debian:buster

RUN apt-get update && apt-get upgrade -y

RUN apt-get -y install make jq


