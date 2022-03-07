FROM abaez/luarocks

RUN apk --update add zip

WORKDIR /home/app
COPY . .
