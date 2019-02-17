Xiaomi-MQTT bridge, written in Python 

based on the following code sample: https://github.com/jon1012/mihome

## Run and build
- Tested with Mi Gateway v2, v1 is NOT supported
- Python 3 is supported
- Dockerfile included

## Mi Aqara Protocol 
- See here: https://aqara.gitbooks.io/lumi-gateway-lan-communication-api/content/

## Using Docker image

### How to pack

```bash
docker build . -t xiaomi-mqtt
```

### How to use

- Create and run shell script run_xiaomi_mqtt.sh

```bash
#!/bin/sh
docker rm xiaomi-mqtt --force
docker run \
        --name xiaomi-mqtt -d \
        --restart always \
        xiaomi-mqtt
```
