Xiaomi-MQTT bridge, written in Python 

based on the following code sample: https://github.com/jon1012/mihome

## Run and build
- Python 3 is supported
- Dockerfile included

## Mi Aqara Protocol 
- See here: https://aqara.gitbooks.io/lumi-gateway-lan-communication-api/content/


Example of usage as a simple mqtt relay:

```python
import paho.mqtt.client as mqtt

MQTT_SERVER = "192.168.0.149"
MQTT_PORT = 1883

PATH_FMT = "xiaomi/{model}/{sid}/{prop}" # short_id or sid ?

def prepare_mqtt():
  client = mqtt.Client()
  client.connect(MQTT_SERVER, MQTT_PORT, 60)

  return client

def push_data(client, model, sid, cmd, data):
  for key, value in data.items():
      path = PATH_FMT.format(model=model,
                             sid=sid,
                             cmd=cmd,
                             prop=key)
      client.publish(path, payload=value, qos=0)

client = prepare_mqtt()
cb = lambda m, s, c, d: push_data(client, m, s, c, d)
connector = XiaomiConnector(data_callback=cb)

while True:
    connector.check_incoming()
```

For more information on the protocol and devices, see my notes: https://notes.jmsinfor.com/blog/post/admin/Xiaomi-Hub
