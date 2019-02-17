import paho.mqtt.client as mqtt
import logging
from xiaomi_mqtt.connector import XiaomiConnector

MQTT_SERVER = "192.168.10.177"
MQTT_PORT = 1883
MQTT_USER = 'test'
MQTT_PASSWORD = 'test'

PATH_FMT = "xiaomi/{model}/{sid}/{prop}" # short_id or sid ?

logging.basicConfig(format='%(levelname)s:%(message)s', level=logging.DEBUG)

def prepare_mqtt():

    client = mqtt.Client()
    if MQTT_USER is not None:
        client.username_pw_set(
            MQTT_USER,
            MQTT_PASSWORD,
        )

    client.connect(MQTT_SERVER, MQTT_PORT, 60)

    return client


def push_data(client, model, sid, cmd, data):
  for key, value in data.items():
      path = PATH_FMT.format(model=model,
                             sid=sid,
                             cmd=cmd,
                             prop=key)
      client.publish(path, payload=value, qos=0)


mqtt_client = prepare_mqtt()
mqtt_client.loop_start()

cb = lambda m, s, c, d: push_data(mqtt_client, m, s, c, d)


def on_metadata(connector, sid, payload):
    logging.info("METADATA CHANGED: sid {}: {}".format(sid, payload))


def on_report(connector, sid, data):
    ldata = connector.get_devices()[sid]['_last_data']
    logging.info("REPORT: sid {}: {}".format(sid, ldata))

def on_data(connector, cmd, sid, payload):
    # if cmd == "iam":
    #     connector.send_get_id_list(payload['sid'])

    if cmd == "report":
        on_report(connector, payload['sid'], payload['data'])

connector = XiaomiConnector(data_callback=on_data, metadata_callback=on_metadata)

while True:
    connector.check_incoming()
