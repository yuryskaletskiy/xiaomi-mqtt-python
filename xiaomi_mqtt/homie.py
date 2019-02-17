import logging

class HomieMqttExporter:
    """
    Metadata exporter in Homie 3.0 convention format
    https://homieiot.github.io/
    """

    supported_models = ['magnet', 'sensor_ht']

    def __init__(self, mqtt_client):
        self.client = mqtt_client

    def export_devices(self, devices):
        supported = [d for d in devices if d['model'] in self.supported_models]

        for dev in supported:
            self.export_device(dev)
            self.export_device_data(dev)

    def export_device(self, dev):
        logging.debug("Homie export device: {}".format(dev))

        model = dev['model']
        sid = dev['sid']

        if model == 'magnet':
            self._pub_device(sid, 'Xiaomi Magnet Device', 'ready')
            self._pub_device_single_node(sid, 'magnet', 'Magnet Status')
            self._pub_device_node_properties(sid, 'magnet', ['status'])
            self._pub_device_node_property_meta(sid, 'magnet', 'status', "boolean", "Open Status")

        if model == 'sensor_ht':
            self._pub_device(sid, 'Xiaomi Temperature and Humidity Sensor', 'ready')
            self._pub_device_single_node(sid, 'sensor_ht', 'Temperature and Humidity')
            self._pub_device_node_properties(sid, 'sensor_ht', ['temperature', 'humidity'])
            self._pub_device_node_property_meta(sid, 'sensor_ht', 'temperature', "float", "Temperature", '°C')
            self._pub_device_node_property_meta(sid, 'sensor_ht', 'humidity', "float", "Humidity", '%')


    def export_device_data(self, dev):
        logging.debug("Homie export device data: {}".format(dev))

        model = dev['model']
        sid = dev['sid']

        if '_last_data' not in dev:
            logging.debug("No last data in sid {} - nohing to export".format(sid))
            return

        ldata=dev['_last_data']

        if model == 'magnet':
            status_value = "OFF" if ldata["status"] != "open" else "ON"
            self._pub_device_node_property_value(sid, 'magnet', 'status', status_value)

        if model == 'sensor_ht':
            if "temperature" in ldata:
                value = round(int(ldata["temperature"]) / 100)
                self._pub_device_node_property_value(sid, 'sensor_ht', 'temperature', value)

            if "humidity" in ldata:
                value = round(int(ldata["humidity"]) / 100)
                self._pub_device_node_property_value(sid, 'sensor_ht', 'humidity', value)



    def _pub_device(self, dev_id, dev_name, dev_status):
        self.client.publish("homie/{}/$homie".format(dev_id), "3.0")
        self.client.publish("homie/{}/$name".format(dev_id), dev_name)
        self.client.publish("homie/{}/$state".format(dev_id), dev_status)

    def _pub_device_single_node(self, dev_id, node_id, node_name):
        self.client.publish("homie/{}/$nodes".format(dev_id), node_id)
        self.client.publish("homie/{}/{}/$name".format(dev_id, node_id), node_name)

    def _pub_device_node_properties(self, dev_id, node_id, prop_ids):
        self.client.publish("homie/{}/{}/$properties".format(dev_id, node_id), ",".join(prop_ids))

    def _pub_device_node_property_meta(self, dev_id, node_id, prop_id, prop_type, prop_name, prop_unit = None):
        self.client.publish("homie/{}/{}/{}/$name".format(dev_id, node_id, prop_id), prop_name)
        self.client.publish("homie/{}/{}/{}/$datatype".format(dev_id, node_id, prop_id), prop_type)

        if prop_unit is not None:
            self.client.publish("homie/{}/{}/{}/$unit".format(dev_id, node_id, prop_id), prop_unit)

    def _pub_device_node_property_value(self, dev_id, node_id, prop_id, prop_value):
            self.client.publish("homie/{}/{}/{}".format(dev_id, node_id, prop_id), prop_value)

