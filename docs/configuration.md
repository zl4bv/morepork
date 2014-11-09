# Configuration

Morepork settings are configured through several YAML configuration files.

## Tripwire

Tripwire is a component for detecting changes in traffic behaviour through port-based and flow-based statistics provided by an OpenFlow-enabled device.

The paramters for suspicious behaviour are defined in a YAML file as a set of thresholds place upon available metrics. The thresholds are compared to incoming statistics and Tripwire will output a list of thresholds that have been breached.

### Config file

The top-level element distinguishes between port-based and flow-based thresholds.

Valid values are: `port`, `flow`

### Port-based parameters

#### Data path ID

Indicates the data path that the statistic(s) come from.

Valid values are: any integer that matches a valid data path ID, or `*` for any data path

#### Port number

Indicates the switch port number.

Valid values are: any integer that matches a valid switch port number or `*` for any port number

#### Metric name

Indicates a metric name as supplied in the OpenFlow port stats response.

Examples of valid values are: `rx_packets`, `rx_bytes`, `tx_bytes`, etc.

#### Threshold

If the matching statistic value exceeds this value then Tripwire will flag this statistic (and return it).

Valid values are: any integer

#### Derivative

Indicates that the nth-order derivative should be calculated before comparing to the threshold.

Assuming the raw statistics is a counter, then the 1st-order statistic will be the rate and the 2nd-order statistic will be the acceleration.

Valid values are: `0`, `1`, `2`

### Flow-based parameters

TODO.

### Example

```yaml
port:
    1:
        1:
            rx_bytes:
                threshold: 1000000000
                derivative: 1
```

This example is provided in morepork/config/tripwire.yaml.example.
