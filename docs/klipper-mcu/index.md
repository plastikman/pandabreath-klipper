# KlipperMCU Firmware

A possible future alternative to the OEM and ESPHome paths: replace the Panda Breath's ESP32-C3 firmware with a custom [ESP-IDF](https://idf.espressif.com/) build that speaks the native **Klipper MCU binary protocol** over USB serial (via the onboard CH340K bridge).

The custom firmware itself has moved out of this repository into its own project:

**[justinh-rahb/klipper-esp32](https://github.com/justinh-rahb/klipper-esp32)**

That repo carries the ESP-IDF project, the Panda Breath board HAL, GPIO mapping, build/flash instructions, and recovery notes. This repo (`pandabreath-klipper`) stays focused on the stock-firmware Klipper integration (`panda_breath.py`) and the ESPHome path; see the [docs home](../index.md) for those.

!!! warning "Exploratory status"
    This path is mostly theoretical right now. It has not been validated end-to-end on real hardware and should be treated as an exploration, not a supported solution.

---

## Why KlipperMCU?

| Concern | OEM firmware | ESPHome | KlipperMCU |
|---|---|---|---|
| Thermal runaway | Removed in v1.0.2; PTC fault UI re-added in v1.0.3; full cutoff uncertain | Configurable | **Klipper's own `verify_heater`** |
| PID control | Device-managed | ESPHome bang-bang | **Klipper PID — fully tunable** |
| Klipper extras module | Required | Required | **Not needed** |
| MQTT broker | Not needed | Required | Not needed |
| WiFi | Required | Optional (MQTT) | **Not needed** |
| Transport | WebSocket (WiFi) | MQTT (WiFi) | **USB serial** |
| Fan speed | Device-managed | Configurable | Internal firmware — follows heater relay |
| OTA updates | BTT releases only | ESPHome OTA | Serial flash (USB) |

The primary advantages would be simplicity and reliability: a single USB cable replacing WiFi dependency and MQTT infrastructure, with Klipper's native PID and thermal safety applying directly. Those advantages are still aspirational until the path is validated.

For hardware mapping, build/flash steps, `printer.cfg` examples, and recovery instructions, see the [justinh-rahb/klipper-esp32](https://github.com/justinh-rahb/klipper-esp32) README.

---

## Multi-instance architecture with Klipper Router

The default KlipperMCU setup adds the Panda Breath as a secondary `[mcu panda_breath]` to the main printer's Klipper instance. An alternative is to run a **dedicated Klipper instance** for the Panda Breath and bridge it to the printer using [Klipper Router](https://github.com/paxx12/klipper-router) — a JSON-RPC bridge by paxx12 (same author as the U1 extended firmware).

The key advantage is **fault isolation**: if the Panda Breath's Klipper instance crashes (USB disconnect, MCU timeout, thermal fault), the main printer keeps running. With a single-instance `[mcu panda_breath]` setup, any MCU communication error triggers Klipper's emergency shutdown and kills the print. In the multi-instance setup, Klipper's `verify_heater` and thermal protections still apply to the Panda Breath instance — it shuts down safely on its own — but the printer is unaffected.

This is useful when:

- You want a crash-safe setup — Panda Breath faults don't kill active prints
- The Snapmaker U1's modified Klipper makes adding a second MCU difficult
- You want the printer to react to chamber temperature changes via event subscriptions

### How it works

Klipper Router connects to multiple Klipper instances over their Unix sockets and registers shared remote methods on each. The main printer can query chamber temperature, send heater commands, and subscribe to status updates — all via G-code macros.

```
Klipper (main printer)           Klipper Router           Klipper (Panda Breath)
  klippy_host_main.sock  ◄────►  router.cfg   ◄────►   klippy_host_pb.sock
                                                              │
                                                        [mcu panda_breath]
                                                          serial: /dev/ttyUSB0
```

### Example: subscribe to chamber temperature

On the main printer, a macro can subscribe to the Panda Breath's heater status:

```ini
[gcode_macro SUBSCRIBE_CHAMBER]
gcode:
    {action_call_remote_method("router/objects/subscribe",
        target="panda_breath",
        objects={"heater_generic chamber": ["temperature"]},
        gcode_callback="ON_CHAMBER_UPDATE")}

[gcode_macro ON_CHAMBER_UPDATE]
gcode:
    {% set temp = params.HEATER_GENERIC_CHAMBER_TEMPERATURE|default(0)|float %}
    M118 Chamber: {temp}°C
```

### Example: send heater commands across instances

```ini
[gcode_macro SET_CHAMBER_TEMP]
gcode:
    {% set target = params.TARGET|default(0)|int %}
    {action_call_remote_method("router/gcode/script",
        target="panda_breath",
        script="SET_HEATER_TEMPERATURE HEATER=chamber TARGET=" ~ target)}
```

See the [Klipper Router README](https://github.com/paxx12/klipper-router) for full configuration and API reference.
