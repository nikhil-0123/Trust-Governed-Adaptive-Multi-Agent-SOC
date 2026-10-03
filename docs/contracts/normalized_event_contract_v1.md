# Normalized Security Event Contract

Project: Trust-Governed Adaptive Multi-Agent SOC for IT Cyber Defense
Version: 1.0

Every endpoint telemetry implementation must normalize important security
events into a common event structure before forwarding them to the SOC.

## Required Fields

event_id
timestamp
agent_id
hostname
os
event_type
source_ip
username
severity
detection_type
confidence
evidence

## Field Meaning

event_id:
Unique identifier for the event.

timestamp:
Time at which the source event occurred.

agent_id:
Unique identifier of the telemetry agent.

hostname:
Hostname of the endpoint that generated the event.

os:
Operating system of the endpoint.

event_type:
Normalized category of the observed event.

source_ip:
Relevant source IP when available.

username:
Relevant account when available.

severity:
Event severity such as low, medium, high, or critical.

detection_type:
Detection mechanism such as rule, xgboost, isolation_forest, or correlation.

confidence:
Detection confidence represented as a value from 0.0 to 1.0.

evidence:
Structured evidence supporting the detection.

## Design Rule

Endpoint implementations may collect OS-specific telemetry differently,
but the normalized output must follow this contract.

The SOC must not depend on Windows-specific or Linux-specific raw event
formats for its core processing pipeline.

## Versioning

Changes to required fields require an architecture review and contract
version update.
