# HackInSDN Anti-DDoS

Sflow-RT application for DDoS detection and mitigation using Kytos-ng SDN Orchestrator. This application provides real-time detection of DDoS flood attacks and automatically add mitigiation rules leveraging Kytos-ng SDN Orchestrator remote triggered black hole (RTBH).

## To install

1. [Download sFlow-RT](https://sflow-rt.com/download.php)
2. Run command: `./sflow-rt/get-app.sh hackinsdn hackinsdn-anti-ddos`
3. Optionally, also install browse-flows application to help monitoring: `./sflow-rt/get-app.sh sflow-rt browse-flows`
4. Restart sFlow-RT

Alternatively, use the Docker image:
https://hub.docker.com/r/sflow/ddos-protect/


For more information, visit:
https://hackinsdn.ufba.br

## References and credits

This application was built based on:
 - https://github.com/sflow-rt/ddos-protect
 - https://blog.sflow.com/2018/04/onos-measurement-based-control.html
