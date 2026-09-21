# OmnetFederateResearch



This repository contains the co-simulation environment, mobility configuration files, packet serialization specifications, and statistical analysis scripts.



The experimental framework couples \*\*Eclipse MOSAIC\*\* with the \*\*OMNeT++ Federate\*\* to model the vehicular wireless protocol stack (IEEE 802.11p/DSRC and IP/UDP/CoAP) alongside \*\*SUMO\*\* for microscopic road traffic simulation.



\---



\## Architecture Overview



The simulation environment integrates three co-simulated components:



\* \*\*Eclipse MOSAIC:\*\* Serves as the central Runtime Infrastructure (RTI) orchestrator, synchronizing simulation time progression and mediating federate message exchanges\[cite: 1].

\* \*\*OMNeT++ Federate:\*\* Models the physical and data link layers (IEEE 802.11p on the 5.9 GHz Control Channel), network routing, and application stacks\[cite: 1]:

&#x20; \* \*\*BSM/WSMP:\*\* Dedicated periodic vehicular safety broadcast\[cite: 1].

&#x20; \* \*\*CoAP/UDP/IPv4:\*\* RESTful vehicular telemetry using Non-Confirmable (NON) datagrams with a deterministic 20-byte binary payload\[cite: 1].

\* \*\*SUMO (Simulation of Urban MObility):\*\* Simulates microscopic vehicle movement, driver behavior, and traffic light phases via the TraCI interface\[cite: 1].





\---



\## Prerequisites and Dependencies



Ensure that the target Linux host (Ubuntu 20.04 LTS or 22.04 LTS recommended) meets the following requirements:



1\. \*\*Java JDK:\*\* OpenJDK 11 or higher (required by Eclipse MOSAIC).

2\. \*\*Eclipse MOSAIC:\*\* Version 21.0 or higher\[cite: 1].

3\. \*\*OMNeT++:\*\* Version 5.6.2 or 5.7 (compiled with C++14/17 support).

4\. \*\*SUMO:\*\* Version 1.12.0 or higher\[cite: 1].

5\. \*\*Python 3.8+:\*\* With `numpy`, `scipy`, `pandas`, and `matplotlib` installed for data analysis.



```bash

sudo apt update

sudo apt install build-essential gcc g++ bison flex perl tcl-dev tk-dev \\

&#x20;   libxml2-dev zlib1g-dev default-jre default-jdk python3 python3-pip sumo sumo-tools

pip3 install numpy scipy pandas matplotlib

```



\---



\## OMNeT++ Federate Setup and Build



Before launching Eclipse MOSAIC, compile the OMNeT++ federate library against the MOSAIC RTI interface:



1\. \*\*Configure environment variables:\*\*

&#x20;  ```bash

&#x20;  export OMNETPP\_HOME=/path/to/omnetpp-5.6.2

&#x20;  export PATH=$OMNETPP\_HOME/bin:$PATH

&#x20;  export MOSAIC\_HOME=/path/to/eclipse-mosaic

&#x20;  ```



2\. \*\*Compile the federate binary:\*\*

&#x20;  ```bash

&#x20;  cd federates/omnetpp/

&#x20;  opp\_makemake -f --deep -o omnetpp\_federate -I$MOSAIC\_HOME/lib

&#x20;  make -j$(nproc)

&#x20;  ```



3\. \*\*Verify compilation:\*\*

&#x20;  Ensure that the executable or shared library (`omnetpp\_federate`) has been generated successfully in `federates/omnetpp/`.



\---



\## Scenario Parameters and Configuration



\### Communication Parameters

\* \*\*MAC/PHY Standard:\*\* IEEE 802.11p (5.9 GHz Control Channel)\[cite: 1].

\* \*\*Transmission Power ($P\_t$):\*\* 20 mW (13 dBm)\[cite: 1].

\* \*\*Data Rate ($R$):\*\* 6 Mbps\[cite: 1].

\* \*\*Effective Communication Range ($R\_{max}$):\*\* $\\approx 250$ m\[cite: 1].

\* \*\*Message Frequency:\*\* 10 Hz (100 ms transmission interval)\[cite: 1].



\### SUMO Mobility Model Parameters

\* \*\*Maximum Acceleration ($a$):\*\* $2.6\\text{ m/s}^2$.

\* \*\*Deceleration ($b$):\*\* $4.5\\text{ m/s}^2$.

\* \*\*Driver Reaction Time ($\\tau$):\*\* $1.0\\text{ s}$.

\* \*\*Driver Imperfection ($\\sigma$):\*\* $0.5$.

\* \*\*Minimum Standstill Gap ($s\_0$):\*\* $2.5\\text{ m}$.



\### BSM-to-CoAP Binary Payload Schema (20 Bytes)

The CoAP application transmits essential vehicular parameters encoded into a fixed-width 20-byte binary layout\[cite: 1]:

\* `Vehicle ID`: 4 bytes (`uint32\_t`)\[cite: 1].

\* `Latitude`: 4 bytes (`float32`, IEEE 754)\[cite: 1].

\* `Longitude`: 4 bytes (`float32`, IEEE 754)\[cite: 1].

\* `Speed`: 4 bytes (`float32`, IEEE 754)\[cite: 1].

\* `Heading`: 4 bytes (`float32`, IEEE 754)\[cite: 1].



\---



\## Running Simulations



To account for stochastic variations, each scenario is evaluated across 30 independent runs using distinct pseudo-random seeds\[cite: 1].



\### Single Execution Example (Urban Scenario with CoAP)

```bash

mosaic.sh -s scenarios/Urban\_campina -c node/MosaicProxyApp.cc

```



\*Note: All simulation runs enforce an initial 60-second warm-up period in SUMO before metric logging begins to ensure traffic flow reaches steady-state conditions\[cite: 1].\*



\---



```

