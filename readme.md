# IoT Network Traffic Monitor Final Project

## Isaac Brickner, Network Security

## Purpose

The **IoT Network Traffic Monitor** is a web app built with **Flask** and **Scapy** that to monitors network traffic from simulated IoT devices! I would love to automate my future home with personal IoT devices, but I know there can be security concerns. I thought I'd combine the python flask skills with scapy that we went over in this course to make a small mock application that monitors traffic to my *future* IoT devices! We don't want a bad actor attempting to unlock our home and turn off the security cameras!

## Functionality

- **Simulated IoT Devices**: Includes *simulated IoT* devices like a couple security cameras, a thermostat, smart lock, and lighting system with unique mock IP addresses.
- **Packet Sniffing**: Monitors the network traffic using **Scapy** and identifies packets attempting to connect to the IoT devices. These packets aren't actually trying to connect to the devices, but I simulated that in order to test the idea.
- **Suspicious Activity Alerts**: This function flags suspicious packets targeting my IoT devices, showing source IP, destination, and a few other details.
- **Real-Time Web Dashboard**: A simple web interface to view IoT device status and suspicious packet alerts using flask and jinja templating!

## Technologies

- **Flask**: Web framework for serving the app and backend logic.
- **Scapy**: Python library for sniffing and analyzing network packets.
- **Jinja2**: Templating engine for dynamically rendering HTML pages.

## Installation

1. Clone the repository:
```git clone https://github.com/yourusername/IoT-Network-Traffic-Monitor.git```
2. Set up venv
    ```python3 -m venv venv source venv/bin/activate```
3. Install dependencies:
    ```pip install -r requirements.txt```
4. Run:
    ```python app.py```
# netsec_final_IoT_traffic_monitor
