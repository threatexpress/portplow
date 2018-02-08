# PortPlow.io

Manage large-scale distributed scans with a web front end.  This project was built to be run on a DigitalOcean 2-4GB RAM system.

## Setup instructions
  - Setup DNS A record pointing to your DigitalOcean Droplet.
  - Download the portplow repo to the droplet
  - Extract the repo to the `/opt` directory
  - Modify the settings in the conf file
  - Execute `./installer.sh`

This will setup and configure nginx, postgres, redis, letsencrypt and Django.
