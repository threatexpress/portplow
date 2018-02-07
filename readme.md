# PortPlow.io

Manage large-scale distributed scans with a web frontend.  This project was build to be
run on DigitalOcean on a 2-4GB ram system.

## Setup instructions
  - Setup DNS A record pointing to your DigitalOcean Droplet.
  - Download the portplow repo to the droplet
  - Extract the repo to the `/opt` directory
  - Modify the settings in the conf file
  - Execute `./installer.sh`

This will setup and configure nginx, postgres, redis, letsencrypt and Django.
