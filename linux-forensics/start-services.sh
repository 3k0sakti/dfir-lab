#!/bin/bash

# Start rsyslog
service rsyslog start

# Start SSH
service ssh start

# Start nginx
service nginx start

# Start cron
service cron start

# Keep container running
tail -f /dev/null