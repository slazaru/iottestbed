!/bin/bash
cd /rq
rq worker describeq -u $REDIS_URL &
rq worker zeekq -u $REDIS_URL &
rq-dashboard --redis-url $REDIS_URL --port 9999

