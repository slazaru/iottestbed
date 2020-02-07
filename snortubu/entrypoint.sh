#! /bin/sh

# update /etc/snort/snort.conf HOME_NET
echo "SNORT (INFO) - Setting HOME_NET variable in snort.conf"
sed -i 's#^ipvar HOME_NET.*#ipvar HOME_NET '"$HOME_NET"'#' /etc/snort/snort.conf
# create cron job for Pull Pork updates
echo "SNORT (INFO) - Creating PulledPork cron job for daily rule updates"
croncmd="/usr/local/bin/pulledpork.pl -H -c /etc/snort/pulledpork.conf"
cronjob="30      13      *       *       *       $croncmd"
( crontab -l | grep -v -F "$croncmd" ; echo "$cronjob" ) | crontab - && crond

# oinkcode

if echo $OINKCODE  | grep -wq "<oinkcode>"
then
    echo "SNORT (INFO) - No OINKCODE provided, only using community rules"
elif echo $OINKCODE | grep -Eq '^[a-f0-9]{40}$'
then
    echo "SNORT (INFO) - adding OINKCODE to pulledpork.conf" 
    sed -i 's/<oinkcode>/'"$OINKCODE"'/g' /etc/snort/pulledpork.conf
    echo "SNORT (INFO) - Activating subscription rules with provided oinkcode"
    sed -i '/rule_url=https\:\/\/www\.snort\.org\/reg\-rules*/s/# //' /etc/snort/pulledpork.conf
else
    echo "SNORT (ERROR) - Invalid OINKCODE format"
fi

# Update Snort rules with Pulled Pork
echo "SNORT (INFO) - Running pulledpork.pl to update rules"
/usr/local/bin/pulledpork.pl -c /etc/snort/pulledpork.conf && \
echo "SNORT (INFO) - PulledPork rules updated" || \
echo "SNORT (ERROR) - Pulled Pork update failed."

# start websnort
websnort > websnort.log
# start snort
echo "SNORT (INFO) - Staring snort with provided options: $@"
exec snort -c /etc/snort/snort.conf "$@"

