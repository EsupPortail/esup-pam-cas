# /etc/cron.d/lib_pam-cas : crontab for libpam-cas cache ticket expiration
# This purges cache files according to /etc/default/pam_cas_expire.conf
*/5 * * * *     root   [ -x /usr/sbin/pam_cas_expire ] && [ -f /etc/default/pam_cas_expire.conf ] && /usr/sbin/pam_cas_expire
