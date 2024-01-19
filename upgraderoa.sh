rm /etc/bird/roa_dn42.conf
rm /etc/bird/roa_dn42_v6.conf
wget -4 -O /tmp/dn42_roa.conf https://dn42.burble.com/roa/dn42_roa_bird2_4.conf && mv -f /tmp/dn42_roa.conf /etc/bird/dn42_roa.conf
wget -4 -O /tmp/dn42_roa_v6.conf https://dn42.burble.com/roa/dn42_roa_bird2_6.conf && mv -f /tmp/dn42_roa_v6.conf /etc/bird/dn42_roa_v6.conf
mv /etc/bird/dn42_roa_v6.conf /etc/bird/roa_dn42_v6.conf
mv /etc/bird/dn42_roa.conf /etc/bird/roa_dn42.conf
birdc configure
birdc show protocol