#!/bin/bash
#source /etc/profile
#./boot.sh
echo removing....
kill -9 $(pidof ovsdb-server)
kill -9 $(pidof ovs-vswitchd)
ovs-dpctl del-dp ovs-system
rmmod openvswitch

./configure --with-linux=/lib/modules/$(uname -r)/build
echo installing....
#cp ../VMS_OVS/datapath_vms.c datapath/linux/datapath.c
make  #-j12 >/dev/null 2>/dev/null

if [ $? -eq 0 ] ; then
    make install
    make modules_install
else
    echo error in make $?
    exit 1
fi

echo loading modules....
modprobe openvswitch

echo initializing....

ovsdb-server --remote=punix:/usr/local/var/run/openvswitch/db.sock \
    --remote=db:Open_vSwitch,Open_vSwitch,manager_options \
    --private-key=db:Open_vSwitch,SSL,private_key \
    --certificate=db:Open_vSwitch,SSL,certificate \
    --bootstrap-ca-cert=db:Open_vSwitch,SSL,ca_cert \
    --pidfile --detach

ovs-vswitchd --pidfile --detach --log-file >/dev/null

if [ $? -eq 0 ] ; then
   # ovs-vsctl add-br br1
   # ovs-vsctl add-port br1 enp3s0f1
    ovs-vsctl add-br br0
    ovs-vsctl add-port br0 eno2
      #ip addr add 192.168.2.3/24 dev br0
      #ip addr add 192.168.1.11/24 dev br1
      #ip link set br0 up
      #ip link set br1 up
      #arp -s 192.168.3.1 11:11:11:11:11:22
      #arp -s 192.168.4.1 11:11:11:11:11:23
      #arp -s 192.168.3.1 38:97:d6:f5:39:15
   #ip link set enp2s0f0 down
   #ip link set enp2s0f1 down
     # ip route add 192.168.3.11 via 192.168.1.1 dev br1
     # ip route add 192.168.3.10 via 192.168.1.1 dev br0
      #ethtool -K br0 tx off
      #ethtool -K br1 tx off
      echo done
else
    echo error
fi
