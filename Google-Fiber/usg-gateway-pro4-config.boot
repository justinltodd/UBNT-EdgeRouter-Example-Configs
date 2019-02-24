firewall {
    all-ping enable
    broadcast-ping disable
    group {
        address-group authorized_guests {
            description "authorized guests MAC addresses"
        }
        address-group guest_allow_addresses {
            description "allow addresses for guests"
        }
        address-group guest_allow_dns_servers {
            description "allow dns servers for guests"
        }
        address-group guest_portal_address {
            description "guest portal address"
        }
        address-group guest_restricted_addresses {
            address 192.168.0.0/16
            address 172.16.0.0/12
            address 10.0.0.0/8
            description "restricted addresses for guests"
        }
        address-group unifi_controller_addresses {
            address 10.0.0.10
        }
        ipv6-network-group corporate_networkv6 {
            description "IPv6 corporate subnets"
        }
        ipv6-network-group guest_networkv6 {
            description "IPv6 guest subnets"
        }
        network-group captive_portal_subnets {
            description "captive portal subnets"
        }
        network-group corporate_network {
            description "corporate subnets"
            network 10.0.0.0/24
        }
        network-group guest_allow_subnets {
            description "allow subnets for guests"
        }
        network-group guest_network {
            description "guest subnets"
        }
        network-group guest_restricted_subnets {
            description "restricted subnets for guests"
        }
        network-group remote_client_vpn_network {
            description "remote client VPN subnets"
        }
        network-group remote_site_vpn_network {
            description "remote site VPN subnets"
        }
        network-group remote_user_vpn_network {
            description "Remote User VPN subnets"
        }
        port-group guest_portal_ports {
            description "guest portal ports"
        }
        port-group guest_portal_redirector_ports {
            description "guest portal redirector ports"
            port 39080
            port 39443
        }
        port-group unifi_controller_ports-tcp {
            description "unifi tcp ports"
            port 8080
        }
        port-group unifi_controller_ports-udp {
            description "unifi udp ports"
            port 3478
        }
    }
    ipv6-name AUTHORIZED_GUESTSv6 {
        default-action drop
        description "authorization check packets from guest network"
    }
    ipv6-name GUESTv6_IN {
        default-action accept
        description "packets from guest network"
        rule 3001 {
            action drop
            description "drop packets to intranet"
            destination {
                group {
                    ipv6-network-group corporate_networkv6
                }
            }
        }
    }
    ipv6-name GUESTv6_LOCAL {
        default-action drop
        description "packets from guest network to gateway"
        rule 3001 {
            action accept
            description "allow DNS"
            destination {
                port 53
            }
            protocol udp
        }
        rule 3002 {
            action accept
            description "allow ICMP"
            protocol icmp
        }
    }
    ipv6-name GUESTv6_OUT {
        default-action accept
        description "packets forward to guest network"
    }
    ipv6-name LANv6_IN {
        default-action accept
        description "packets from intranet"
    }
    ipv6-name LANv6_LOCAL {
        default-action accept
        description "packets from intranet to gateway"
    }
    ipv6-name LANv6_OUT {
        default-action accept
        description "packets forward to intranet"
    }
    ipv6-name WANv6_IN {
        default-action drop
        description "packets from internet to intranet"
        rule 3001 {
            action accept
            description "allow established/related sessions"
            state {
                established enable
                invalid disable
                new disable
                related enable
            }
        }
        rule 3002 {
            action drop
            description "drop invalid state"
            state {
                established disable
                invalid enable
                new disable
                related disable
            }
        }
    }
    ipv6-name WANv6_LOCAL {
        default-action drop
        description "packets from internet to gateway"
        rule 3001 {
            action accept
            description "Allow neighbor advertisements"
            icmpv6 {
                type neighbor-advertisement
            }
            protocol ipv6-icmp
        }
        rule 3002 {
            action accept
            description "Allow neighbor solicitation"
            icmpv6 {
                type neighbor-solicitation
            }
            protocol ipv6-icmp
        }
        rule 3003 {
            action accept
            description "allow established/related sessions"
            state {
                established enable
                invalid disable
                new disable
                related enable
            }
        }
        rule 3004 {
            action accept
            description "Allow DHCPv6"
            destination {
                port 546
            }
            protocol udp
            source {
                port 547
            }
        }
        rule 3005 {
            action accept
            description "Allow router advertisements"
            icmpv6 {
                type router-advertisement
            }
            protocol ipv6-icmp
        }
        rule 3006 {
            action drop
            description "drop invalid state"
            state {
                established disable
                invalid enable
                new disable
                related disable
            }
        }
    }
    ipv6-name WANv6_OUT {
        default-action accept
        description "packets to internet"
    }
    ipv6-receive-redirects disable
    ipv6-src-route disable
    ip-src-route disable
    log-martians enable
    name AUTHORIZED_GUESTS {
        default-action drop
        description "authorization check packets from guest network"
    }
    name GUEST_IN {
        default-action accept
        description "packets from guest network"
        rule 3001 {
            action accept
            description "allow DNS packets to external name servers"
            destination {
                port 53
            }
            protocol tcp_udp
        }
        rule 3002 {
            action accept
            description "allow packets to captive portal"
            destination {
                group {
                    network-group captive_portal_subnets
                }
                port 443
            }
            protocol tcp
        }
        rule 3003 {
            action accept
            description "allow packets to allow subnets"
            destination {
                group {
                    address-group guest_allow_addresses
                }
            }
        }
        rule 3004 {
            action drop
            description "drop packets to restricted subnets"
            destination {
                group {
                    address-group guest_restricted_addresses
                }
            }
        }
        rule 3005 {
            action drop
            description "drop packets to intranet"
            destination {
                group {
                    network-group corporate_network
                }
            }
        }
        rule 3006 {
            action drop
            description "drop packets to remote user"
            destination {
                group {
                    network-group remote_user_vpn_network
                }
            }
        }
        rule 3007 {
            action drop
            description "authorized guests white list"
            destination {
                group {
                    address-group authorized_guests
                }
            }
        }
    }
    name GUEST_LOCAL {
        default-action drop
        description "packets from guest network to gateway"
        rule 3001 {
            action accept
            description "allow DNS"
            destination {
                port 53
            }
            protocol tcp_udp
        }
        rule 3002 {
            action accept
            description "allow ICMP"
            protocol icmp
        }
        rule 3003 {
            action accept
            description "allow to DHCP server"
            destination {
                port 67
            }
            protocol udp
            source {
                port 68
            }
        }
    }
    name GUEST_OUT {
        default-action accept
        description "packets forward to guest network"
    }
    name LAN_IN {
        default-action accept
        description "packets from intranet"
        rule 6001 {
            action accept
            description "accounting defined network 10.0.0.0/24"
            source {
                address 10.0.0.0/24
            }
        }
    }
    name LAN_LOCAL {
        default-action accept
        description "packets from intranet to gateway"
    }
    name LAN_OUT {
        default-action accept
        description "packets forward to intranet"
        rule 6001 {
            action accept
            description "accounting defined network 10.0.0.0/24"
            destination {
                address 10.0.0.0/24
            }
        }
    }
    name WAN_IN {
        default-action drop
        description "packets from internet to intranet"
        rule 3001 {
            action accept
            description "allow established/related sessions"
            state {
                established enable
                invalid disable
                new disable
                related enable
            }
        }
        rule 3002 {
            action drop
            description "drop invalid state"
            state {
                established disable
                invalid enable
                new disable
                related disable
            }
        }
    }
    name WAN_LOCAL {
        default-action drop
        description "packets from internet to gateway"
        rule 3001 {
            action accept
            description "allow established/related sessions"
            state {
                established enable
                invalid disable
                new disable
                related enable
            }
        }
        rule 3002 {
            action drop
            description "drop invalid state"
            state {
                established disable
                invalid enable
                new disable
                related disable
            }
        }
    }
    name WAN_OUT {
        default-action accept
        description "packets to internet"
    }
    options {
        mss-clamp {
            interface-type pppoe
            interface-type pptp
            interface-type vti
            mss 1452
        }
        mss-clamp6 {
            interface-type pppoe
            interface-type pptp
            mss 1452
        }
    }
    receive-redirects disable
    send-redirects enable
    source-validation strict
    syn-cookies enable
}
interfaces {
    ethernet eth0 {
        address 10.0.0.1/24
        description LAN
        duplex auto
        firewall {
            in {
                ipv6-name LANv6_IN
                name LAN_IN
            }
            local {
                ipv6-name LANv6_LOCAL
                name LAN_LOCAL
            }
            out {
                ipv6-name LANv6_OUT
                name LAN_OUT
            }
        }
        ipv6 {
            dup-addr-detect-transmits 1
            router-advert {
                cur-hop-limit 64
                default-preference high
                link-mtu 0
                managed-flag false
                max-interval 600
                name-server fe80::b6fb:e4ff:fe8e:d7a3
                other-config-flag false
                prefix ::/64 {
                    autonomous-flag true
                    on-link-flag true
                    preferred-lifetime 14400
                    valid-lifetime 86400
                }
                radvd-options "DNSSL localdomain {};"
                reachable-time 0
                retrans-timer 0
                send-advert true
            }
        }
        speed auto
    }
    ethernet eth1 {
        disable
        duplex auto
        speed auto
    }
    ethernet eth2 {
        description WAN
        duplex auto
        speed auto
        vif 2 {
            address dhcp
            description WAN
            dhcp-options {
                client-option "retry 60;"
                default-route update
                default-route-distance 1
                name-server update
            }
            dhcpv6-pd {
                pd 0 {
                    interface eth0 {
                        prefix-id 56
                    }
                    prefix-length 56
                }
                rapid-commit enable
            }
            egress-qos "0:3 1:3 2:3 4:3 5:3 6:3 7:3"
            firewall {
                in {
                    ipv6-name WANv6_IN
                    name WAN_IN
                }
                local {
                    ipv6-name WANv6_LOCAL
                    name WAN_LOCAL
                }
                out {
                    ipv6-name WANv6_OUT
                    name WAN_OUT
                }
            }
        }
    }
    ethernet eth3 {
        disable
        duplex auto
        speed auto
    }
    loopback lo {
    }
}
port-forward {
    auto-firewall disable
    hairpin-nat enable
    lan-interface eth0
    wan-interface eth2.2
}
service {
    dhcp-server {
        disabled false
        global-parameters "class &quot;denied&quot; { match substring (hardware, 1, 6); deny booting; } subclass &quot;denied&quot; b4:fb:e4:8e:d7:a3; subclass &quot;denied&quot; b4:fb:e4:8e:d7:a4; subclass &quot;denied&quot; b4:fb:e4:8e:d7:a5; subclass &quot;denied&quot; b4:fb:e4:8e:d7:a6;"
        hostfile-update enable
        shared-network-name net_LAN_eth0_10.0.0.0-24 {
            authoritative enable
            description vlan1
            subnet 10.0.0.0/24 {
                default-router 10.0.0.1
                dns-server 10.0.0.1
                domain-name localdomain
                lease 86400
                start 10.0.0.6 {
                    stop 10.0.0.254
                }
            }
        }
        static-arp disable
        use-dnsmasq disable
    }
    dns {
        forwarding {
            cache-size 10000
            except-interface eth2.2
            options host-record=unifi,10.0.0.10
        }
    }
    gui {
        http-port 80
        https-port 443
        older-ciphers enable
    }
    lldp {
        interface eth2 {
            disable
        }
    }
    nat {
        rule 6001 {
            description "MASQ corporate_network to WAN"
            log disable
            outbound-interface eth2.2
            protocol all
            source {
                group {
                    network-group corporate_network
                }
            }
            type masquerade
        }
        rule 6002 {
            description "MASQ remote_user_vpn_network to WAN"
            log disable
            outbound-interface eth2.2
            protocol all
            source {
                group {
                    network-group remote_user_vpn_network
                }
            }
            type masquerade
        }
        rule 6003 {
            description "MASQ guest_network to WAN"
            log disable
            outbound-interface eth2.2
            protocol all
            source {
                group {
                    network-group guest_network
                }
            }
            type masquerade
        }
    }
    ssh {
        port 22
        protocol-version v2
    }
}
system {
    conntrack {
        expect-table-size 2048
        hash-size 32768
        modules {
            sip {
                disable
            }
        }
        table-size 262144
        timeout {
            icmp 30
            other 600
            tcp {
                close 10
                close-wait 60
                established 7440
                fin-wait 120
                last-ack 30
                syn-recv 60
                syn-sent 120
                time-wait 120
            }
            udp {
                other 30
                stream 180
            }
        }
    }
    domain-name localdomain
    host-name ubnt
    ip {
        override-hostname-ip 10.0.0.1
    }
    login {
        user admin {
            authentication {
                encrypted-password $6$jwAbbljT$a1TwxV/9J5/b3T4257mu19lcZGSnk83wBi0TOUyufEizhbgM1W4Xq8FPIr7ELQhggLjuDBMEULhvWLsknjKam1
            }
            level admin
        }
    }
    ntp {
        server 0.ubnt.pool.ntp.org {
        }
        server 1.ubnt.pool.ntp.org {
        }
        server 2.ubnt.pool.ntp.org {
        }
        server 3.ubnt.pool.ntp.org {
        }
    }
    offload {
        ipsec enable
        ipv4 {
            forwarding enable
            gre enable
            pppoe enable
            vlan enable
        }
        ipv6 {
            forwarding enable
            vlan enable
        }
    }
    static-host-mapping {
        host-name setup.ubnt.com {
            alias setup
            inet 10.0.0.1
        }
    }
    syslog {
        global {
            facility all {
                level notice
            }
            facility protocols {
                level debug
            }
        }
    }
    time-zone America/Chicago
    traffic-analysis {
        dpi enable
        export disable
    }
}
unifi {
    mgmt {
        cfgversion 7f6c20e408df92e4
    }
}


/* Warning: Do not remove the following line. */
/* === vyatta-config-version: "config-management@1:conntrack@1:cron@1:dhcp-relay@1:dhcp-server@4:firewall@5:ipsec@5:nat@3:qos@1:quagga@2:system@4:ubnt-pptp@1:ubnt-util@1:vrrp@1:webgui@1:webproxy@1:zone-policy@1" === */
/* Release version: v4.4.36.5146617.181205.0451 */
