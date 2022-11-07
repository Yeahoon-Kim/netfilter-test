#pragma once

#include <cstdint>
#include <arpa/inet.h>
#include "ip.hpp"

struct IPv4Hdr final {
    uint8_t ip_hl:4,        /* header length */
            ip_v:4;         /* version */
    uint8_t ip_tos;         /* type of service */

    uint16_t ip_len;        /* total length */
    uint16_t ip_id;         /* identification */
    uint16_t ip_off;

    uint8_t ip_ttl;         /* time to live */
    uint8_t ip_p;           /* protocol */
    uint16_t ip_sum;        /* checksum */

    IPv4 ip_src, ip_dst;    /* source and dest address */

    uint32_t sip() { return ntohl(ip_src); }
    uint32_t dip() { return ntohl(ip_dst); }
    uint16_t totalLength() { return ntohs(ip_len); }
};
