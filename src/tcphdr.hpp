#pragma once

#include <cstdint>
#include <arpa/inet.h>

/*
 *  TCP header
 *  Transmission Control Protocol
 *  Static header size: 20 bytes
 */
#pragma pack(push, 1)
struct TcpHdr final {
    uint16_t th_sport;          /* source port */
    uint16_t th_dport;          /* destination port */
    uint32_t th_seq;            /* sequence number */
    uint32_t th_ack;            /* acknowledgement number */

    uint8_t th_x2: 4,           /* (unused) */
           th_off: 4;           /* data offset */

    /* control flags */
    enum th_flags: uint8_t {
        TH_FIN = 0x01,  /* finished send data */
        TH_SYN = 0x02,  /* synchronize sequence numbers */
        TH_RST = 0x04,  /* reset the connection */
        TH_PUSH = 0x08, /* push data to the app layer */
        TH_ACK = 0x10,  /* acknowledge */
        TH_URG = 0x20,  /* urgent! */
        TH_ECE = 0x40,  
        TH_CWR = 0x80   
    };

    uint16_t th_win;    /* window */
    uint16_t th_sum;    /* checksum */
    uint16_t th_urp;    /* urgent pointer */

    uint16_t sport() { return ntohs(this->th_sport); }
    uint16_t dport() { return ntohs(this->th_dport); }
};
#pragma pack(pop)
