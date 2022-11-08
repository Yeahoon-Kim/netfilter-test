#include <iostream>
#include <iomanip>
#include <cstdint>
#include <cstring>

#include <netinet/in.h>
#include <linux/types.h>
#include <linux/netfilter.h>		/* for NF_ACCEPT */
#include <errno.h>

#include <libnetfilter_queue/libnetfilter_queue.h>

#include "ipv4hdr.hpp"
#include "tcphdr.hpp"

using namespace std;

string filterKeyword;

/* returns packet id */
static uint32_t print_pkt(struct nfq_data *tb) {
	struct nfqnl_msg_packet_hdr *ph;
	struct nfqnl_msg_packet_hw *hwph;
	uint32_t id, mark, ifi;
	uint8_t *data;
	int ret;

	ph = nfq_get_msg_packet_hdr(tb);
	if (ph) {
		id = ntohl(ph->packet_id);

		cout << "hw_protocol: 0x" << hex << setw(4) << setfill('0') << ntohs(ph->hw_protocol);
		cout << " hook: " << (unsigned int)ph->hook;
		cout << " id: " << (unsigned int)id << '\n';
	}
	else {
		std::cerr << "Error: Error while getting message packet header" << std::endl;
		return -1;
	}

	hwph = nfq_get_packet_hw(tb);
	if (hwph) {
		int i, hlen = ntohs(hwph->hw_addrlen);

		// Print hardware address of source device
		cout << "hw_src_addr: ";
		for (i = 0; i < hlen - 1; i++) cout << hex << setw(2) << setfill('0') << (unsigned int)hwph->hw_addr[i] << ':';
		cout << hex << setw(2) << setfill('0') << (unsigned int)hwph->hw_addr[hlen - 1] << '\n';
	}

	// Print packet mark
	mark = nfq_get_nfmark(tb);
	if(mark) cout << "mark: " << (unsigned int)mark << '\n';

	// Print the interface that the packet was received through
	ifi = nfq_get_indev(tb);
	if(ifi) cout << "indev: " << (unsigned int)ifi << '\n';

	// Print gets the interface that the packet will be routed out
	ifi = nfq_get_outdev(tb);
	if(ifi) cout << "outdev: " << (unsigned int)ifi << '\n';

	// Print the physical interface that the packet was received
	ifi = nfq_get_physindev(tb);
	if(ifi) cout << "physindev: " << (unsigned int)ifi << '\n';

	// Print the physical interface that the packet output
	ifi = nfq_get_physoutdev(tb);
	if(ifi) cout << "physoutdev: " << (unsigned int)ifi << '\n';

	// Print payload
	ret = nfq_get_payload(tb, &data);
	if (ret >= 0) cout << "Payload length: " << dec << ret << '\n';
	
	cout << '\n';

	return id;
}

int acceptPacket(struct nfq_q_handle *qh, const uint32_t id) {
	return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
}

int dropPacket(struct nfq_q_handle *qh, const uint32_t id) {
	return nfq_set_verdict(qh, id, NF_DROP, 0, NULL);
}

static int cb(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg, struct nfq_data *nfa, void *data) {
	int totalHeaderLength, packetLength, IPHeaderLength;
	uint8_t* packet;
	uint32_t id;

	std::string payload;

	TcpHdr* TCPHeader;
	IPv4Hdr* IPv4Header;

	id = print_pkt(nfa);
	if(not id) return -1;

	if(nfq_get_payload(nfa, &packet) >= 0) {
		IPv4Header = (IPv4Hdr*)packet;

		// Check if next layer protocol is TCP
		if(IPv4Header->ip_p != 0x06) return acceptPacket(qh, id);
		
		packetLength = IPv4Header->totalLength();
		IPHeaderLength = IPv4Header->ip_hl << 2;
		TCPHeader = (TcpHdr*)(packet + IPHeaderLength);

		// Check if source or destination port is using HTTP protocol
		if(TCPHeader->dport() != 80 and TCPHeader->sport() != 80) return acceptPacket(qh, id);

		totalHeaderLength = IPHeaderLength + (TCPHeader->th_off << 2);

		// Check if payload is empty
		if(packetLength == totalHeaderLength) return acceptPacket(qh, id);
		payload = (char*)(packet + totalHeaderLength);

		// Check if payload include filter keyword
		if(payload.find(filterKeyword) == string::npos) return acceptPacket(qh, id);
		else return dropPacket(qh, id);
	}

	return -1;
}

int main(int argc, char* argv[]) {
	struct nfq_handle *handle;
	struct nfq_q_handle *qh;
	int fd, rv;
	char buf[4096] __attribute__ ((aligned));

	if(argc != 2) {
		cerr << "Error: Wrong parameters are given\n";
		cerr << "syntax : netfilter-test <host>\n";
		cerr << "sample : netfilter-test test.gilgil.net" << endl;

		return 1;
	}

	filterKeyword = argv[1];

	cout << "opening library handle\n";
	handle = nfq_open();

	if (not handle) {
		cerr << "Error: error during nfq_open()" << endl;
		exit(1);
	}

	cout << "unbinding existing nf_queue handler for AF_INET (if any)\n";
	if (nfq_unbind_pf(handle, AF_INET) < 0) {
		cerr << "Error: error during nfq_unbind_pf()" << endl;
		exit(1);
	}

	cout << "binding nfnetlink_queue as nf_queue handler for AF_INET\n";
	if (nfq_bind_pf(handle, AF_INET) < 0) {
		cerr << "Error: error during nfq_bind_pf()" << endl;
		exit(1);
	}

	cout << "binding this socket to queue '0'\n";
	qh = nfq_create_queue(handle, 0, &cb, NULL);
	if (not qh) {
		cerr << "Error: error during nfq_create_queue()" << endl;
		exit(1);
	}

	cout << "setting copy_packet mode\n";
	if (nfq_set_mode(qh, NFQNL_COPY_PACKET, 0xffff) < 0) {
		cerr << "Error: can't set packet_copy mode" << endl;
		exit(1);
	}

	fd = nfq_fd(handle);

	while( true ) {
		if ((rv = recv(fd, buf, sizeof(buf), 0)) >= 0) {
			cout << "pkt received\n";
			nfq_handle_packet(handle, buf, rv);

			continue;
		}
		/* if your application is too slow to digest the packets that
		 * are sent from kernel-space, the socket buffer that we use
		 * to enqueue packets may fill up returning ENOBUFS. Depending
		 * on your application, this error may be ignored. nfq_nlmsg_verdict_putPlease, see
		 * the doxygen documentation of this library on how to improve
		 * this situation.
		 */
		if (rv < 0 and errno == ENOBUFS) {
			cout << "losing packets!\n";
			continue;
		}

		cerr << "recv failed";
		break;
	}

	cout << "unbinding from queue 0\n";
	nfq_destroy_queue(qh);

#ifdef INSANE
	/* normally, applications SHOULD NOT issue this command, since
	 * it detaches other programs/sockets from AF_INET, too ! */
	cout << "unbinding from AF_INET\n";
	nfq_unbind_pf(h, AF_INET);
#endif

	cout << "closing library handle\n";
	nfq_close(handle);

	exit(0);
}
