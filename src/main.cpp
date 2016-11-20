#include <arpa/inet.h>
#include <linux/if_packet.h>
#include <sys/socket.h>
#include <netinet/ether.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/tcp.h>
#include <net/if.h>

#include <iostream>
#include <memory>
#include <tuple>
#include <vector>
#include <array>
#include <cassert>
#include <cstdlib>
#include <ctime>
#include <boost/program_options.hpp>
#include <boost/optional.hpp>

// Likely/unlikely for better speed?
// TO DO: move semantics for make_three_way_handshake_segment?

/*
 * Inheritance for enum class if we dont wana default size which is 4B. E.g for option_kind I need
   only 1B.

 * __attribute__((packed) if I wana timestamps size to have 10B. Without there is 12B.
   Unfortunately there is no standard [[packed]]. Maybe because it's dangerous on some
   archs? ref: http://stackoverflow.com/questions/8568432/is-gccs-attribute-packed-pragma-pack-unsafe

 * nice trick with sizeof(*this) :)

 * Thanks to Assertion `this->is_initialized()' in boost::optional I managed to fix stupid bug in
         make_three_way_handshake_segment. Experimental::optional doesn't have such assertion :(

 * if (x = y) is bad and compiler wanrns about it. Sth like x == y; is bad too and fortunately
   there are warnings for this too :)

 * Options impl based on seastar tcp.hh and
   http://www.firewall.cx/networking-topics/protocols/tcp/138-tcp-options.html

 * now there are:
    - tcp_manager which is not owner of packet, it only takes packet from outside and
      change its state
    - ip_manger which is "packet generator" - send/recv packets and pass them to tcp_manager
    - Main purpose - network_manager: it would be great to just send/recv stream of data
        (even in only one connection):
        -> init connection

        -> segmentation
        -> setting seq
        -> send
        -> recv
        -> ack
        -> checking seq + merging
        -> maybe retransmission

        -> close connection

        -> control flow, window, timeouts, etc

 * in recv_full_segment htons(ETHER_TYPE) is very important.
   Without this protocol no frames will be recieved by program

 * TO DO:
    - trigger_three_way_handshake__ok_scenario1__posix_backend
    - make segment (at the beginning in tcp_manager because it's covered) and stuff from dummy_test move-able
    - stuff from dummy_test (like endpoints) should probably be moved to ip_manager (owner of
      endpoints) and get by getter (const ref) if needed.
*/

namespace tcp
{

enum class state
{
    CLOSED, LISTEN, SYN_RCVD, SYN_SENT, ESTABLISHED,
    FIN_WAIT1, FIN_WAIT2, TIMED_WAIT, CLOSING, CLOSE_WAIT, LAST_ACK
};

enum class option_kind : uint8_t
{
    EOL = 0, NOP = 1, MSS = 2, WIN_SCALE = 3, SACK = 4, TIMESTAMPS = 8
};

constexpr unsigned minimum_tcp_header_size = 20;
constexpr unsigned maximum_ip_payload_size = 65515;
constexpr unsigned maximum_packet_size = maximum_ip_payload_size;
constexpr unsigned tcp_payload_size = maximum_packet_size - minimum_tcp_header_size;

struct packet
{
    uint16_t src_port, dst_port;
    uint32_t seq_number, ack_number;
    uint8_t offset : 4;
    uint8_t reserved_ns : 4;
    //uint8_t ns : 1;
    uint8_t cwr : 1;
    uint8_t ece : 1;
    uint8_t urg : 1;
    uint8_t ack : 1;
    uint8_t psh : 1;
    uint8_t rst : 1;
    uint8_t syn : 1;
    uint8_t fin : 1;
    uint16_t window_size, checksum, urg_ptr;
};

template<class T, option_kind init>
struct tcp_option
{
    option_kind kind {init};
    uint8_t length {sizeof(*this)};
    T data;
} __attribute__((packed));

template<option_kind init>
struct tcp_option<void, init>
{
    option_kind kind {init};
    uint8_t length {sizeof(*this)};
} __attribute__((packed));

struct timestamp
{
    uint32_t t1, t2;
};

using mss = tcp_option<uint16_t, option_kind::MSS>;
using win_scale = tcp_option<uint8_t, option_kind::WIN_SCALE>;
using sack = tcp_option<void, option_kind::SACK>;
using timestamps = tcp_option<timestamp, option_kind::TIMESTAMPS>;
using nop = uint8_t;
using eol = uint8_t;

class ipv4_address
{
public:
    ipv4_address() = default;
    ipv4_address(const std::string &address)
        : address_(address){}

    uint32_t get_value() const
    {
        std::array<unsigned short, 4> octets;
        unsigned i = 0;
        for (unsigned j = 0; j < octets.size(); j++)
            octets[j] = extract_number(i);

        return ((octets[0] << 24) | (octets[1] << 16) | (octets[2] << 8) | octets[3]);
    }

private:

    unsigned extract_number(unsigned &i) const
    {
        unsigned acc = 0;
        while (i < address_.size() && address_[i] != '.')
        {
            acc = acc*10 + ((unsigned)(address_[i]) - 48);
            i++;
        }
        i++;
        return acc;
    }

    std::string address_;
};


struct triggers
{
    bool listen;
    union
    {
        bool connect;
        bool close;
    };
};

class tcp_manager
{
public:
    tcp_manager(unsigned reserved_sockets_number)
    {
        assert(reserved_sockets_number < 100000000);
        current_states.assign(reserved_sockets_number, state::CLOSED);
        seq_numbers_cached.assign(reserved_sockets_number, 0);
        srand(time(NULL));
    }

    state get_state() const
    {
        return current_states[id];
    }

    void set_socket(unsigned socket)
    {
        id = socket;
    }

    boost::optional<packet> handle_state(const triggers &initial_triggers,
                                       const boost::optional<packet> &recv_segment)
    {
        if (current_states[id] == state::CLOSED)
        {
            if (initial_triggers.listen)
                current_states[id] = state::LISTEN;
            else
                if (initial_triggers.connect)
                {
                    // SYN(x) + send
                    current_states[id] = state::SYN_SENT;
                    uint32_t seq_number = rand() % UINT32_MAX;
                    seq_numbers_cached[id] = seq_number;
                    return make_three_way_handshake_segment(true, false, seq_number, boost::none);
                }
            return boost::none;
        }
        else
        if (current_states[id] == state::LISTEN)
        {
            // wait for SYN(x) + recv
            if (recv_segment != boost::none)
            {
                if (recv_segment->syn & 1) //OK?
                {
                    current_states[id] = state::SYN_RCVD;
                    seq_numbers_cached[id] = recv_segment->seq_number;
                    uint32_t seq_number = rand() % UINT32_MAX;
                    uint32_t ack_number = seq_numbers_cached[id] + 1;
                    return make_three_way_handshake_segment(true, true, seq_number, ack_number);
                }
            }
            return boost::none;
        }
        else
        if (current_states[id] == state::SYN_SENT)
        {
            // wait for SYN+ACK
            if (recv_segment != boost::none)
            {
                if ((recv_segment->syn & 1) && (recv_segment->ack & 1))
                {
                    current_states[id] = state::ESTABLISHED;
                    uint32_t seq_number = recv_segment->ack_number;
                    uint32_t ack_number = recv_segment->seq_number + 1;
                    return make_three_way_handshake_segment(false, true, seq_number, ack_number);
                }
                else
                if (recv_segment->syn & 1)
                {
                    current_states[id] = state::SYN_RCVD;
                    uint32_t seq_number = seq_numbers_cached[id];
                    uint32_t ack_number = recv_segment->seq_number + 1;
                    return make_three_way_handshake_segment(true, true, seq_number, ack_number);
                }
            }
            return boost::none;
        }
        else
        if (current_states[id] == state::SYN_RCVD)
        {
            // wait for ACK
            if (recv_segment != boost::none)
            {
                if (recv_segment->ack & 1)
                {
                    current_states[id] = state::ESTABLISHED;
                    return boost::none;
                }
            }
            return boost::none;
        }
        else
        if (current_states[id] == state::ESTABLISHED)
        {
            if (initial_triggers.close)
            {
                current_states[id] = state::FIN_WAIT1;
                return make_four_way_handshake_segment(true, false);
            }
            else
                if (recv_segment != boost::none)
                {
                    if (recv_segment->fin & 1)
                    {
                        current_states[id] = state::CLOSE_WAIT;
                        return make_four_way_handshake_segment(false, true);
                    }
                }
            return boost::none;
        }
        else
        if (current_states[id] == state::FIN_WAIT1)
        {
            if (recv_segment != boost::none)
            {
                if (recv_segment->ack & 1)
                {
                    current_states[id] = state::FIN_WAIT2;
                    return boost::none;
                }
            }
            return boost::none;
        }
        else
        if (current_states[id] == state::FIN_WAIT2)
        {
            if (recv_segment != boost::none)
            {
                if (recv_segment->fin & 1)
                {
                    current_states[id] = state::TIMED_WAIT;
                    return make_four_way_handshake_segment(false, true);
                }
            }
            return boost::none;
        }
        else
        if (current_states[id] == state::CLOSE_WAIT)
        {
            if (initial_triggers.close)
            {
                current_states[id] = state::LAST_ACK;
                return make_four_way_handshake_segment(true, false);
            }
            return boost::none;
        }
        else
        if (current_states[id] == state::LAST_ACK)
        {
            if (recv_segment != boost::none)
            {
                if (recv_segment->ack & 1)
                {
                    current_states[id] = state::CLOSED;
                    return boost::none;
                }
            }
            return boost::none;
        }
        else
        if (current_states[id] == state::TIMED_WAIT)
        {
            current_states[id] = state::CLOSED;
            return boost::none;
        }
        else
        return boost::none;
    }

    static packet make_three_way_handshake_segment(bool syn, bool ack,
                                                   boost::optional<uint32_t> seq_number,
                                                   boost::optional<uint32_t> ack_number)
    {
        packet temp_segment;
        temp_segment.syn = static_cast<uint8_t>(syn);
        temp_segment.ack = static_cast<uint8_t>(ack);
        if (seq_number)
            temp_segment.seq_number = *seq_number;
        if (ack_number)
            temp_segment.ack_number = *ack_number;
        return temp_segment;
    }

    static packet make_four_way_handshake_segment(bool fin, bool ack)
    {
        packet temp_segment;
        temp_segment.fin = static_cast<uint8_t>(fin);
        temp_segment.ack = static_cast<uint8_t>(ack);
        return temp_segment;
    }

private:

    unsigned id {0};
    std::vector<state> current_states;
    std::vector<uint32_t> seq_numbers_cached;
};

}

namespace unit_tests
{

static void preliminaries()
{
    static_assert(sizeof(tcp::packet) == 20, "WTF: should be 20");

    static_assert(static_cast<int>(tcp::state::CLOSED) == 0, "WTF: should be 0");
    static_assert(static_cast<int>(tcp::state::LISTEN) == 1, "WTF: should be 1");
    static_assert(static_cast<int>(tcp::state::SYN_RCVD) == 2, "WTF: should be 2");
    static_assert(static_cast<int>(tcp::state::SYN_SENT) == 3, "WTF: should be 3");
    static_assert(static_cast<int>(tcp::state::ESTABLISHED) == 4, "WTF: should be 4");
    static_assert(static_cast<int>(tcp::state::FIN_WAIT1) == 5, "WTF: should be 5");
    static_assert(static_cast<int>(tcp::state::FIN_WAIT2) == 6, "WTF: should be 6");
    static_assert(static_cast<int>(tcp::state::TIMED_WAIT) == 7, "WTF: should be 7");
    static_assert(static_cast<int>(tcp::state::CLOSING) == 8, "WTF: should be 8");
    static_assert(static_cast<int>(tcp::state::CLOSE_WAIT) == 9, "WTF: should be 9");
    static_assert(static_cast<int>(tcp::state::LAST_ACK) == 10, "WTF: should be 10");

    static_assert(sizeof(tcp::mss) == 4, "WTF: should be 4");
    tcp::mss mss;
    assert(mss.kind == tcp::option_kind::MSS && mss.length == 4);

    static_assert(sizeof(tcp::win_scale) == 3, "WTF: should be 3");
    tcp::win_scale win_scale;
    assert(win_scale.kind == tcp::option_kind::WIN_SCALE && win_scale.length == 3);

    static_assert(sizeof(tcp::sack) == 2, "WTF: should be 2");
    tcp::sack sack;
    assert(sack.kind == tcp::option_kind::SACK && sack.length == 2);

    static_assert(sizeof(tcp::timestamps) == 10, "WTF: should be 10");
    tcp::timestamps timestamps;
    assert(timestamps.kind == tcp::option_kind::TIMESTAMPS && timestamps.length == 10);

    static_assert(sizeof(tcp::nop) == 1, "WTF: should be 1");
    static_assert(sizeof(tcp::eol) == 1, "WTF: should be 1");

    tcp::ipv4_address ip1{"192.168.0.101"};
    assert(ip1.get_value() == ((192U << 24) | (168 << 16) | (0 << 8) | 101));
    tcp::ipv4_address ip2{"192.168.0.102"};
    assert(ip2.get_value() == ((192U << 24) | (168 << 16) | (0 << 8) | 102));
    tcp::ipv4_address ip3{"127.0.0.1"};
    assert(ip3.get_value() == ((127U << 24) | (0 << 16) | (0 << 8) | 1));
    tcp::ipv4_address ip4{"0.0.0.0"};
    assert(ip4.get_value() == ((0U << 24) | (0 << 16) | (0 << 8) | 0));
    tcp::ipv4_address ip5{"255.255.255.255"};
    assert(ip5.get_value() == ((255U << 24) | (255 << 16) | (255 << 8) | 255));


    std::cout << "OK. " << __PRETTY_FUNCTION__ << " passed.\n";
}

static void make_three_way_handshake_segment()
{
    auto segment = tcp::tcp_manager::make_three_way_handshake_segment(false, false, boost::none, boost::none);
    assert((segment.syn & 1) == 0 && (segment.ack & 1) == 0);

    segment = tcp::tcp_manager::make_three_way_handshake_segment(true, true, boost::none, boost::none);
    assert((segment.syn & 1) == 1 && (segment.ack & 1) == 1);

    segment = tcp::tcp_manager::make_three_way_handshake_segment(true, true, 123, 321);
    assert((segment.syn & 1) == 1 && (segment.ack & 1) == 1);
    assert(segment.seq_number == 123 && segment.ack_number == 321);

    std::cout << "OK. " << __PRETTY_FUNCTION__ << " passed.\n";
}

using managers = std::tuple<tcp::tcp_manager, tcp::tcp_manager>;

static managers trigger_three_way_handshake__ok_scenario1()
{
    tcp::tcp_manager server_manager(1), client_manager(1);
    server_manager.set_socket(0);
    client_manager.set_socket(0);
    assert(server_manager.get_state() == tcp::state::CLOSED);
    assert(client_manager.get_state() == tcp::state::CLOSED);

    auto segment = server_manager.handle_state({true, false}, boost::none);
    assert(server_manager.get_state() == tcp::state::LISTEN);
    assert(segment == boost::none);

    segment = client_manager.handle_state({false, true}, boost::none);
    assert(client_manager.get_state() == tcp::state::SYN_SENT);
    assert((segment->syn & 1) == 1 && (segment->ack & 1) == 0);

    segment = server_manager.handle_state({}, segment);
    assert(server_manager.get_state() == tcp::state::SYN_RCVD);
    assert((segment->syn & 1) == 1 && (segment->ack & 1) == 1);

    segment = client_manager.handle_state({}, segment);
    assert(client_manager.get_state() == tcp::state::ESTABLISHED);
    assert((segment->syn & 1) == 0 && (segment->ack & 1) == 1);

    segment = server_manager.handle_state({}, segment);
    assert(server_manager.get_state() == tcp::state::ESTABLISHED);
    assert(segment == boost::none);
    return {server_manager, client_manager};
}

static managers trigger_three_way_handshake__ok_scenario2()
{
    tcp::tcp_manager manager1(1), manager2(1);
    manager1.set_socket(0);
    manager2.set_socket(0);
    assert(manager1.get_state() == tcp::state::CLOSED);
    assert(manager2.get_state() == tcp::state::CLOSED);

    // SYN(x)
    auto segment = manager1.handle_state({false, true}, boost::none);
    assert(manager1.get_state() == tcp::state::SYN_SENT);
    assert((segment->syn & 1) == 1 && (segment->ack & 1) == 0);

    auto syn_segment1 = segment;

    // SYN(y)
    segment = manager2.handle_state({false, true}, boost::none);
    assert(manager2.get_state() == tcp::state::SYN_SENT);
    assert((segment->syn & 1) == 1 && (segment->ack & 1) == 0);

    // send SYN+ACK(y,x+1) to manager2
    segment = manager1.handle_state({}, segment);
    assert(manager1.get_state() == tcp::state::SYN_RCVD);
    assert((segment->syn & 1) == 1 && (segment->ack & 1) == 1);

    auto syn_ack_segment1 = segment;

    // send SYN+ACK(y,x+1) to manager1
    segment = manager2.handle_state({}, syn_segment1);
    assert(manager2.get_state() == tcp::state::SYN_RCVD);
    assert((segment->syn & 1) == 1 && (segment->ack & 1) == 1);

    // recv SYN+ACK(y,x+1)
    segment = manager1.handle_state({}, segment);
    assert(manager1.get_state() == tcp::state::ESTABLISHED);
    assert(segment == boost::none);

    // recv SYN+ACK(y,x+1)
    segment = manager2.handle_state({}, syn_ack_segment1);
    assert(manager2.get_state() == tcp::state::ESTABLISHED);
    assert(segment == boost::none);

    return {manager1, manager2};
}

static void three_way_handshake__ok_scenario1()
{
    trigger_three_way_handshake__ok_scenario1();
    std::cout << "OK. " << __PRETTY_FUNCTION__ << " passed.\n";
}

static void three_way_handshake__ok_scenario2()
{
    trigger_three_way_handshake__ok_scenario2();
    std::cout << "OK. " << __PRETTY_FUNCTION__ << " passed.\n";
}

static void three_way_handshake__nok_scenario()
{

}

static void four_way_handshake__ok_scenario()
{
    auto established_managers = trigger_three_way_handshake__ok_scenario1();
    auto manager1 = std::get<0>(established_managers);
    auto manager2 = std::get<0>(established_managers);

    assert(manager1.get_state() == tcp::state::ESTABLISHED);
    assert(manager2.get_state() == tcp::state::ESTABLISHED);

    // send FIN
    auto segment = manager1.handle_state({false, true}, boost::none);
    assert(manager1.get_state() == tcp::state::FIN_WAIT1);
    assert((segment->fin & 1) == 1);

    // recv FIN, send ACK
    segment = manager2.handle_state({}, segment);
    assert(manager2.get_state() == tcp::state::CLOSE_WAIT);
    assert((segment->ack & 1) == 1);

    // recv ACK
    segment = manager1.handle_state({}, segment);
    assert(manager1.get_state() == tcp::state::FIN_WAIT2);
    assert(segment == boost::none);

    // send FIN
    segment = manager2.handle_state({false, true}, boost::none);
    assert(manager2.get_state() == tcp::state::LAST_ACK);
    assert((segment->fin & 1) == 1);

    // recv FIN, send ACK
    segment = manager1.handle_state({}, segment);
    assert(manager1.get_state() == tcp::state::TIMED_WAIT);
    assert((segment->ack & 1) == 1);

    // recv ACK
    segment = manager2.handle_state({}, segment);
    assert(manager2.get_state() == tcp::state::CLOSED);
    assert(segment == boost::none);

    segment = manager1.handle_state({}, boost::none);
    assert(manager1.get_state() == tcp::state::CLOSED);
    assert(segment == boost::none);
    std::cout << "OK. " << __PRETTY_FUNCTION__ << " passed.\n";
}

static void three_way_handshake__ok_scenario_benchmark()
{
    // ~90 CPU cycles per handshake
    constexpr unsigned n = 10000000;
    tcp::tcp_manager server_manager(n), client_manager(n);

    for (unsigned socket = 0; socket < n; socket++)
    {
        server_manager.set_socket(socket);
        client_manager.set_socket(socket);

        auto segment = server_manager.handle_state({true, false}, boost::none);
        segment = client_manager.handle_state({false, true}, boost::none);
        segment = server_manager.handle_state({}, segment);
        segment = client_manager.handle_state({}, segment);
        segment = server_manager.handle_state({}, segment);
        assert(server_manager.get_state() == tcp::state::ESTABLISHED &&
               client_manager.get_state() == tcp::state::ESTABLISHED &&
               segment == boost::none);
    }

    std::cout << "OK. " << __PRETTY_FUNCTION__ << " passed.\n";
}

}


namespace posix_transport
{

// TO DO1: prefer exceptions then error codes here
// TO DO2: Zero copy + move semantics
// TO DO3: In fill_tcp_header I need options for mss

using mac = std::array<unsigned char, ETH_ALEN>;
using endpoint = std::tuple<mac, tcp::ipv4_address, uint16_t>;

class ip_manager
{
public:

    constexpr static unsigned max_packet_size = 128;
    using raw_packet = std::array<unsigned char, max_packet_size>;

    ip_manager()
    {
        srand(time(nullptr));
    }

    void send_packet(tcp::packet &packet, const endpoint &src_endpoint, const endpoint &dst_endpoint)
    {
        source_mac = std::get<0>(src_endpoint);
        source_ip = std::get<1>(src_endpoint);
        source_port = std::get<2>(src_endpoint);

        destination_mac = std::get<0>(dst_endpoint);
        destination_ip = std::get<1>(dst_endpoint);
        destination_port = std::get<2>(dst_endpoint);
        send_full_segment();
        flush();
    }

    raw_packet get_packet()
    {
        return packet;
    }

    void recv_packet(const endpoint &src_endpoint)
    {
        (void)src_endpoint;
        recv_full_segment();
    }

    tcp::packet recv_tcp_packet(const endpoint &src_endpoint)
    {
        (void)src_endpoint;
        recv_full_segment();
        tcp::packet tcp_packet;
        memcpy(&tcp_packet, get_tcp_header(), sizeof tcp_packet);
        return tcp_packet;
    }

    tcp::packet *get_tcp_header()
    {
        // should be OK when network order = BE. Check what about strict aliasing here.
        return (tcp::packet*) (packet.data() + sizeof(iphdr)
                                                  + sizeof(ether_header));
    }


private:
    tcp::ipv4_address source_ip, destination_ip;
    uint16_t source_port, destination_port;
    raw_packet packet;

    mac source_mac, destination_mac;
    std::array<unsigned char, 4>  payload {'D', 'u', 'p', 'a'};
    constexpr static int interface_index = 2; // eth0 index

    void flush()
    {
        packet = {};
    }

    void fill_ethernet_header(unsigned char *dest_mac,
                                     unsigned char *src_mac)
    {
        ether_header *ethernet_header = (ether_header *) packet.data();
        ethernet_header->ether_type = htons(ETH_P_IP);
        memcpy(ethernet_header->ether_shost, (uint8_t *)src_mac, ETH_ALEN);
        memcpy(ethernet_header->ether_dhost, (uint8_t *)dest_mac, ETH_ALEN);
    }

    void fill_ip_header__for_tcp(unsigned size)
    {
        iphdr *ip_header = (iphdr *) (packet.data() + sizeof(ether_header));
        unsigned payload_size = size - sizeof(ether_header) - sizeof(iphdr)
                - sizeof(tcphdr);
        ip_header->daddr = htonl(destination_ip.get_value());
        ip_header->frag_off = 0;
        ip_header->check = 0; //0x67f9; // should I compute checksum or linux will do this?
        ip_header->protocol = IPPROTO_TCP;
        ip_header->saddr = htonl(source_ip.get_value());
        ip_header->ttl = 64;
        ip_header->tot_len = htons(payload_size + sizeof(iphdr) + sizeof(tcphdr));
        ip_header->id = 12345;
        ip_header->ihl = 5; //Minmal size is 5. IP header has options too, so this field is needed !
        ip_header->tos = 0;
        ip_header->version = 4; //ipv4
    }

    void fill_tcp_header()
    {
        tcphdr *tcp_header = (tcphdr *)((unsigned char *)packet.data()
                                                      + sizeof(ether_header)
                                                      + sizeof(iphdr));
        tcp_header->source = htons(source_port);
        tcp_header->dest = htons(destination_port);
        tcp_header->seq = htonl(12345);
        //tcp_header->ack_seq = 0;
        tcp_header->syn = 1;
        tcp_header->urg = 0;
        tcp_header->doff = 5;
    }

    void fill_payload(unsigned char payload[4])
    {
        unsigned char *payload_ptr = ((unsigned char *)packet.data()
                                                      + sizeof(ether_header)
                                                      + sizeof(iphdr)
                                                      + sizeof(tcphdr));
        memcpy(payload_ptr, payload, 4);
    }

    void make_segment(int packet_size)
    {
        memset(packet.data(), 0, max_packet_size);

        fill_ethernet_header(destination_mac.data(), source_mac.data());
        fill_ip_header__for_tcp(packet_size);
        fill_tcp_header();
        fill_payload(payload.data());
    }

    void send_full_segment()
    {
        sockaddr_ll dest_address;
        dest_address.sll_ifindex = interface_index;
        dest_address.sll_halen = ETH_ALEN;
        memcpy(dest_address.sll_addr, destination_mac.data(), ETH_ALEN);

        int packet_size = 64;
        make_segment(packet_size);

        int sockfd = socket(AF_PACKET, SOCK_RAW, IPPROTO_RAW);
        assert(sockfd > 2);

        int result = sendto(sockfd, packet.data(), packet_size, 0, (sockaddr*)&dest_address,
                   sizeof(sockaddr_ll));
        assert(result == packet_size);
    }

    void recv_full_segment()
    {
        constexpr uint16_t ETHER_TYPE = 0x0800;
        int sockfd = socket(AF_PACKET, SOCK_RAW, htons(ETHER_TYPE));
        assert(sockfd > 2);

        int rc = setsockopt(sockfd, SOL_SOCKET, SO_BINDTODEVICE, "eth0", IFNAMSIZ-1);
        assert(rc >= 0);

        unsigned frames_counter = 0;
        tcphdr *tcp_header = NULL;
        while (!(tcp_header && tcp_header->source == tcp_header->dest &&
                tcp_header->source == htons(1024)))
        {
            int numbytes = recvfrom(sockfd, packet.data(), max_packet_size, 0, 0, 0);
            assert(numbytes > 0);
            frames_counter++;

            if ((unsigned)numbytes >= sizeof(iphdr) + sizeof(ether_header))
            {
                tcp_header = (tcphdr *) (packet.data() + sizeof(iphdr)
                                                         + sizeof(ether_header));
            }
        }
        close(sockfd);
        std::cout << __FUNCTION__ <<":  recieved " << frames_counter << " frames in total\n";
    }

};

}

namespace posix_transport_tests
{

// TO DO: Disabled tcp_header->syn checking.
//        Fix problem with tcp_header->syn (tcp::packet vs tcphdr)!
static void basic_network_connection_test(char is_sender)
{
    posix_transport::ip_manager ip_manager;
    const posix_transport::mac dest_mac = {0x00, 0x1a, 0xa0, 0xb9, 0xd7, 0xad}; //eth0
    const posix_transport::mac src_mac = {0x9c, 0xb6, 0x54, 0xa3, 0xd4, 0xc6}; //enp0s25
    const tcp::ipv4_address dest_ip{"10.0.0.10"};
    const tcp::ipv4_address src_ip{"10.0.0.20"};
    constexpr uint16_t port = 1024;
    const posix_transport::endpoint src_endpoint = {src_mac, src_ip, port};
    const posix_transport::endpoint dst_endpoint = {dest_mac, dest_ip, port};
    tcp::packet* tcp_header = nullptr;

    // in this moment segments are hardcoded
    tcp::packet segment;

    if (is_sender == 'S')
        ip_manager.send_packet(segment, src_endpoint, dst_endpoint);
    else
        ip_manager.recv_packet(dst_endpoint);

    tcp_header = ip_manager.get_tcp_header();
    assert(tcp_header->src_port == tcp_header->dst_port);
    assert(tcp_header->src_port == htons(port));
    // implicit (hardcoded in send)
    assert(tcp_header->seq_number == htonl(12345));
    //assert((tcp_header->syn & 1) == 1);
    assert((tcp_header->ack & 1) == 0);
    std::cout << "OK. " << __PRETTY_FUNCTION__ << " passed.\n";
}

static void trigger_three_way_handshake__ok_scenario1__posix_backend(bool server_side)
{
    posix_transport::ip_manager ip_manager;
    const posix_transport::mac server_mac = {0x00, 0x1a, 0xa0, 0xb9, 0xd7, 0xad}; //eth0
    const posix_transport::mac client_mac = {0x9c, 0xb6, 0x54, 0xa3, 0xd4, 0xc6}; //enp0s25
    const tcp::ipv4_address server_ip{"10.0.0.10"};
    const tcp::ipv4_address client_ip{"10.0.0.20"};
    constexpr uint16_t port = 1024;
    const posix_transport::endpoint client_endpoint = {client_mac, client_ip, port};
    const posix_transport::endpoint server_endpoint = {server_mac, server_ip, port};

    // optiplex
    if (server_side)
    {
        tcp::tcp_manager server_manager(1);

        server_manager.set_socket(0);
        assert(server_manager.get_state() == tcp::state::CLOSED);

        auto segment = server_manager.handle_state({true, false}, boost::none);
        assert(server_manager.get_state() == tcp::state::LISTEN);
        assert(segment == boost::none);

        segment = ip_manager.recv_tcp_packet(client_endpoint);
        assert((segment->syn & 1) == 1 && (segment->ack & 1) == 0);

        segment = server_manager.handle_state({}, segment);
        assert(server_manager.get_state() == tcp::state::SYN_RCVD);
        assert((segment->syn & 1) == 1 && (segment->ack & 1) == 1);

        ip_manager.send_packet(*segment, server_endpoint, client_endpoint);
        segment = ip_manager.recv_tcp_packet(client_endpoint);
        assert((segment->syn & 1) == 0 && (segment->ack & 1) == 1);

        segment = server_manager.handle_state({}, segment);
        assert(server_manager.get_state() == tcp::state::ESTABLISHED);
        assert(segment == boost::none);
    }
    else
    {
        tcp::tcp_manager client_manager(1);

        client_manager.set_socket(0);
        assert(client_manager.get_state() == tcp::state::CLOSED);

        auto segment = client_manager.handle_state({false, true}, boost::none);
        assert(client_manager.get_state() == tcp::state::SYN_SENT);
        assert((segment->syn & 1) == 1 && (segment->ack & 1) == 0);

        ip_manager.send_packet(*segment, client_endpoint, server_endpoint);
        segment = ip_manager.recv_tcp_packet(server_endpoint);
        assert((segment->syn & 1) == 1 && (segment->ack & 1) == 1);

        segment = client_manager.handle_state({}, segment);
        assert(client_manager.get_state() == tcp::state::ESTABLISHED);
        assert((segment->syn & 1) == 0 && (segment->ack & 1) == 1);

        ip_manager.send_packet(*segment, client_endpoint, server_endpoint);
    }
    std::cout << "OK. " << __PRETTY_FUNCTION__ << " passed.\n";
}

}

class network_manager
{
public:
    network_manager(std::unique_ptr<posix_transport::ip_manager> ip_manager_,
                    std::unique_ptr<tcp::tcp_manager> tcp_manager_)
        : ip_manager(std::move(ip_manager_)), tcp_manager(std::move(tcp_manager_)) {}

    template<class Buffer>
    unsigned send_data(unsigned bytes, const Buffer &buffer)
    {
        try
        {

        }
        catch (...)
        {

        }
        return bytes;
    }
    template<class Buffer>
    unsigned recv_data(const Buffer &buffer, unsigned max_size)
    {
        try
        {

        }
        catch (...)
        {

        }
        return max_size;
    }
private:
    std::unique_ptr<posix_transport::ip_manager> ip_manager {nullptr};
    std::unique_ptr<tcp::tcp_manager> tcp_manager {nullptr};
};


int main(int argc, char **argv)
{
    unit_tests::preliminaries();
    unit_tests::make_three_way_handshake_segment();
    unit_tests::three_way_handshake__ok_scenario1();
    unit_tests::three_way_handshake__ok_scenario2();
    unit_tests::three_way_handshake__nok_scenario();
    unit_tests::four_way_handshake__ok_scenario();

    assert(argc == 2 && (argv[1][0] == 'S' || argv[1][0] == 'L'));
    bool server_side = (argv[1][0] == 'S');
    posix_transport_tests::basic_network_connection_test(argv[1][0]);
    posix_transport_tests::trigger_three_way_handshake__ok_scenario1__posix_backend(server_side);

    return 0;
}
