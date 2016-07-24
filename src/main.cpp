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
    uint8_t reserved : 3;
    uint8_t ns : 1;
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
    ipv4_address(const std::string &address)
        : address_(address){}
private:
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

int main()
{
    unit_tests::preliminaries();
    unit_tests::make_three_way_handshake_segment();
    unit_tests::three_way_handshake__ok_scenario1();
    unit_tests::three_way_handshake__ok_scenario2();
    unit_tests::three_way_handshake__nok_scenario();
    unit_tests::four_way_handshake__ok_scenario();
    unit_tests::three_way_handshake__ok_scenario_benchmark();
    return 0;
}
