#include <iostream>
#include <memory>
#include <vector>
#include <array>
#include <cassert>
#include <cstdlib>
#include <ctime>
#include <boost/program_options.hpp>
#include <experimental/optional>

using namespace std::experimental;

// TO DO1: http://www.firewall.cx/networking-topics/protocols/tcp/138-tcp-options.html
// attribute packed in [] ?, likely/unlikely
// what for derivation like enum class tcp_state : uint16_t {} ?

// TO DO2: OK Scenario 2

// TO DO3: move semantics for make_handshake_segment?

namespace tcp
{

enum class state
{
    CLOSED, LISTEN, SYN_RCVD, SYN_SENT, ESTABLISHED,
    FIN_WAIT1, FIN_WAIT2, TIMED_WAIT, CLOSING, CLOSE_WAIT, LAST_ACK
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
    //std::array<uint8_t, tcp_payload_size> payload;
};

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
    bool connect;
};

namespace dummy
{

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

    optional<packet> handle_state(const triggers &initial_triggers,
                                       const optional<packet> &recv_segment)
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
                    return make_handshake_segment(true, false, seq_number, nullopt);
                }
            return nullopt;
        }
        if (current_states[id] == state::LISTEN)
        {
            // wait for SYN(x) + recv
            if (recv_segment != nullopt)
            {
                if (recv_segment->syn & 1) //OK?
                {
                    current_states[id] = state::SYN_RCVD;
                    seq_numbers_cached[id] = recv_segment->seq_number;
                    uint32_t seq_number = rand() % UINT32_MAX;
                    uint32_t ack_number = seq_numbers_cached[id] + 1;
                    return make_handshake_segment(true, true, seq_number, ack_number);
                }
            }
            return nullopt;
        }
        if (current_states[id] == state::SYN_SENT)
        {
            // wait for SYN+ACK
            if (recv_segment != nullopt)
            {
                if ((recv_segment->syn & 1) && (recv_segment->ack & 1)) //OK?
                {
                    current_states[id] = state::ESTABLISHED;
                    uint32_t seq_number = recv_segment->ack;
                    uint32_t ack_number = recv_segment->seq_number + 1;
                    return make_handshake_segment(false, true, seq_number, ack_number);
                }
            }
            return nullopt;
        }
        if (current_states[id] == state::SYN_RCVD)
        {
            // wait for ACK
            if (recv_segment != nullopt)
            {
                if (recv_segment->ack & 1) //OK?
                {
                    current_states[id] = state::ESTABLISHED;
                    return nullopt;
                }
            }
            return nullopt;
        }
        return nullopt;
    }

    static packet make_handshake_segment(bool syn, bool ack, optional<uint32_t> seq_number,
                                         optional<uint32_t> ack_number)
    {
        packet temp_segment;
        temp_segment.syn = static_cast<uint8_t>(syn);
        temp_segment.ack = static_cast<uint8_t>(ack);
        if (seq_number)
            temp_segment.seq_number = *seq_number;
        if (seq_number)
            temp_segment.ack_number = *ack_number;
        return temp_segment;
    }

private:

    unsigned id {0};
    std::vector<state> current_states;
    std::vector<uint32_t> seq_numbers_cached;
};

}

class tcp_manager
{
public:
    tcp_manager(unsigned reserved_sockets_number)
    {
        assert(reserved_sockets_number < 100000000);
        valid_segment->syn = 0;
        valid_segment->ack = 0;
        valid_segment->seq_number = 0;
        valid_segment->ack_number = 0;
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

    const optional<packet> &handle_state(const triggers &initial_triggers,
                                       const optional<packet> &recv_segment)
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
                    make_handshake_segment_fw(true, false, seq_number, nullopt);
                    return valid_segment;
                }
            return empty_segment;
        }
        else
        if (current_states[id] == state::LISTEN)
        {
            // wait for SYN(x) + recv
            if (recv_segment != nullopt)
            {
                if (recv_segment->syn & 1) //OK?
                {
                    current_states[id] = state::SYN_RCVD;
                    seq_numbers_cached[id] = recv_segment->seq_number;
                    uint32_t seq_number = rand() % UINT32_MAX;
                    uint32_t ack_number = seq_numbers_cached[id] + 1;
                    make_handshake_segment_fw(true, true, seq_number, ack_number);
                    return valid_segment;
                }
            }
            return empty_segment;
        }
        else
        if (current_states[id] == state::SYN_SENT)
        {
            // wait for SYN+ACK
            if (recv_segment != nullopt)
            {
                if ((recv_segment->syn & 1) && (recv_segment->ack & 1)) //OK?
                {
                    current_states[id] = state::ESTABLISHED;
                    uint32_t seq_number = recv_segment->ack;
                    uint32_t ack_number = recv_segment->seq_number + 1;
                    make_handshake_segment_fw(false, true, seq_number, ack_number);
                    return valid_segment;
                }
            }
            return empty_segment;
        }
        else
        if (current_states[id] == state::SYN_RCVD)
        {
            // wait for ACK
            if (recv_segment != nullopt)
            {
                if (recv_segment->ack & 1) //OK?
                {
                    current_states[id] = state::ESTABLISHED;
                    return empty_segment;
                }
            }
            return empty_segment;
        }
        else
        return empty_segment;
    }

    static packet make_handshake_segment(bool syn, bool ack, optional<uint32_t> seq_number,
                                         optional<uint32_t> ack_number)
    {
        packet temp_segment;
        temp_segment.syn = static_cast<uint8_t>(syn);
        temp_segment.ack = static_cast<uint8_t>(ack);
        if (seq_number)
            temp_segment.seq_number = *seq_number;
        if (seq_number)
            temp_segment.ack_number = *ack_number;
        return temp_segment;
    }

    void make_handshake_segment_fw(bool syn, bool ack, optional<uint32_t> seq_number,
                                         optional<uint32_t> ack_number)
    {
        valid_segment->syn = static_cast<uint8_t>(syn);
        valid_segment->ack = static_cast<uint8_t>(ack);
        if (seq_number)
            valid_segment->seq_number = *seq_number;
        if (seq_number)
            valid_segment->ack_number = *ack_number;
    }

    //static std::array<state, 2> next_state;

private:

    unsigned id {0};
    optional<packet> valid_segment;
    const optional<packet> empty_segment {nullopt};
    std::vector<state> current_states;
    std::vector<uint32_t> seq_numbers_cached;
};

//std::array<state, 2> tcp_manager::next_state = {state::CLOSED, state::CLOSED};

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

    //tcp::state some_state = tcp::state::CLOSED;
    //tcp::state another_state = tcp::tcp_manager::next_state[static_cast<int>(some_state)];
    std::cout << "OK. " << __PRETTY_FUNCTION__ << " passed.\n";
}

static void make_handshake_segment()
{
    auto segment = tcp::tcp_manager::make_handshake_segment(false, false, nullopt, nullopt);
    assert((segment.syn & 1) == 0 && (segment.ack & 1) == 0);

    segment = tcp::tcp_manager::make_handshake_segment(true, true, nullopt, nullopt);
    assert((segment.syn & 1) == 1 && (segment.ack & 1) == 1);

    segment = tcp::tcp_manager::make_handshake_segment(true, true, 123, 321);
    assert((segment.syn & 1) == 1 && (segment.ack & 1) == 1);
    assert(segment.seq_number == 123 && segment.ack_number == 321);

    std::cout << "OK. " << __PRETTY_FUNCTION__ << " passed.\n";
}


// TO DO: WTF here? Copying is broken? But it works when not optional!

struct dummy_packet
{
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

optional<dummy_packet> valid_segment;

optional<dummy_packet> &make_optional()
{
    valid_segment->syn = static_cast<uint8_t>(true);
    valid_segment->ack = static_cast<uint8_t>(false);
    assert((valid_segment->ack & 1) == 0);
    return valid_segment;
}

static void optional_testcase()
{
    static_assert(sizeof(dummy_packet) == 16, "WTF: should be 16");
    auto segment2 = make_optional();
    assert((segment2->ack & 1) == 0); // WTF??
}

static void three_way_handshake__ok_scenario1()
{
    optional_testcase();

    tcp::tcp_manager server_manager(1), client_manager(1);
    server_manager.set_socket(0);
    client_manager.set_socket(0);
    assert(server_manager.get_state() == tcp::state::CLOSED);
    assert(client_manager.get_state() == tcp::state::CLOSED);

    auto segment = server_manager.handle_state({true, false}, nullopt);
    assert(server_manager.get_state() == tcp::state::LISTEN);
    assert(segment == nullopt);

    auto segment2 = client_manager.handle_state({false, true}, nullopt);
    assert(client_manager.get_state() == tcp::state::SYN_SENT);
    assert((segment2->syn & 1) == 1 && (segment2->ack & 1) == 0);

//    server_manager.handle_state({}, segment_c);
//    assert(server_manager.get_state() == tcp::state::SYN_RCVD);
//    assert((segment_s->syn & 1) == 1 && (segment_s->ack & 1) == 1);

//    segment2 = client_manager.handle_state({}, segment1);
//    assert(client_manager.get_state() == tcp::state::ESTABLISHED);
//    assert((segment2->syn & 1) == 0 && (segment2->ack & 1) == 1);

//    segment1 = server_manager.handle_state({}, segment2);
//    assert(server_manager.get_state() == tcp::state::ESTABLISHED);
//    assert(segment1 == nullopt);

    std::cout << "OK. " << __PRETTY_FUNCTION__ << " passed.\n";
}

static void three_way_handshake__ok_scenario2()
{

}

static void three_way_handshake__nok_scenario()
{

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

        auto segment = server_manager.handle_state({true, false}, nullopt);
        segment = client_manager.handle_state({false, true}, nullopt);
        segment = server_manager.handle_state({}, segment);
        segment = client_manager.handle_state({}, segment);
        segment = server_manager.handle_state({}, segment);
        assert(server_manager.get_state() == tcp::state::ESTABLISHED &&
               client_manager.get_state() == tcp::state::ESTABLISHED &&
               segment == nullopt);
    }

    std::cout << "OK. " << __PRETTY_FUNCTION__ << " passed.\n";
}

}

//namespace tcp_sockets
//{
//class client_socket
//{
//public:
//    client_socket() = default;
//    client_socket(const tcp::ipv4_address &src_address, unsigned src_port) {}
//    void connect(const tcp::ipv4_address &dst_address, unsigned dst_port) {}
//    unsigned send(const std::vector<char> &data, unsigned size) {}
//    unsigned recv(const std::vector<char> &data, unsigned max_size) {}
//};

//class server_socket
//{
//public:
//    server_socket() = default;
//    server_socket(const tcp::ipv4_address &src_address, unsigned src_port) {}
//    void accept() {}
//    unsigned send(const std::vector<char> &data, unsigned size) {}
//    unsigned recv(const std::vector<char> &data, unsigned max_size) {}
//};
//}

//namespace minimal_tcp
//{

//void minimal_tcp_server()
//{
//    const tcp::ipv4_address src_address {"192.168.253.20"};
//    std::vector<char> buffer(6);
//    auto socket = std::make_unique<tcp_sockets::server_socket>(src_address, 5555);
//    socket->accept();
//    socket->recv(buffer, buffer.size());
//    socket->send(buffer, buffer.size());
//}

//void minimal_tcp_client()
//{
//    const tcp::ipv4_address src_address {"192.168.253.28"};
//    const tcp::ipv4_address dst_address {"192.168.253.20"};
//    std::vector<char> buffer = {'S','i','e','m','a'};
//    auto socket = std::make_unique<tcp_sockets::client_socket>(src_address, 12345);
//    socket->connect(dst_address, 5555);
//    unsigned send_bytes = socket->send(buffer, buffer.size());
//    assert(send_bytes > 0);
//    socket->recv(buffer, buffer.size());
//}

//void test_case()
//{

//}

//}

int main()
{
    unit_tests::preliminaries();
    unit_tests::make_handshake_segment();
    unit_tests::three_way_handshake__ok_scenario1();
    //unit_tests::three_way_handshake__ok_scenario_benchmark();
    return 0;
}
