#pragma once

#include "checkin_request.hpp"
#include "log_utils.hpp"
#include "openssl/signature.hpp"
#include "voter_id_request.hpp"
#include "openssl/openssl_exception.hpp"

#include <asio.hpp>
#include <asio/ssl.hpp>
#include <asio/ssl/context.hpp>
#include <iostream>
#include <cstdint>
#include <future>
#include <string>
#include <tuple>

namespace epollbook {

struct CheckinResult {
    bool success;
    std::string failure_reason;
};

enum class ClientType {
    UntrustedClient,
    TrustedClient
};

class PollbookClient {
private:
    /** A pointer to the debug logger */
    std::shared_ptr<spdlog::logger> logger;
    /** The IO Context to use for all network actions */
    asio::io_context network_io_context;
    /** Work guard for the network IO context, to keep its run() thread alive while the client is idle */
    asio::executor_work_guard<asio::io_context::executor_type> network_work_guard;
    /* A variable for ssl context for id server with tls ver 12 */ 
    asio::ssl::context ssl_context_id;
    /* A variable for ssl context for checkin server with tls ver 12 */ 
    asio::ssl::context ssl_context_checkin;
    /** The socket to use to communicate with the check-in server */
    asio::ssl::stream<asio::ip::tcp::socket> checkin_server_socket;
    /** The socket used to communicate with the voter-ID server */
    asio::ssl::stream<asio::ip::tcp::socket> id_server_socket;
    /* asio::ip::tcp::socket id_server_socket; */
    /**
     * True if the client has been connected to a check-in server, false if
     * connect_checkin_server() has not yet been called.
     */
    ClientType client_type;
    bool checkin_connected;
    /**
     * True if the client has been connected to an ID-verification server, false
     * if connect_id_server() has not yet been called.
     */
    bool id_connected;
    /**
     * A byte array that will be allocated to receive a message from the check-in
     * server once a read is initiated. Its size will be determined by the first
     * sizeof(size_t) bytes of the incoming message from the server.
     */
    std::vector<uint8_t> checkin_server_buffer;
    /**
     * A byte array that will be allocated to receive a message from the check-in
     * server once a read is initiated. Its size will be determined by the first
     * sizeof(size_t) bytes of the incoming message from the server.
     */
    std::vector<uint8_t> id_server_buffer;
    /**
     * A Signer object configured with this client's private key, which it will
     * use to sign outgoing messages.
     */
    openssl::Signer private_key_signer;
    /**
     * A Verifier object configured with the public key of the ID-verification
     * service.
     */
    openssl::Verifier id_service_verifier;
    /**
     * A Verifier object configured with the public key of the check-in service.
     */
    openssl::Verifier checkin_service_verifier;
    /**
     * A Promise object for the currently-pending check-in request, if there is
     * one. This is initialized when check_in_voter() is called, and it can be
     * used to notify the caller of check_in_voter() when the check-in request
     * is complete. Only one check-in request can be in progress at any time.
     */
    std::promise<CheckinResult> current_request_promise;
    /**
     * Contains (first name, middle name, last name) of the voter for the
     * currently-pending check-in request, if there is one. This needs to be
     * stored locally while waiting for the ID-verification request to complete,
     * so it can be used to construct the check-in request message.
     */
    std::tuple<std::string, std::string, std::string> current_request_voter_name;
    /** The thread that executes asynchronous network operations */
    std::thread network_thread;

public:
    /**
     * Constructs a new PollbookClient that is not connected to any server.
     */
    PollbookClient();

    ~PollbookClient();
    /**
     * Connects the client to both the checkin server and the ID server, using
     * the addresses and ports configured in the configuration file.
     */
    void connect();
    /**
     * Connects the client to a check-in server, identified by its hostname (which
     * could be just an IP address) and port. This is a blocking, synchronous method.
     */
    void configure_ssl_context(asio::ssl::context& ssl_context, 
                               asio::ssl::stream<asio::ip::tcp::socket>& socket,
                               const std::string& cert_file, 
                               const std::string& key_file, 
                               const std::string& ca_file);
    void connect_checkin_server(const std::string& server_hostname, const std::string& server_port);

    /**
     * Connects the client to a voter-ID-verification server, identified by its
     * hostname and port. This method blocks until the server is connected.
     */
    void connect_id_server(const std::string& server_hostname, const std::string& server_port);
    void make_handshake(const std::string& host, const std::string& port, bool is_id_server);

    /* --- Various asynchronous I/O event handlers for receiving messages from the servers --- */

    void start_message_read(bool on_id_server);

    void handle_id_response(const VerifiedVoterID& response);

    void start_checkin_response_read(std::size_t message_size, std::shared_ptr<asio::streambuf>);

    void handle_checkin_response(const CheckinResponse& response);

    /**
     * Asynchronously sends a voter ID verification request to the ID-verification server.
     * This method returns once the ASIO async_write has been submitted.
     *
     * @param timestamp The "current time" timestamp to use when constructing the message.
     * @param voter_id_data The byte buffer containing the voter ID data to submit.
     */
    void start_id_request_write(std::uint64_t timestamp, const std::vector<std::uint8_t>& voter_id_data);

    /**
     * Asynchronously sends a check-in request to the check-in server for the voter
     * whose ID has been verified in the provided VerifiedVoterID (a response from
     * the ID-verification server).
     *
     * @param verified_id_response
     */
    void start_checkin_request_write(const VerifiedVoterID& verified_id_response);

    /**
     * Version of check_in_voter in which the caller supplies the voter's unique ID,
     * even though the ID-verification service should be matching identification data
     * to voter unique ID numbers. This should be used with the mock-up version of the
     * ID-verification service, which doesn't understand identification data and just
     * echoes back the ID number supplied by the client.
     *
     * @param first_name
     * @param middle_name
     * @param last_name
     * @param desired_voter_unique_id
     * @param voter_id_data
     * @return A future for the CheckinResult object that contains the result of
     * the check-in request. The future will be fulfilled when the check-in
     * service responds to the request.
     */
    std::future<CheckinResult> check_in_voter(const std::string& first_name, const std::string& middle_name,
                                              const std::string& last_name,
                                              std::uint32_t desired_voter_unique_id,
                                              const std::vector<uint8_t>& voter_id_data);

    /**
     * Starts the process of attempting to check in a voter, given the name the
     * voter entered at the client interface and the data blob representing the
     * identification document they presented. This method is non-blocking and
     * returns a future that can be used to wait for the check-in to complete.
     *
     * @param first_name The voter's first name
     * @param middle_name The voter's middle name
     * @param last_name The voter's last name
     * @param voter_id_data A byte array containing a representation of the
     * voter's identification (e.g. an image of a state ID).
     * @return A future for the CheckinResult object that contains the result of
     * the check-in request. The future will be fulfilled when the check-in
     * service responds to the request.
     */
    std::future<CheckinResult> check_in_voter(const std::string& first_name, const std::string& middle_name,
                                              const std::string& last_name, const std::vector<std::uint8_t>& voter_id_data);

    /**
     * Starts the process to initiate verrification of voters existance
     * and verify the ticket that it sends to untrusted client.
     *
     *
     * @param first_name The voter's first name
     * @param middle_name The voter's middle name
     * @param last_name The voter's last name
     * @param voter_id_data A byte array containing a representation of the
     * voter's identification (e.g. an image of a state ID).
     * @param ticket The ticket sent to untrusted client from checkin server
     * @return A future for the CheckinResult object that contains the result of
     * the check-in request. The future will be fulfilled when the check-in
     * service responds to the request.
     */
    std::future<CheckinResult> verify_ticket(const std::string& ticket, const std::uint32_t pin);
    void start_verify_ticket_response_read();
    /**
     * A simple demo method that sends a string to the server. This is a blocking,
     * synchronous method.
     */
    void send_string_message(const std::string& message);
    std::string receive_string_message();
};

}  // namespace epollbook
