#pragma once

#include "checkin_request.hpp"
#include "log_utils.hpp"
#include "openssl/signature.hpp"
#include "voter_id_request.hpp"

#include <asio.hpp>
#include <future>
#include <string>
#include <tuple>

namespace epollbook {

struct CheckinResult {
    bool success;
    std::string failure_reason;
};

class PollbookClient {
private:
    /** A pointer to the debug logger */
    std::shared_ptr<spdlog::logger> logger;
    /** The IO Context to use for all network actions */
    asio::io_context network_io_context;
    /** Work guard for the network IO context, to keep its run() thread alive while the client is idle */
    asio::executor_work_guard<asio::io_context::executor_type> network_work_guard;
    /** The socket to use to communicate with the check-in server */
    asio::ip::tcp::socket checkin_server_socket;
    /** The socket used to communicate with the voter-ID server */
    asio::ip::tcp::socket id_server_socket;
    /**
     * True if the client has been connected to a check-in server, false if
     * connect_checkin_server() has not yet been called.
     */
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
    /**
     * Contains the ID document number (e.g. driver's license number) of the
     * voter for the currently-pending check-in request, if there is one.
     */
    std::uint32_t current_request_voter_id_number;
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
    void connect_checkin_server(const std::string& server_hostname, const std::string& server_port);

    /**
     * Connects the client to a voter-ID-verification server, identified by its
     * hostname and port. This method blocks until the server is connected.
     */
    void connect_id_server(const std::string& server_hostname, const std::string& server_port);

    void start_size_read(bool on_id_server);

    void start_id_response_read(std::size_t message_size);

    void handle_id_response(const VerifiedVoterID& response);

    void start_checkin_response_read(std::size_t message_size);

    void handle_checkin_response(const CheckinResponse& response);

    void start_id_request_write(std::uint64_t timestamp, const std::vector<std::uint8_t>& voter_id_data);

    void start_checkin_request_write(const VerifiedVoterID& verified_id_response);

    std::future<CheckinResult> check_in_voter(const std::string& first_name, const std::string& middle_name, const std::string& last_name,
                                              std::uint32_t voter_id_document_number, const std::vector<uint8_t>& voter_id_data);

    /**
     * A simple demo method that sends a string to the server. This is a blocking,
     * synchronous method.
     */
    void send_string_message(const std::string& message);
};

}  // namespace epollbook
