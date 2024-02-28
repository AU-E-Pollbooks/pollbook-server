# E-Pollbook Check-in Service

This library provides a proof-of-concept implementation of a secure e-pollbook service that allows untrusted client devices to check in voters at a polling place. It includes these components:

* A CheckinService class that implements the check-in service, intended to run on a "back-end" server within a polling place (accessible only to poll workers, not the public)
* A PollbookClient class that implements the client logic, intended to run on untrusted client devices (e.g. tablets, kiosks) available to the public within the polling place
* A VoterIDService class that mocks up the behavior of an independent, state-provided voter ID verification service. The actual implementation of this service will vary greatly depending on the state administering the election, so in this library the class just provides the expected API but does not attempt to verify any identity documents.
* Application entry points (Main functions) that construct each of these classes in a stand-alone executable and provide a basic command-line interface
* A set of configuration files for the executables that demonstrate how to deploy the clients, check-in server, and ID server as processes within a single machine that communicate using the local loopback interface.

## Building this library

This is a CMake C++ project adhering to the C++17 standard, so it requires a recent version of CMake and a C++ compiler. It depends on the following libraries:

* [OpenSSL](https://www.openssl.org/) for cryptography (packaged for Debian-like systems as `libssl-dev`)
* [spdlog](https://github.com/gabime/spdlog) for logging (packaged for Debian-like systems as `libspdlog-dev`)
* [ASIO](https://think-async.com/asio), the non-Boost standalone version, for platform-independent network sockets
* [mutils](https://github.com/mpmilano/mutils), a C++ template utility library by [@mpmilano](https://github.com/mpmilano)
* [nlohmann](https://github.com/nlohmann/json), for json serialised communication between the client and the server. 

Once these dependencies are installed, and available in an include path that CMake can find, you should be able to build this library using the standard CMake incantations:

```
mkdir build
cd build
cmake ..
cmake --build .
```

After building is complete, the `apps/` directory within the build folder will contain the executables `client`, `server`, and `id_server`, along with the `local-test-deployment` directory, which contains the sample configuration files for running the clients and servers as local processes on a single machine.

## Deployment and configuration

Both the client and server classes in this library expect certain global configuration options to be set in a configuration file that should be loaded and parsed by the singleton Config class when the program starts. The `client`, `server`, and `id_server` executables demonstrate how to initialize the Config class before constructing a client or service object, and they allow you to specify the name of the config file as a command-line option. The config file should be written in the standard INI format, and example config files for each type of executable (client, server, and id-server) are provided in the folder src/config/. The expected sections and keys for the config file are defined by the string constants defined in `/include/epollbook/config/config.hpp`.
