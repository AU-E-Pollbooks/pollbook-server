# E-Pollbook Check-in Service

This library provides a proof-of-concept implementation of a secure e-pollbook service that allows untrusted client devices to check in voters at a polling place. It includes these components:

* A CheckinService class that implements the check-in service, intended to run on a "back-end" server within a polling place (accessible only to poll workers, not the public)
* A PollbookClient class that implements the client logic, intended to run on untrusted client devices (e.g. tablets, kiosks) available to the public within the polling place
* A VoterIDService class that mocks up the behavior of an independent, state-provided voter ID verification service. The actual implementation of this service will vary greatly depending on the state administering the election, so in this library the class just provides the expected API but does not attempt to verify any identity documents.
* Application entry points (Main functions) that construct each of these classes in a stand-alone executable and provide a basic command-line interface
* A set of configuration files for the executables that demonstrate how to deploy the clients, check-in server, and ID server as processes within a single machine that communicate using the local loopback interface.
* A set of configuration files for the executables that can be used to deploy the clients, check-in server, and ID server as Docker containers that communicate using a Docker Compose network, as well as the corresponding Docker configuration files needed for this deployment.

## Building this library

This is a CMake C++ project adhering to the C++17 standard, so it requires a recent version of CMake and a C++ compiler. It depends on the following libraries:

* [OpenSSL](https://www.openssl.org/) for cryptography (packaged for Debian-like systems as `libssl-dev`)
* [spdlog](https://github.com/gabime/spdlog) for logging, v1.11 or higher
* [ASIO](https://think-async.com/asio), the non-Boost standalone version, for platform-independent network sockets
* [nlohmann](https://github.com/nlohmann/json), for json serialised communication between the client and the server.

Once these dependencies are installed, and available in an include path that CMake can find, you should be able to build this library using the standard CMake incantations:

```
mkdir build
cd build
cmake ..
cmake --build .
```

After building is complete, the `apps/` directory within the build folder will contain the executables `client`, `secure_client`, `server`, and `id_server`, along with the `local-test-deployment` directory, which contains the sample configuration files for running the clients and servers as local processes on a single machine.

## Deployment and configuration

Both the client and server classes in this library expect certain global configuration options to be set in a configuration file that should be loaded and parsed by the singleton Config class when the program starts. The `client`, `server`, and `id_server` executables demonstrate how to initialize the Config class before constructing a client or service object, and they allow you to specify the name of the config file as a command-line option. The config file should be written in the standard INI format, and example config files for each type of executable (client, server, and id-server) are provided in the folder src/config/. The expected sections and keys for the config file are defined by the string constants defined in `include/epollbook/config/config.hpp`.

Among the essential configuration options are the locations of x509 public-key certificates for the check-in server and ID server, which must be manually copied to each device (clients and servers) before starting the service. Each client must also have its own public-key certificate, which it will send to the servers upon connecting. The script `generate_keys.sh` in the `local-test-deployment` directory demonstrates how to generate all the required keys and certificates, and copies the certificates needed by each device into its configuration folder.

### Test Deployment Using Docker

This repository contains a Dockerfile and compose.yaml file that can be used to deploy several Docker containers connected to a virtual network, for easier testing and development of this code on a single machine. Each container will get its own copy of the source code, but if you edit the code on your host computer you can use Docker Compose Watch to automatically copy changed files from your host's source directory to the containers. The directory `docker-test-deployment` inside the `apps` directory contains the config files for each container, similar to the local-test-deployment directory. However, unlike the local-test-deployment directory, you must populate it with public keys using the `generate_keys.sh` script *before* launching the Docker containers, since they will not share a filesystem.

To start the Docker test deployment, assuming this repository is cloned to the folder `~/pollbook-server` on your development computer, you should run the following commands:

```
~/pollbook-server$ cd apps/docker-test-deployment
~/pollbook-server/apps/docker-test-deployment$ ./generate_keys.sh
~/pollbook-server/apps/docker-test-deployment$ cd ../../
~/pollbook-server$ docker compose up -w
```

The terminal in which you run `docker compose up` will be occupied by the Docker Compose process, so you should open four new terminal windows to connect to the two servers and two clients. In each of these windows, use a `docker compose attach` command to connect to a container, where the terminal should already be in the correct working directory. You can then launch the `server`, `id_server`, `client`, or `secure_client` binaries, which should already be compiled:

**Terminal 1**:
```
~/pollbook-server$ docker compose attach checkin
root@a80553c134fe:/epollbook/build/apps/docker-test-deployment/checkin_server# ../../server
```

**Terminal 2**:
```
~/pollbook-server$ docker compose attach dummy-id
root@5808a59fa1ad:/epollbook/build/apps/docker-test-deployment/id_server# ../../id_server
```

**Terminal 3**:
```
~/pollbook-server$ docker compose attach untrusted-client-0
root@c4639b41e86b:/epollbook/build/apps/docker-test-deployment/client0# ../../client
```

**Terminal 4**:
```
~/pollbook-server$ docker compose attach trusted-client-1
root@529bd64dda2e:/epollbook/build/apps/docker-test-deployment/client1# ../../secure_client
```

If you make changes to a source code file (anywhere within your development computer's `~/pollbook-server` folder), Docker Compose Watch will automatically copy it to all of the containers. You can then rebuild the server or client programs by running `cmake --build .` within the `/epollbook/build/` directory on each container.