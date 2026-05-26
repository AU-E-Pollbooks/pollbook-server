# syntax=docker/dockerfile:1

# Base stage: Installs most of the tools and dependencies for the epollbook code
FROM ubuntu:24.04 AS base

# Install necessary tools
RUN apt-get update && apt-get install -y \
    build-essential \
    python3 \
    python3-pip \
    python-is-python3 \
    cmake \
    git

# Install dependencies from apt
RUN apt-get install -y libssl-dev \
    libasio-dev \
    libspdlog-dev

# Set the working directory in the container
WORKDIR /epollbook

# json-build stage: Used only for building the nlohmann-json dependency, which isn't in apt
FROM base AS json-build
# Download and install headers to the default /usr/local/ location.
# JSON_BuildTests=OFF skips nlohmann/json's unit-test suite, which otherwise
# compiles dozens of memory-heavy TUs in parallel and can exhaust host RAM.
RUN git clone --branch v3.12.0 --depth 1 https://github.com/nlohmann/json.git nlohmann_json && \
    cd nlohmann_json && \
    mkdir build && cd build && \
    cmake .. -DJSON_BuildTests=OFF && \
    make -j4 && \
    make install

# Dev stage: Creates the final image used for developing the pollbook project,
# with all dependencies installed and the source code in /epollbook
FROM base AS dev
# Copy just the compiled json library from /usr/local/ in the json-build stage (assuming nothing else is in /usr/local/)
COPY --from=json-build /usr/local/ /usr/local/

# Copy the source code to the container
COPY requirements.txt requirements.txt
RUN pip3 install --no-cache-dir --break-system-packages -r /epollbook/requirements.txt

COPY CMakeLists.txt ./
COPY cmake/ cmake/
COPY src/ src/
COPY include/ include/
COPY apps/ apps/

# Set up the build directory and do an initial compile
RUN mkdir build && cd build && cmake .. && cmake --build .

# Set the container's default command to a shell, since this is for interactive development
CMD ["/bin/bash"]
