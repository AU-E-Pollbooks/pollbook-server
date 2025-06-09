# syntax=docker/dockerfile:1

FROM ubuntu:24.04

# Install necessary tools
RUN apt-get update && apt-get install -y \
    build-essential \
    cmake \
    git \
    wget \
    unzip

# Install dependencies from apt
RUN apt-get install -y libssl-dev \
    libasio-dev \
    libspdlog-dev

# Set the working directory in the container
WORKDIR /epollbook

# Download and install the nlohmann-json dependency
RUN wget -O develop.zip https://github.com/nlohmann/json/archive/refs/heads/develop.zip && \
	unzip develop.zip && \
	cd json-develop && \
	mkdir build && cd build && \
	cmake .. && make -j$(nproc) && make install && \
	cd ../.. && rm -rf json-develop develop.zip

# Copy the source code to the container
COPY CMakeLists.txt ./
COPY cmake/ cmake/
COPY src/ src/
COPY include/ include/
COPY apps/ apps/

# Set up the build directory and do an initial compile
RUN mkdir build && cd build && cmake .. && cmake --build .

# Set the container's default command to a shell, since this is for interactive development
CMD ["/bin/bash"]