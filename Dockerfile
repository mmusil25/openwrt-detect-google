FROM debian:bookworm

RUN apt-get update &&\
    DEBIAN_FRONTEND=noninteractive apt-get install -y \
            sudo build-essential clang flex bison g++ gawk \
	gcc-multilib g++-multilib gettext git libncurses5-dev libssl-dev \
	python3-setuptools rsync swig unzip zlib1g-dev file wget openssl && \

    apt-get clean && \
    groupadd -g 1000 mark && \
    useradd -u 1000 -g mark -d /home/mark -m mark && \
    echo 'mark ALL=(ALL) NOPASSWD: ALL' > /etc/sudoers.d/mark && \
    echo mark:pass1234 | chpasswd

# Set correct permissions for the sudoers file
RUN chmod 0440 /etc/sudoers.d/mark

