#!/bin/bash
#
# This file is part of the joinparty package.
#

# uncomment for debugging
#set -x

set -e

###############################################################
# convenience functions
###############################################################
function check_program()
{
    program=$1
    has_program=$(which $program)
    if [ -z $has_program ]; then
        echo "Error: $program is required but does not appear to be installed"
        exit 1
    fi
}

###############################################################
# checks command line args
###############################################################
if [ -z "$1" ]; then
    echo "Usage: ./install.sh install_dir"
    echo ""
    echo "  install_dir: the directory all packages should be deployed into (required)"
    exit 1
fi

install_dir=$(pwd)/$(basename $1)

required_programs="autoconf automake gcc g++"
for program in $required_programs; do
    check_program $program
done

num_cpus=$(grep -c "processor" /proc/cpuinfo)

###############################################################
# libbitcoin explorer build/installation
###############################################################
mkdir -p $install_dir
pushd $install_dir > /dev/null
rm -rf build
mkdir build
pushd build > /dev/null


export PKG_CONFIG_PATH=$install_dir/lib/pkgconfig
export BOOST_ROOT=$install_dir/build/build-libbitcoin-explorer/build-boost_1_61_0.tar.bz2

BOOST_ROOT=$install_dir/build/build-libbitcoin-explorer/build-boost_1_61_0.tar.bz2 \
PKG_CONFIG_PATH=$install_dir/lib/pkgconfig \
  ../../install_libbitcoin_explorer.sh --prefix=$install_dir \
  --with-icu --build-icu --disable-shared --enable-static \
  --with-zlib --build-zlib --build-boost --without-tests

popd > /dev/null # build


###############################################################
# install libsodium
###############################################################
wget https://download.libsodium.org/libsodium/releases/libsodium-1.0.10.tar.gz
tar -xvzf libsodium-1.0.10.tar.gz

pushd libsodium-1.0.10 > /dev/null
./autogen.sh && ./configure --prefix=$install_dir
make -j $num_cpus install
popd > /dev/null # libsodium

popd > /dev/null # install_dir

###############################################################
# build joinparty
###############################################################
./configure --prefix=$install_dir
make -j $num_cpus
make install

echo "In your shell, set the LD_LIBRARY_PATH to include $install_dir"
echo "e.g. In bash, type:"
echo "export LD_LIBRARY_PATH=$install_dir:$LD_LIBRARY_PATH"
export LD_LIBRARY_PATH=$install_dir/lib:$LD_LIBRARY_PATH
