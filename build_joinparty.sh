#!/bin/bash
#
# This file is part of the joinparty package.
#

set -e


###############################################################
# checks command line args
###############################################################
if [ -z "$1" ]; then
    echo "Usage: ./install.sh install_dir"
    echo ""
    echo "  install_dir: the directory all packages should be deployed into (required)"
    exit 1
fi


###############################################################
# convenience methods
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

PKG_CONFIG_PATH=$install_dir/lib/pkgconfig \
  ../../install_libbitcoin_explorer.sh --prefix=$install_dir \
  --with-icu --build-icu --disable-shared --enable-static \
  --with-zlib --build-zlib --build-boost --without-tests

popd > /dev/null # build


###############################################################
# install libsodium
###############################################################
libsodium_version="1.0.12"

wget https://download.libsodium.org/libsodium/releases/libsodium-$libsodium_version.tar.gz
tar -xvzf libsodium-$libsodium_version.tar.gz

pushd libsodium-$libsodium_version > /dev/null
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

echo ""
echo ""
echo "Joinparty build is complete!"
echo ""
echo "*******************************************************************"
echo "In your shell, set the LD_LIBRARY_PATH to include $install_dir"
echo "e.g. In bash, type:"
echo "export LD_LIBRARY_PATH=$install_dir/lib:$LD_LIBRARY_PATH"
export LD_LIBRARY_PATH=$install_dir/lib:$LD_LIBRARY_PATH
echo "*******************************************************************"
