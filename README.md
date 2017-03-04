****************************
  Donating to Joinparty
****************************

If you use, support or study this software, please consider donating
to help fund the initial and future development.

This is a free time project that I thought would be useful to the
community.  The purpose is to demonstrate interactions with Joinmarket
built on an entirely different software stack that uses C++ instead of
Python, and Libbitcoin instead of Bitcoin Core.

Any and all donations are much appreciated!

BTC: 1EdjdJ9sCX7w4creSKaenhgBi3oYEntTx7

Please also consider donating to Joinmarket, as this project has
little meaning without their sustained efforts.


****************************
  Contacting Joinparty
****************************

Feel free to contact joinparty@protonmail.com

As a free time project, user support will be very limited.


****************************
  Joinparty Dependencies
****************************

Required dependendencies:

```
gcc4.9 or later (gcc5/6)
git
libtool
autoconf
automake
libgmp
libssl (for boost asio/ssl)
libsodium (built and installed)*
libbitcoin-explorer (built and installed)*
```
Required dependencies (debian based system):

```
apt-get install build-essential automake autoconf \
  gcc libicu-dev git libtool libgmp3-dev libssl-dev
```

The rest of the dependencies* are compiled by the build scripts
mentioned in the build section below.


****************************
  Getting Joinparty
****************************

```
git clone https://github.com/joinparty/joinparty.git
```

Joinparty is Free Software and is licensed under the GNU General
Public License.  One of the original goals was to make an LGPL library
from this code for easier third-party application integration.
Perhaps if there is sufficient interest ... ?


****************************
  Building Joinparty
****************************

```
cd joinparty
./build_joinparty.sh INSTALL-DIRECTORY
```

Recommended example:

```
./build_joinparty.sh joinparty
```

This builds and installs everything into a newly created directory
called joinparty located inside of the current directory.

This step will take a while, so be patient.


****************************
  Running Joinparty
****************************

```
joinparty/bin/joinparty --help
```

If this shows program output and describes the help options, continue
to the next section.

If you see an error such as:

"joinparty/bin/joinparty: error while loading shared libraries: libsodium.so.18:
cannot open shared object file: No such file or directory"

Simply set your LD_LIBRARY_PATH to include the new build and then
re-run it.

For example:

```
export LD_LIBRARY_PATH=$(pwd)/joinparty/lib
joinparty/bin/joinparty --help
```


****************************
  Creating a new wallet
****************************

```
joinparty/bin/joinparty -w wallet.json -c
Generating a new wallet in wallet.json...

*************************************************************
  NOTE: It's *very* important that you write down this word
  list in order to re-create your wallet in case it gets
  corrupted or otherwise needs to be restored
  (e.g. on another machine)
*************************************************************

[ 1] torch
[ 2] direct
[ 3] stool
[ 4] vendor
[ 5] salt
[ 6] interest
[ 7] pen
[ 8] address
[ 9] front
[10] inmate
[11] derive
[12] vanish
[13] between
[14] boost
[15] inherit
[16] method
[17] short
[18] hip
[19] install
[20] remove
[21] scorpion
[22] total
[23] weekend
[24] another

Enter wallet encryption passphrase:

Re-enter wallet encryption passphrase:


Wallet created and written to wallet.json
```


****************************
  Recovering a lost wallet
****************************

Assuming you wrote down the 24 words presented at wallet creation
time, a wallet can be recovered from scratch using those words and the
original password.

For example:

```
joinparty/bin/joinparty -w wallet-test.json -r

Enter all mnemonic words separated by spaces and then press enter
torch direct stool vendor salt interest pen address front inmate derive vanish between boost inherit method short hip install remove scorpion total weekend another

Enter wallet encryption passphrase:

Wallet recovered and written to wallet-test.json
```


****************************
  A note on libbitcoin
****************************

Joinparty is built on top of libbitcoin (more information at
libbitcoin.org).  It interacts with a libbitcoin server chosen
randomly from a list of the following known public servers:

```
tcp://libbitcoin1.openbazaar.org:9091
tcp://libbitcoin2.openbazaar.org:9091
```

If you know of others or run an open one yourself, please suggest them
so that they can be added.

The most private option is to download/build libbitcoin and run your
own server and tell joinparty to use it.  To switch which server to
use, there is a --server option that can be used as follows:

```
joinparty/bin/joinparty -w wallet.json --server tcp://some-server:9091 <options>
```

If you are running a libbitcoin server locally (highly recommended for
privacy), you could use:

```
joinparty/bin/joinparty -w wallet.json --server tcp://localhost:9091 <options>
```


****************************
  Displaying your wallet
****************************

```
joinparty/bin/joinparty -w wallet.json --list
```

Joinparty implements a BIP32 HD Wallet and mimics the wallet used in
Joinmarket.  For this project at the moment, all mix depths other than
mix depth 0 are perhaps overkill and not needed, but you can add as
many as you'd like by editing your wallet.json file*).  Perhaps makers
will be supported in the future, in which case additional mix depths
will be used.  For now, the idea was to make the wallet similar to
joinmarket so that users that were already familiar with joinmarket
would feel more or less at home.

* Specifically, edit the "index_cache":"0,0" section to have
  "index_cache":"0,0|0,0" for each additional mix depth you'd like.
  Note that comma separated pair of numbers separated by the '|'
  character.

As a review, or for those that are new, the external addresses are
where you should send bitcoin into the wallet.  The internal addresses
are used automatically as change addresses.  Balances are reflected in
the listings after they have been picked up by the libbitcoin server
(which depends on their configuration).  Coins are not spendable from
the wallet until they have at least 6 confirmations.

One of the goals of the joinparty wallet is to not re-use addresses.
In general the addresses are shown if they have a balance in them,
otherwise just the latest 6 unused addresses in each mix level (both
external and internal) are displayed.

If you need to see all past addresses that were used, use the
--listall option instead.

```
joinparty/bin/joinparty -w wallet.json --listall
```


****************************
  Spending from your wallet
****************************

The joinparty wallet allows two main methods of getting funds out of
the wallet.  First is of course through coin joins, but a simple send
method also exists in case you want to spend bitcoin without
attempting a coin join.  That's the simplest case, so it's covered
here first.  Note that amounts are always denominated in satoshis.

```
joinparty/bin/joinparty -w wallet.json -s -m 0 -d BITCOIN-ADDRESS -a AMOUNT
```

For example, to send 1 millibit (0.001 btc, or 100000 satoshis) from
mix depth 0 to some destination BITCOIN-ADDRESS, use something like
this:

```
joinparty/bin/joinparty -w wallet.json -s -m 0 -d BITCOIN-ADDRESS -a 100000
```

[ medium fee, 100000 satoshis at the destination, fee taken from wallet ]

This attempts to send 1 millibit to some BITCOIN-ADDRESS and also
takes out an estimated fee for the transaction to complete.  So the
total cost for doing this will be 100000 + some fee amount of
satoshis.

You can modify your estimated fee with one of three values: low,
medium, or high (with numeric values 0, 1, or 2 respectively).  The
default is medium.  To adjust the fee, use the -f option.  For
example, a low fee could use -f 0 such as:

```
joinparty/bin/joinparty -w wallet.json -s -m 0 -d BITCOIN-ADDRESS -a 100000 -f 0
```

[ low fee, 100000 satoshis at the destination, fee taken from wallet ]

Another thing to note is that the fee is required on top of the
specified amount (i.e. amount + fee).  If you want to include the fee
inside of the amount, use the -F option.  This means that you can
specify an amount like 100000 and if the fee is 5000 satoshis, it will
be subtracted from the target amount so that 95000 satoshis will
arrive at the destination BITCOIN-ADDRESS.

The default is to not subtract the fee from the target amount.  To
specify this option, use the -F 1 option.

```
joinparty/bin/joinparty -w wallet.json -s -m 0 -d BITCOIN-ADDRESS -a 100000 -f 0 -F 1
```

[ low fee, subtract fee from amount, yields 100000 - fee at the destination ]

The last thing to note is that you can sweep an entire mix depth.  If
you have coins spread out in the same mix depth across multiple
external and internal addresses, you can specify the amount of 0 to
include all of it.  With this option, the -F 1 option should also be
used since there won't be additional funds left to support the fee
without it.

To sweep the entire mix depth 0, you could use:

```
joinparty/bin/joinparty -w wallet.json -s -m 0 -d BITCOIN-ADDRESS -a 0 -F 1
```


****************************
  Joining from your wallet
****************************

Finally, to attempt a coin join take against makers in the Joinmarket,
the -j option is required in addition to the number of makers you're
like to join with.  For example, to attempt a coin join (-j) with 5
makers (-n 5), using coins from your mix depth 0 (-m 0), you could
use:

```
joinparty/bin/joinparty -w wallet.json -j -m 0 -n 5 -d BITCOIN-ADDRESS -a 100000
```

All of the spending and fee related options above also work with coin
joins.

Related to v2 protocol support, several optional parameters were
added.

First is --retryindex, or -R.  Currently, each utxo can be used up to
3 times before it's blacklisted (as configured by default on the maker
side).  So for each utxo, 3 different commitments can be computed and
used. For example if a join intends to use 1 utxo as the input for a
transaction, you can specify -R 1 to use the second retry for
commitment 0 (the default).  The default retry index is 0, which
specifies the first form of the commitment.  Note however that if utxo
0 has been blacklisted all 3 times using -R, it cannot be used in the
transaction at all.  For the more advanced, -R specifies which NUMS
index to use.  Example usage: -R 1

For finer grained utxo control, the --commitmentindex, or -C can be
used to specify which utxo's commitment to use for a join when there
are multiples going into the transaction.  For example if a join
intends to use 3 utxo's as inputs in a transaction, you can specify -C
1 to use the second one (-C 0 is the first).  This is generally not
needed unless you know what you're doing.  Example usage: -C 1

For whitelisting preferred makers, the --preferred, or -P option can
be used to specify maker nick names in a comma separated list.  If
they have orders available in the range that we're looking for, they
will be selected before other makers.

In the Joinmarket v2 protocol, some malicious makers stop responding
at a certain point in the coin join attempt.  To help combat this,
some order filtering has been automatically added.  In addition, a new
argument -M, or --minmakers was introduced that allows you to do a
join with some minimum number of makers, even if the target is higher.
An example would be like, "I want to join this amount with 10 makers,
but if 10 are not responding properly, continue the join if at least 6
makers are honest makers".  Without this feature, if any one of the 10
makers stopped responding, the commitment has been burned and cannot
be re-used, which can cause major usability issues.  This option
allows a more flexible arrangement and will allow joins to continue in
most cases despite some malicious makers that do not respond.

A concrete example showing a join with 5 makers, but with a minimum of
3:

```
joinparty/bin/joinparty -w wallet.json -j -m 0 -n 5 -M 3 -d BITCOIN-ADDRESS -a 100000
```

Finally, --exclude, or -E was added to allow bitcoin addresses in a
particular mix depth to be specified so that no utxos associated with
that address will be used.  This is also for fine grained control
where a particular utxo has been blacklisted, but you still want to
sweep the mix depth, or enable transactions with other coins in that
mix depth.  Example usage: -E "address1,address2,address3"


****************************
  Troubleshooting
****************************

There are a number of issues that can cause Joinparty to fail the
operations that you're intending to use.  For example, if the
libbitcoin server configured for use cannot be reached, very little
can be done as the server is required to get transaction information
for retrieving information about your addresses and utxos.

Specific to coin joins, the following are the most common reasons for
a failed join:

1) The IRC server may be down.  In this case, try again later.

2) You may see an error about no more eligible orders found, which
means that there are not enough unique maker orders available at that
time to fulfill the coin join for the amount specified.  In this case,
try again later, or adjust the destination join amount.

3) You may see an error about a decrypted signature failing.  It seems
that there are some malicious makers hanging around the Joinmarket
channel which are not sending properly formed messages.  In this case,
attempting a join another time may not help as that maker's order is
likely to appear in the next attempt.  In this case, try to black list
the maker by nickname and then retry the coin join.  To blacklist one
or more makers, use the -B or --blacklist option.  Example usage: -B
"user1,user2,user3" or --blacklist "user1,user2,user3"

Note that blacklisting is not permanent.  It simply ignores their
orders for the coin join that you're currently running.

4) You may see that Joinparty hangs while waiting for a maker.  It's
possible that stopping the join (using Ctrl-C) and re-starting it will
fix it immediately.  If not, blacklist the maker that it's waiting
for, as some malicious or malfunctioning makers appear to randomly not
respond at times.
