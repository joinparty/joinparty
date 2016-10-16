bin_PROGRAMS=joinparty

joinparty_SOURCES= nums.cpp \
                   encryption.cpp \
                   utils.cpp \
                   wallet_utils.cpp \
                   wallet.cpp \
                   order_manager.cpp \
                   block_cypher_client.cpp \
                   irc_client.cpp \
                   joinparty.cpp

joinparty_LDADD= @bitcoin_client_LIBS@ \
                 @sodium_LIBS@ \
                 @gmp_LIBS@ \
                 @ssl_LIBS@ \
                 @crypto_LIBS@ \
		 -ldl # ubuntu ordering issue hack (must be after libicu)

