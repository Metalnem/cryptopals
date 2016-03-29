%% Challenge 15 - PKCS#7 padding validation
%% http://cryptopals.com/sets/2/challenges/15/

-module(c15).
-export([run/0]).

run() ->
	<<"ICE ICE BABY">> = aes:pkcs7_unpad(<<"ICE ICE BABY", 4, 4, 4, 4>>, 16),
	<<"ICE ICE BABY ICE">> = aes:pkcs7_unpad(<<"ICE ICE BABY ICE", (binary:copy(<<16>>, 16))/binary>>, 16),
	ok.
