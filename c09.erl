%% Challenge 9 - Implement PKCS#7 padding
%% http://cryptopals.com/sets/2/challenges/9/

-module(c09).
-export([run/0]).

run() ->
	<<"YELLOW SUBMARINE", 4, 4, 4, 4>> = aes:pkcs7_pad(<<"YELLOW SUBMARINE">>, 20),
	Expected = binary:copy(<<16>>, 16),
	Expected = aes:pkcs7_pad(<<>>, 16),
	ok.
