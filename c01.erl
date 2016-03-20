%% Challenge 1 - Convert hex to base64
%% http://cryptopals.com/sets/1/challenges/1/

-module(c01).
-export([hex_to_string/1, run/0]).

hex_to_decimal(C) when C >= $0 andalso C =< $9 -> C - $0;
hex_to_decimal(C) when C >= $A andalso C =< $F -> C - $A + 10;
hex_to_decimal(C) when C >= $a andalso C =< $f -> C - $a + 10.

hex_to_string(<<C1, C2, Rest/binary>>) ->
	C = 16 * hex_to_decimal(C1) + hex_to_decimal(C2),
	Result = hex_to_string(Rest),
	<<C, Result/binary>>;

hex_to_string(<<>>) -> <<>>.

run() ->
	Hex = <<"49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d">>,
	S = hex_to_string(Hex),
	<<"SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t">> = base64:encode(S),
	ok.
