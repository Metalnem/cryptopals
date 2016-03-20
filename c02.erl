%% Challenge 2 - Fixed XOR
%% http://cryptopals.com/sets/1/challenges/2/

-module(c02).
-export([decimal_to_hex/1, xor_buffers/2, string_to_hex/1, run/0]).

decimal_to_hex(D) when D >= 0 andalso D < 10 -> $0 + D;
decimal_to_hex(D) when D >= 10 andalso D < 16 -> $a + D - 10.

xor_buffers(<<C1, Rest1/binary>>, <<C2, Rest2/binary>>) ->
	C = C1 bxor C2,
	Result = xor_buffers(Rest1, Rest2),
	<<C, Result/binary>>;

xor_buffers(<<>>, <<>>) -> <<>>.

string_to_hex(<<X1:4, X2:4, Rest/binary>>) ->
	C1 = decimal_to_hex(X1),
	C2 = decimal_to_hex(X2),
	Result = string_to_hex(Rest),
	<<C1, C2, Result/binary>>;

string_to_hex(<<>>) -> <<>>.

run() ->
	S1 = c01:hex_to_string(<<"1c0111001f010100061a024b53535009181c">>),
	S2 = c01:hex_to_string(<<"686974207468652062756c6c277320657965">>),
	Xor = xor_buffers(S1, S2),
	<<"746865206b696420646f6e277420706c6179">> = string_to_hex(Xor),
	ok.
