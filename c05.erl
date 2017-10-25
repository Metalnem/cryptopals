%% Challenge 5 - Implement repeating-key XOR
%% http://cryptopals.com/sets/1/challenges/5/

-module(c05).
-export([repeating_key_xor/2, run/0]).

repeating_key_xor_impl(<<C, RestPlaintext/binary>>, <<K, RestKey/binary>>, Key) ->
	<<Part1:4, Part2:4>> = <<(C bxor K)>>,
	C1 = c02:decimal_to_hex(Part1),
	C2 = c02:decimal_to_hex(Part2),
	Result = repeating_key_xor_impl(RestPlaintext, RestKey, Key),
 	<<C1, C2, Result/binary>>;

repeating_key_xor_impl(<<>>, _, _) -> <<>>;
repeating_key_xor_impl(Plaintext, <<>>, Key) -> repeating_key_xor_impl(Plaintext, Key, Key).

repeating_key_xor(Plaintext, Key) -> repeating_key_xor_impl(Plaintext, Key, Key).

run() ->
	Plaintext = <<"Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal">>,
	Key = <<"ICE">>,
	Result = repeating_key_xor(Plaintext, Key),
	<<"0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272"
		"a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f">> = Result,
	ok.
