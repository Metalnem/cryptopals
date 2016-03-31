%% Challenge 20 - Break fixed-nonce CTR statistically
%% http://cryptopals.com/sets/3/challenges/20/

-module(c20).
-export([run/0]).
-define(HALF_BLOCK_SIZE, 8).

run() ->
	Key = c11:random_key(),
	Nonce = <<0:?HALF_BLOCK_SIZE/little-unit:8>>,
	
	Ciphertexts = lists:filter(fun(Plaintext) -> byte_size(Plaintext) > 0 end,
		lists:map(fun(Plaintext) ->
			S = base64:decode(Plaintext),
			aes:aes_ctr_encrypt(Key, Nonce, S)
		end, c04:read_lines("c20.txt"))),

	Length = lists:foldl(fun(Ciphertext, Acc) ->
		min(Acc, byte_size(Ciphertext))
	end, 1000, Ciphertexts),

	Truncated = lists:map(fun(Ciphertext) ->
		<<Result:Length/binary, _/binary>> = Ciphertext,
		Result
	end, Ciphertexts),

	Decrypted = c06:decrypt_repeating_key_xor(list_to_binary(Truncated)),
	Blocks = c06:partition(Decrypted, Length),
	lists:map(fun(Plaintext) -> io:fwrite("~s~n", [Plaintext]) end, Blocks),
	ok.
