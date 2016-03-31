%% Challenge 27 - Recover the key from CBC with IV=Key
%% http://cryptopals.com/sets/4/challenges/27/

-module(c27).
-export([run/0]).
-define(BLOCK_SIZE, 16).

encrypt(Key, Plaintext) -> aes:aes128_cbc_encrypt(Key, Key, Plaintext).

decrypt(Key, Ciphertext) ->
	Plaintext = aes:aes128_cbc_decrypt(Key, Key, Ciphertext),
	case is_valid(Plaintext) of
		true -> ok;
		false -> {error, Plaintext}
	end.

is_valid(<<>>) -> true;

is_valid(<<C:1/binary, Rest/binary>>) ->
	case is_valid_char(C) of
		true -> is_valid(Rest);
		false -> false
	end.

is_valid_char( <<0:1, _:7>>) -> true;
is_valid_char( <<1:1, _:7>>) -> false.

decrypt_key(Ciphertext, Oracle) ->
	<<C1:?BLOCK_SIZE/binary, _:(2 * ?BLOCK_SIZE)/binary, Rest/binary>> = Ciphertext,
	Tampered = <<C1/binary, 0:?BLOCK_SIZE/unit:8, C1/binary, Rest/binary>>,
	{error, Plaintext} = Oracle(Tampered),
	<<X1:?BLOCK_SIZE/binary, _X2:?BLOCK_SIZE/binary, X3:?BLOCK_SIZE/binary, _/binary>> = Plaintext,
	c02:xor_buffers(X1, X3).

run() ->
	Key = c11:random_key(),
	Message = <<"Cooking MC's like a pound of bacon. Cooking MC's like a pound of bacon.">>,
	Ciphertext = encrypt(Key, Message),
	Key = decrypt_key(Ciphertext, fun(X) -> decrypt(Key, X) end),
	ok.
