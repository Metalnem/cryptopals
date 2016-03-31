%% Challenge 26 - CTR bitflipping
%% http://cryptopals.com/sets/4/challenges/26/

-module(c26).
-export([run/0]).
-define(BLOCK_SIZE, 16).
-define(HALF_BLOCK_SIZE, 8).

escape(Text, Original, Replacement) ->
	binary:replace(Text, [Original], Replacement, [global]).

encrypt(Plaintext, Key) ->
	Nonce = <<0:?HALF_BLOCK_SIZE/unit:8>>,
	Prefix = <<"comment1=cooking%20MCs;userdata=">>,
	Suffix = <<";comment2=%20like%20a%20pound%20of%20bacon">>,
	Data = escape(escape(Plaintext, <<";">>, <<"%3B">>), <<"=">>, <<"%3D">>),
	Input = <<Prefix/binary, Data/binary, Suffix/binary>>,
	aes:aes_ctr_encrypt(Key, Nonce, Input).

decrypt(Ciphertext, Key) ->
	Nonce = <<0:?HALF_BLOCK_SIZE/unit:8>>,
	Plaintext = aes:aes_ctr_encrypt(Key, Nonce, Ciphertext),

	case binary:match(Plaintext, <<";admin=true;">>) of
		nomatch -> error;
		_ -> {ok, Plaintext}
	end.

ctr_bitflipping(F) ->
	Desired = <<"test;admin=true">>,
	Size = byte_size(Desired),
	Input = <<0:Size/unit:8>>,

	<<Prefix:(2 * ?BLOCK_SIZE)/binary, Original:Size/binary, Suffix/binary>> = F(Input),
	Tampered = c02:xor_buffers(Original, Desired),
	<<Prefix/binary, Tampered/binary, Suffix/binary>>.

run() ->
	Key = c11:random_key(),
	F = fun(Plaintext) -> encrypt(Plaintext, Key) end,
	Tampered = ctr_bitflipping(F),
	{ok, Plaintext} = decrypt(Tampered, Key),
	io:fwrite("~s~n", [Plaintext]),
	ok.
