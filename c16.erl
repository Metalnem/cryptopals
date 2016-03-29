%% Challenge 16 - CBC bitflipping attacks
%% http://cryptopals.com/sets/2/challenges/16/

-module(c16).
-export([run/0, bitflipping_attack/1]).
-define(BLOCK_SIZE, 16).

escape(Text, Original, Replacement) ->
	binary:replace(Text, [Original], Replacement, [global]).

encrypt(Plaintext, Key) ->
	Iv = <<0:?BLOCK_SIZE/unit:8>>,
	Prefix = <<"comment1=cooking%20MCs;userdata=">>,
	Suffix = <<";comment2=%20like%20a%20pound%20of%20bacon">>,
	Data = escape(escape(Plaintext, <<";">>, <<"%3B">>), <<"=">>, <<"%3D">>),
	Input = <<Prefix/binary, Data/binary, Suffix/binary>>,
	aes:aes128_cbc_encrypt(Key, Iv, Input).

is_admin(Ciphertext, Key) ->
	Iv = <<0:?BLOCK_SIZE/unit:8>>,
	Plaintext = aes:aes128_cbc_decrypt(Key, Iv, Ciphertext),

	case binary:match(Plaintext, <<";admin=true;">>) of
		nomatch -> false;
		_ -> true
	end.

bitflipping_attack(F) ->
	DesiredBlock = <<";admin=true;a=bc">>,
	Plaintext = <<0:32/unit:8>>,
	<<Block1:?BLOCK_SIZE/binary, Block2:?BLOCK_SIZE/binary, Block3:?BLOCK_SIZE/binary, Rest/binary>> = F(Plaintext),
	ModifiedBlock = c02:xor_buffers(Block3, DesiredBlock),
	<<Block1/binary, Block2/binary, ModifiedBlock/binary, Rest/binary>>.

run() ->
	Key = c11:random_key(),
	F = fun(Plaintext) -> encrypt(Plaintext, Key) end,
	Result = bitflipping_attack(F),
	true = is_admin(Result, Key),
	ok.
