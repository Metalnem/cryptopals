%% Challenge 17 - The CBC padding oracle
%% http://cryptopals.com/sets/3/challenges/17/

-module(c17).
-export([run/0, decrypt/3]).
-define(BLOCK_SIZE, 16).

random_string() ->
	Strings = [
		<<"MDAwMDAwTm93IHRoYXQgdGhlIHBhcnR5IGlzIGp1bXBpbmc=">>,
		<<"MDAwMDAxV2l0aCB0aGUgYmFzcyBraWNrZWQgaW4gYW5kIHRoZSBWZWdhJ3MgYXJlIHB1bXBpbic=">>,
		<<"MDAwMDAyUXVpY2sgdG8gdGhlIHBvaW50LCB0byB0aGUgcG9pbnQsIG5vIGZha2luZw==">>,
		<<"MDAwMDAzQ29va2luZyBNQydzIGxpa2UgYSBwb3VuZCBvZiBiYWNvbg==">>,
		<<"MDAwMDA0QnVybmluZyAnZW0sIGlmIHlvdSBhaW4ndCBxdWljayBhbmQgbmltYmxl">>,
		<<"MDAwMDA1SSBnbyBjcmF6eSB3aGVuIEkgaGVhciBhIGN5bWJhbA==">>,
		<<"MDAwMDA2QW5kIGEgaGlnaCBoYXQgd2l0aCBhIHNvdXBlZCB1cCB0ZW1wbw==">>,
		<<"MDAwMDA3SSdtIG9uIGEgcm9sbCwgaXQncyB0aW1lIHRvIGdvIHNvbG8=">>,
		<<"MDAwMDA4b2xsaW4nIGluIG15IGZpdmUgcG9pbnQgb2g=">>,
		<<"MDAwMDA5aXRoIG15IHJhZy10b3AgZG93biBzbyBteSBoYWlyIGNhbiBibG93">>
	],
	Index = crypto:rand_uniform(0, length(Strings)),
	S = lists:nth(Index + 1, Strings),
	base64:decode(S).

padding_oracle(Key, Iv, Ciphertext) ->
	try aes:aes128_cbc_decrypt(Key, Iv, Ciphertext) of
		_ -> true
	catch
		padding_error -> false
	end.

decrypt(Iv, Ciphertext, F) ->
	L = binary:bin_to_list(Ciphertext),
	EncryptedBlocks = lists:map(fun list_to_binary/1, c06:partition(L, ?BLOCK_SIZE)),
	PreviousBlocks = [Iv | lists:droplast(EncryptedBlocks)],
	DecryptedBlocks = lists:zipwith(fun(X, Y) ->
		RandomBlock = crypto:rand_bytes(?BLOCK_SIZE),
		c02:xor_buffers(Y, decrypt_block(RandomBlock, X, << >>, F))
	end, EncryptedBlocks, PreviousBlocks),
	aes:pkcs7_unpad(list_to_binary(DecryptedBlocks), ?BLOCK_SIZE).

decrypt_block(_, _, KnownBytes, _) when byte_size(KnownBytes) =:= ?BLOCK_SIZE -> KnownBytes;

decrypt_block(RandomBlock, CiphertextBlock, KnownBytes, F) ->
	PaddingByte = byte_size(KnownBytes) + 1,
	Prefix = binary:part(RandomBlock, 0, ?BLOCK_SIZE - PaddingByte),
	Suffix = c02:xor_buffers(KnownBytes, binary:copy(<<PaddingByte>>, byte_size(KnownBytes))),
	Candidates = [{X, F(<<Prefix/binary, X, Suffix/binary, CiphertextBlock/binary>> )} || X <- lists:seq(0, 255)],
	{Winner, _} = lists:keyfind(true, 2, Candidates),
	DecryptedByte = Winner bxor PaddingByte,
	decrypt_block(RandomBlock, CiphertextBlock, <<DecryptedByte, KnownBytes/binary>>, F).

run() ->
	Key = c11:random_key(),
	Iv = c11:random_iv(),
	Plaintext = random_string(),
	Ciphertext = aes:aes128_cbc_encrypt(Key, Iv, Plaintext),
	decrypt(Iv, Ciphertext, fun(X) -> padding_oracle(Key, Iv, X) end).
