%% Challenge 25 - Break "random access read/write" AES CTR
%% http://cryptopals.com/sets/4/challenges/25/

-module(c25).
-export([run/0]).

edit(Ciphertext, Key, Nonce, Offset, NewText) ->
	Size = byte_size(NewText),
	<<Prefix:Offset/binary, _:Size/binary, Suffix/binary>> = Ciphertext,
	Temp = aes:aes_ctr_encrypt(Key, Nonce, <<Prefix/binary, NewText/binary>>),
	Encrypted = binary:part(Temp, {byte_size(Temp), -Size}),
	<<Prefix/binary, Encrypted/binary, Suffix/binary>>.

decrypt(Ciphertext, Oracle) -> Oracle(Ciphertext, 0, Ciphertext).

run() ->
	Base64Lines = c04:read_lines("c25.txt"),
	EncryptedLines = lists:map(fun base64:decode/1, Base64Lines),
	OldCiphertext = binary:list_to_bin(EncryptedLines),
	OldPlaintext = aes:aes128_ecb_decrypt(<<"YELLOW SUBMARINE">>, OldCiphertext),

	Key = crypto:rand_bytes(16),
	Nonce = crypto:rand_bytes(8),
	NewCiphertext = aes:aes_ctr_encrypt(Key, Nonce, OldPlaintext),
	NewPlaintext = decrypt(NewCiphertext, fun(Ciphertext, Offset, NewText) -> edit(Ciphertext, Key, Nonce, Offset, NewText) end),

	io:fwrite("~s", [NewPlaintext]),
	ok.
