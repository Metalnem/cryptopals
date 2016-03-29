%% Challenge 10 - Implement CBC mode
%% http://cryptopals.com/sets/2/challenges/10/

-module(c10).
-export([run/0]).

run() ->
	Base64Lines = c04:read_lines("c10.txt"),
	EncryptedLines = lists:map(fun base64:decode/1, Base64Lines),
	Ciphertext = binary:list_to_bin(EncryptedLines),
	Result = aes:aes128_cbc_decrypt(<<"YELLOW SUBMARINE">>, <<0:128>>, Ciphertext),
	io:fwrite("~s", [Result]),
	ok.
