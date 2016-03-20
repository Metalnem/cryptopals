%% Challenge 7 - AES in ECB mode
%% http://cryptopals.com/sets/1/challenges/7/

-module(c07).
-export([run/0]).

run() ->
	Base64Lines = c04:read_lines("c07.txt"),
	EncryptedLines = lists:map(fun base64:decode/1, Base64Lines),
	Ciphertext = binary:list_to_bin(EncryptedLines),
	Result = aes:aes128_ecb_decrypt(<<"YELLOW SUBMARINE">>, Ciphertext),
	io:fwrite("~s", [Result]).
