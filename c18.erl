%% Challenge 18 - Implement CTR, the stream cipher mode
%% http://cryptopals.com/sets/3/challenges/18/

-module(c18).
-export([run/0]).
-define(HALF_BLOCK_SIZE, 8).

run() ->
	Key = <<"YELLOW SUBMARINE">>,
	Ciphertext = base64:decode(<<"L77na/nrFsKvynd6HzOoG7GHTLXsTVu9qvY/2syLXzhPweyyMTJULu/6/kXX0KSvoOLSFQ==">>),
	aes:aes_ctr_encrypt(Key, <<0:?HALF_BLOCK_SIZE/little-unit:8>>, Ciphertext).
