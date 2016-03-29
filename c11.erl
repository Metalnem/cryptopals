%% Challenge 11 - An ECB/CBC detection oracle
%% http://cryptopals.com/sets/2/challenges/11/

-module(c11).
-export([run/0, encrypt/1, random_key/0, random_iv/0, ecb_cbc_detection_oracle/1]).

random_key() -> crypto:rand_bytes(16).
random_iv() -> crypto:rand_bytes(16).

encrypt(Plaintext) ->
	Key = random_key(),
	BytesBefore = crypto:rand_bytes(5 + crypto:rand_uniform(0, 6)),
	BytesAfter = crypto:rand_bytes(5 + crypto:rand_uniform(0, 6)),
	Input = <<BytesBefore/binary, Plaintext/binary, BytesAfter/binary>>,
	case crypto:rand_uniform(0, 2) of
		0 -> {ecb, aes:aes128_ecb_encrypt(Key, Input)};
		1 -> {cbc, aes:aes128_cbc_encrypt(Key, random_iv(), Input)}
	end.

ecb_cbc_detection_oracle(F) ->
	Plaintext = <<0:48/unit:8>>,
	{Expected, Result} = F(Plaintext),
	Part1 = binary:part(Result, 16, 16),
	Part2 = binary:part(Result, 32, 16),
	Detected = 
		case Part1 =:= Part2 of
			true -> ecb;
			false -> cbc
		end,
	{Expected, Detected}.

run() ->
	ecb_cbc_detection_oracle(fun encrypt/1).
