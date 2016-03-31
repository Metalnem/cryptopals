%% Challenge 24 - Create the MT19937 stream cipher and break it
%% http://cryptopals.com/sets/3/challenges/24/

-module(c24).
-export([run/0]).
-define(MASK, 16#ffff).
-define(SUFFIX_SIZE, 16).

mt_encrypt(Key, <<_/binary>> = Plaintext) ->
	mt:seed(Key band ?MASK),
	mt_encrypt_impl(<<>>, Plaintext).

mt_encrypt_impl(_, <<>>) -> <<>>;
mt_encrypt_impl(<<>>, Plaintext) -> mt_encrypt_impl(<<(mt:next_int()):32>>, Plaintext);

mt_encrypt_impl(<<C1:8, Rest1/binary>>, <<C2:8, Rest2/binary>>) ->
	C = C1 bxor C2,
	Rest = mt_encrypt_impl(Rest1, Rest2),
	<<C, Rest/binary>>.

encrypt(Plaintext) ->
	Key = crypto:rand_uniform(0, ?MASK),
	Prefix = crypto:rand_bytes(10 + crypto:rand_uniform(0, 20)),
	{Key, mt_encrypt(Key, <<Prefix/binary, Plaintext/binary>>)}.

decrypt(Ciphertext) -> decrypt_impl(0, Ciphertext).

decrypt_impl(Key, Ciphertext) ->
	Plaintext = mt_encrypt(Key, Ciphertext),
	Suffix = binary:part(Plaintext, {byte_size(Plaintext), -?SUFFIX_SIZE}),
	case suffix() of
		Suffix -> Key;
		_ -> decrypt_impl(Key + 1, Ciphertext) 
	end.

suffix() -> <<0:?SUFFIX_SIZE/unit:8>>.

generate_token() ->
	timer:sleep(1000 * (5 + random:uniform(10))),
	Token = generate_token(c22:timestamp()),
	timer:sleep(1000 * (5 + random:uniform(10))),
	Token.

generate_token(Seed) ->
	mt:seed(Seed),
	<<(mt:next_int()):32, (mt:next_int()):32, (mt:next_int()):32, (mt:next_int()):32>>.

detect_token(Token) -> detect_token(c22:timestamp(), Token, 10000).

detect_token(Timestamp, Token, NumberOfTries) ->
	case {generate_token(Timestamp) =:= Token, NumberOfTries} of
		{_, 0} -> error;
		{true, _} -> {ok, Timestamp};
		{false, _} -> detect_token(Timestamp - 1, Token, NumberOfTries - 1)
	end.

run() ->
	mt:start_link(),
	{Key, Ciphertext} = encrypt(suffix()),
	Key = decrypt(Ciphertext),
	Token = generate_token(),
	{ok, _Timestamp} = detect_token(Token),
	mt:stop(),
	ok.
