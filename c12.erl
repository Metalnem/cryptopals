%% Challenge 12 - Byte-at-a-time ECB decryption (Simple)
%% http://cryptopals.com/sets/2/challenges/12/

-module(c12).
-export([run/0, decrypt/1]).

encrypt(Plaintext, Key) ->
	Base64Encoded = <<"Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg"
		"aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq"
		"dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg"
		"YnkK">>,
	Secret = base64:decode(Base64Encoded),
	Input = <<Plaintext/binary, Secret/binary>>,
	aes:aes128_ecb_encrypt(Key, Input).

decrypt(F) ->
	Mode = determine_mode(F),
	{BlockSize, SecretSize} = determine_secret_size(F),
	PrefixSize = BlockSize - 1,
	Prefix = <<0:PrefixSize/unit:8>>,
	<<_:PrefixSize/unit:8, Result/binary>> = decrypt_impl(0, SecretSize, Prefix, F, BlockSize),
	{Mode, Result}.

decrypt_impl(Size, Size, KnownBytes, _, _) -> KnownBytes;

decrypt_impl(Index, Size, KnownBytes, F, BlockSize) ->
	Prefix1 = binary:copy(<<0>>, BlockSize - (Index rem BlockSize) - 1),
	Prefix2 = binary:part(KnownBytes, byte_size(KnownBytes) - BlockSize + 1, BlockSize - 1),

	Chars = lists:seq(0, 255),
	ActualSize = byte_size(KnownBytes) - BlockSize + 1,
	Position = ActualSize - ActualSize rem BlockSize,

	Encrypted = F(<<Prefix1/binary>>),
	CurrentBlock = binary:part(Encrypted, Position, BlockSize),

	Candidates = lists:map(fun(C) ->
		Result = F(<<Prefix2/binary, C>>),
		{C, binary:part(Result, 0, BlockSize)}
	end, Chars),
	
	{C, _} = lists:keyfind(CurrentBlock, 2, Candidates),
	decrypt_impl(Index + 1, Size, <<KnownBytes/binary, C>>, F, BlockSize).

determine_secret_size(F) -> determine_secret_size_impl(F, <<>>, byte_size(F(<<>>))).

determine_secret_size_impl(F, PrevInput, PrevSize) ->
	Input = <<0, PrevInput/binary>>,
	Result = F(Input),
	Size = byte_size(Result),
	case Size > PrevSize of
		true -> {Size - PrevSize, PrevSize - byte_size(Input)};
		false -> determine_secret_size_impl(F, Input, Size)
	end.

determine_mode(F) ->
	Plaintext = <<0:48/unit:8>>,
	Result = F(Plaintext),
	Part1 = binary:part(Result, 16, 16),
	Part2 = binary:part(Result, 32, 16),
	case Part1 =:= Part2 of
		true -> ecb;
		false -> cbc
	end.

run() ->
	Key = c11:random_key(),
	F = fun(Plaintext) -> encrypt(Plaintext, Key) end,
	{_Mode, Result} = decrypt(F),
	io:fwrite("~s", [Result]),
	ok.
